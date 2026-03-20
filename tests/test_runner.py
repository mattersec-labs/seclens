"""Tests for the evaluation runner."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from engine_harness import EngineLoopResult, ModelResponse, TokenUsage

from seclens.evaluation.config import RunConfig
from seclens.schemas.task import EvalLayer
from seclens.evaluation.runner import (
    _build_run_metadata,
    _error_result,
    evaluate_task,
)
from seclens.schemas.output import ParseStatus
from seclens.schemas.task import (
    GroundTruth,
    Location,
    Repository,
    Target,
    Task,
    TaskMetadata,
    TaskType,
)


@pytest.fixture()
def positive_task() -> Task:
    return Task(
        id="test-pos-001",
        version="1.0",
        type=TaskType.TRUE_POSITIVE,
        metadata=TaskMetadata(
            cve_id="CVE-2024-0001",
            description="SQL injection test",
        ),
        repository=Repository(
            url="https://github.com/test/repo",
            commit="abc123",
            language="python",
        ),
        target=Target(
            function="execute_query",
            file="app.py",
            line_start=10,
            line_end=20,
        ),
        ground_truth=GroundTruth(
            vulnerable=True,
            cwe="CWE-89",
            category="sql_injection",
            location=Location(file="app.py", line_start=10, line_end=20),
        ),
        max_task_points=3,
    )


@pytest.fixture()
def negative_task() -> Task:
    return Task(
        id="test-neg-001",
        version="1.0",
        type=TaskType.POST_PATCH,
        metadata=TaskMetadata(
            cve_id="CVE-2024-0001",
            description="SQL injection patched",
        ),
        repository=Repository(
            url="https://github.com/test/repo",
            commit="def456",
            language="python",
        ),
        target=Target(
            function="execute_query",
            file="app.py",
            line_start=10,
            line_end=20,
        ),
        ground_truth=GroundTruth(vulnerable=False),
        max_task_points=1,
    )


@pytest.fixture()
def config() -> RunConfig:
    return RunConfig(model="test/model", dataset="test.jsonl", layer="code-in-prompt", mode="guided")


@pytest.fixture()
def config_layer2() -> RunConfig:
    return RunConfig(model="test/model", dataset="test.jsonl", layer="tool-use", mode="guided", max_turns=5)


def _make_engineloop_result(content: str, turns: int = 1) -> EngineLoopResult:
    """Create a mock EngineLoopResult with the given response content."""
    return EngineLoopResult(
        final_response=ModelResponse(
            content=content,
            tool_calls=[],
            usage=TokenUsage(input_tokens=100, output_tokens=50),
        ),
        messages=[],
        turns=turns,
        max_turns_exceeded=False,
        wall_time_s=1.5,
        total_usage=TokenUsage(input_tokens=100, output_tokens=50),
    )


class TestRunConfig:
    def test_defaults(self) -> None:
        cfg = RunConfig(model="anthropic/claude-sonnet-4-20250514", dataset="test-org/test-dataset:test")
        assert cfg.prompt == "base"
        assert cfg.layer == EvalLayer.TOOL_USE
        assert cfg.mode == "guided"
        assert cfg.max_turns == 200
        assert cfg.workers == 5
        assert cfg.seed == 42

    def test_custom_values(self) -> None:
        cfg = RunConfig(
            model="openai/gpt-4",
            dataset="local.jsonl",
            layer="code-in-prompt",
            mode="open",
            max_turns=5,
            max_cost=1.0,
            workers=10,
            seed=123,
        )
        assert cfg.model == "openai/gpt-4"
        assert cfg.layer == EvalLayer.CODE_IN_PROMPT
        assert cfg.seed == 123

    def test_invalid_layer_number(self) -> None:
        with pytest.raises(Exception):
            RunConfig(model="test", dataset="x.jsonl", layer=3)

    def test_invalid_layer_string(self) -> None:
        with pytest.raises(Exception):
            RunConfig(model="test", dataset="x.jsonl", layer="invalid")

    def test_min_max_turns(self) -> None:
        with pytest.raises(Exception):
            RunConfig(model="test", dataset="x.jsonl", max_turns=0)

    def test_dataset_required(self) -> None:
        with pytest.raises(Exception):
            RunConfig(model="test")


class TestBuildRunMetadata:
    def test_metadata_fields(self, config: RunConfig) -> None:
        meta = _build_run_metadata(config)
        assert meta.model == "test/model"
        assert meta.prompt == "base"
        assert meta.layer == EvalLayer.CODE_IN_PROMPT
        assert meta.mode == "guided"
        assert meta.seed == 42
        assert meta.seclens_version == "0.1.0"
        assert meta.timestamp.endswith("+00:00") or meta.timestamp.endswith("Z")


class TestErrorResult:
    def test_all_zeros(self, positive_task: Task, config: RunConfig) -> None:
        meta = _build_run_metadata(config)
        result = _error_result(positive_task, meta, config.layer, "test error")
        assert result.error == "test error"
        assert result.scores.verdict == 0
        assert result.scores.cwe == 0
        assert result.scores.location == 0
        assert result.scores.earned == 0
        assert result.parse_result.status == ParseStatus.FAILED
        # CIP: positive tasks get max_task_points=2
        assert result.scores.max_task_points == 2

    def test_negative_task_error(self, negative_task: Task, config: RunConfig) -> None:
        meta = _build_run_metadata(config)
        result = _error_result(negative_task, meta, config.layer, "timeout")
        assert result.scores.max_task_points == 1
        assert result.task_type == TaskType.POST_PATCH


class TestEvaluateTaskLayer1:
    @patch("seclens.evaluation.runner.fetch_target_code")
    @patch("seclens.evaluation.runner.EngineLoop")
    @patch("seclens.evaluation.runner.CostTracker")
    def test_correct_positive(
        self,
        mock_cost_cls: MagicMock,
        mock_runner_cls: MagicMock,
        mock_fetch: MagicMock,
        positive_task: Task,
        config: RunConfig,
    ) -> None:
        mock_fetch.return_value = "def execute_query(q):\n    cursor.execute(q)\n"

        json_response = (
            '{"vulnerable": true, "cwe": "CWE-89", '
            '"location": {"file": "app.py", "line_start": 10, "line_end": 20}}'
        )
        loop_result = _make_engineloop_result(json_response)

        mock_runner = MagicMock()
        mock_runner.run.return_value = loop_result
        mock_runner_cls.return_value = mock_runner

        mock_cost = MagicMock()
        mock_cost.current_cost = 0.005
        mock_cost_cls.return_value = mock_cost

        adapter = MagicMock()
        eval_output = evaluate_task(positive_task, adapter, config)
        result = eval_output.result

        assert result.task_id == "test-pos-001"
        assert result.scores.verdict == 1
        assert result.scores.cwe == 1
        assert result.scores.location == 0.0  # CIP: no location scoring
        assert result.scores.earned == 2.0    # CIP: max 2 points
        assert result.scores.max_task_points == 2
        assert result.error is None
        mock_fetch.assert_called_once()
        mock_runner_cls.assert_called_once()

    @patch("seclens.evaluation.runner.fetch_target_code")
    @patch("seclens.evaluation.runner.EngineLoop")
    @patch("seclens.evaluation.runner.CostTracker")
    def test_correct_negative(
        self,
        mock_cost_cls: MagicMock,
        mock_runner_cls: MagicMock,
        mock_fetch: MagicMock,
        negative_task: Task,
        config: RunConfig,
    ) -> None:
        mock_fetch.return_value = "def execute_query(q):\n    cursor.execute(q)\n"

        loop_result = _make_engineloop_result('{"vulnerable": false}')
        mock_runner = MagicMock()
        mock_runner.run.return_value = loop_result
        mock_runner_cls.return_value = mock_runner

        mock_cost = MagicMock()
        mock_cost.current_cost = 0.003
        mock_cost_cls.return_value = mock_cost

        adapter = MagicMock()
        eval_output = evaluate_task(negative_task, adapter, config)
        result = eval_output.result

        assert result.scores.verdict == 1
        assert result.scores.earned == 1
        assert result.task_type == TaskType.POST_PATCH

    @patch("seclens.evaluation.runner.fetch_target_code")
    def test_fetch_error_returns_error_result(
        self,
        mock_fetch: MagicMock,
        positive_task: Task,
        config: RunConfig,
    ) -> None:
        mock_fetch.side_effect = ConnectionError("network error")

        adapter = MagicMock()
        eval_output = evaluate_task(positive_task, adapter, config)
        result = eval_output.result

        assert result.error == "ConnectionError: network error"
        assert result.scores.verdict == 0
        assert result.scores.earned == 0

    @patch("seclens.evaluation.runner.fetch_target_code")
    @patch("seclens.evaluation.runner.EngineLoop")
    @patch("seclens.evaluation.runner.CostTracker")
    def test_parse_failure(
        self,
        mock_cost_cls: MagicMock,
        mock_runner_cls: MagicMock,
        mock_fetch: MagicMock,
        positive_task: Task,
        config: RunConfig,
    ) -> None:
        mock_fetch.return_value = "code"

        loop_result = _make_engineloop_result("I cannot determine the vulnerability.")
        mock_runner = MagicMock()
        mock_runner.run.return_value = loop_result
        mock_runner_cls.return_value = mock_runner

        mock_cost = MagicMock()
        mock_cost.current_cost = 0.002
        mock_cost_cls.return_value = mock_cost

        adapter = MagicMock()
        eval_output = evaluate_task(positive_task, adapter, config)
        result = eval_output.result

        assert result.parse_result.status == ParseStatus.FAILED
        assert result.scores.verdict == 0

    @patch("seclens.evaluation.runner.fetch_target_code")
    @patch("seclens.evaluation.runner.EngineLoop")
    @patch("seclens.evaluation.runner.CostTracker")
    def test_metrics_populated(
        self,
        mock_cost_cls: MagicMock,
        mock_runner_cls: MagicMock,
        mock_fetch: MagicMock,
        positive_task: Task,
        config: RunConfig,
    ) -> None:
        mock_fetch.return_value = "code"

        loop_result = _make_engineloop_result('{"vulnerable": true}')
        mock_runner = MagicMock()
        mock_runner.run.return_value = loop_result
        mock_runner_cls.return_value = mock_runner

        mock_cost = MagicMock()
        mock_cost.current_cost = 0.01
        mock_cost_cls.return_value = mock_cost

        adapter = MagicMock()
        eval_output = evaluate_task(positive_task, adapter, config)
        result = eval_output.result

        assert result.metrics.input_tokens == 100
        assert result.metrics.output_tokens == 50
        assert result.metrics.total_tokens == 150
        assert result.metrics.cost_usd == 0.01
        assert result.metrics.turns == 1
        assert result.metrics.wall_time_s == 1.5
        assert result.metrics.tool_calls == 0


class TestEvaluateTaskLayer2:
    @patch("seclens.evaluation.runner.SandboxManager")
    @patch("seclens.evaluation.runner.EngineLoop")
    @patch("seclens.evaluation.runner.CostTracker")
    @patch("seclens.evaluation.runner.ToolLogger")
    def test_sandbox_lifecycle(
        self,
        mock_tl_cls: MagicMock,
        mock_cost_cls: MagicMock,
        mock_runner_cls: MagicMock,
        mock_sandbox_cls: MagicMock,
        positive_task: Task,
        config_layer2: RunConfig,
    ) -> None:
        mock_sandbox = MagicMock()
        mock_sandbox.create.return_value = Path("/tmp/sandbox/test-pos-001")
        mock_sandbox_cls.return_value = mock_sandbox

        loop_result = _make_engineloop_result('{"vulnerable": true, "cwe": "CWE-89"}')
        mock_runner = MagicMock()
        mock_runner.run.return_value = loop_result
        mock_runner_cls.return_value = mock_runner

        mock_cost = MagicMock()
        mock_cost.current_cost = 0.05
        mock_cost_cls.return_value = mock_cost

        mock_tl = MagicMock()
        mock_tl.log = []
        mock_tl_cls.return_value = mock_tl

        adapter = MagicMock()
        eval_output = evaluate_task(positive_task, adapter, config_layer2)
        result = eval_output.result

        assert result.scores.verdict == 1
        mock_sandbox.create.assert_called_once_with(
            "test-pos-001",
            "https://github.com/test/repo",
            "abc123",
        )
        mock_sandbox.cleanup.assert_called_once_with("test-pos-001")

    @patch("seclens.evaluation.runner.SandboxManager")
    @patch("seclens.evaluation.runner.EngineLoop")
    @patch("seclens.evaluation.runner.CostTracker")
    @patch("seclens.evaluation.runner.ToolLogger")
    def test_cleanup_on_error(
        self,
        mock_tl_cls: MagicMock,
        mock_cost_cls: MagicMock,
        mock_runner_cls: MagicMock,
        mock_sandbox_cls: MagicMock,
        positive_task: Task,
        config_layer2: RunConfig,
    ) -> None:
        mock_sandbox = MagicMock()
        mock_sandbox.create.return_value = Path("/tmp/sandbox/test-pos-001")
        mock_sandbox_cls.return_value = mock_sandbox

        mock_runner = MagicMock()
        mock_runner.run.side_effect = RuntimeError("LLM error")
        mock_runner_cls.return_value = mock_runner

        mock_cost_cls.return_value = MagicMock()
        mock_tl_cls.return_value = MagicMock()

        adapter = MagicMock()
        eval_output = evaluate_task(positive_task, adapter, config_layer2)
        result = eval_output.result

        assert result.error == "RuntimeError: LLM error"
        mock_sandbox.cleanup.assert_called_once_with("test-pos-001")

    @patch("seclens.evaluation.runner.EngineLoop")
    @patch("seclens.evaluation.runner.CostTracker")
    @patch("seclens.evaluation.runner.ToolLogger")
    def test_shared_sandbox_manager(
        self,
        mock_tl_cls: MagicMock,
        mock_cost_cls: MagicMock,
        mock_runner_cls: MagicMock,
        positive_task: Task,
        config_layer2: RunConfig,
    ) -> None:
        shared_manager = MagicMock()
        shared_manager.create.return_value = Path("/tmp/sandbox/test-pos-001")

        loop_result = _make_engineloop_result('{"vulnerable": true}')
        mock_runner = MagicMock()
        mock_runner.run.return_value = loop_result
        mock_runner_cls.return_value = mock_runner

        mock_cost = MagicMock()
        mock_cost.current_cost = 0.01
        mock_cost_cls.return_value = mock_cost

        mock_tl = MagicMock()
        mock_tl.log = []
        mock_tl_cls.return_value = mock_tl

        adapter = MagicMock()
        eval_output = evaluate_task(
            positive_task, adapter, config_layer2,
            sandbox_manager=shared_manager,
        )

        assert eval_output.result.error is None
        shared_manager.create.assert_called_once()
        shared_manager.cleanup.assert_called_once()

    @patch("seclens.evaluation.runner.SandboxManager")
    @patch("seclens.evaluation.runner.EngineLoop")
    @patch("seclens.evaluation.runner.CostTracker")
    @patch("seclens.evaluation.runner.ToolLogger")
    def test_tool_calls_counted(
        self,
        mock_tl_cls: MagicMock,
        mock_cost_cls: MagicMock,
        mock_runner_cls: MagicMock,
        mock_sandbox_cls: MagicMock,
        positive_task: Task,
        config_layer2: RunConfig,
    ) -> None:
        from engine_harness import ToolCallRecord

        mock_sandbox = MagicMock()
        mock_sandbox.create.return_value = Path("/tmp/sandbox/test-pos-001")
        mock_sandbox_cls.return_value = mock_sandbox

        loop_result = _make_engineloop_result('{"vulnerable": true}', turns=3)
        mock_runner = MagicMock()
        mock_runner.run.return_value = loop_result
        mock_runner_cls.return_value = mock_runner

        mock_cost = MagicMock()
        mock_cost.current_cost = 0.03
        mock_cost_cls.return_value = mock_cost

        tool_records = [
            ToolCallRecord(
                tool="read_file", input={"path": "app.py"},
                output_length=500, duration_ms=50,
            ),
            ToolCallRecord(
                tool="search", input={"query": "execute"},
                output_length=200, duration_ms=30,
            ),
        ]
        mock_tl = MagicMock()
        mock_tl.log = tool_records
        mock_tl_cls.return_value = mock_tl

        adapter = MagicMock()
        eval_output = evaluate_task(positive_task, adapter, config_layer2)
        result = eval_output.result

        assert result.metrics.tool_calls == 2
        assert result.metrics.turns == 3
