"""Tests for Pydantic data models."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from seclens.schemas import (
    AggregateReport,
    ConfidenceInterval,
    CoreMetrics,
    CostMetrics,
    GroundTruth,
    Location,
    ParsedOutput,
    ParseResult,
    ParseStatus,
    RunMetadata,
    Task,
    TaskMetrics,
    TaskResult,
    TaskScore,
    TaskType,
)

BOOTSTRAP_PATH = Path(__file__).parent.parent.parent / "benchmark-harness-research" / "bootstrap.jsonl"


# --- TaskType ---


class TestTaskType:
    def test_enum_values(self) -> None:
        assert TaskType.TRUE_POSITIVE == "true_positive"
        assert TaskType.POST_PATCH == "post_patch"
        assert TaskType.SAST_FALSE_POSITIVE == "sast_false_positive"

    def test_from_string(self) -> None:
        assert TaskType("true_positive") is TaskType.TRUE_POSITIVE


# --- Location ---


class TestLocation:
    def test_creation(self) -> None:
        loc = Location(file="foo.py", line_start=10, line_end=20)
        assert loc.file == "foo.py"
        assert loc.line_start == 10
        assert loc.line_end == 20

    def test_serialization_roundtrip(self) -> None:
        loc = Location(file="foo.py", line_start=10, line_end=20)
        data = json.loads(loc.model_dump_json())
        restored = Location.model_validate(data)
        assert restored == loc


# --- GroundTruth ---


class TestGroundTruth:
    def test_positive_task_full(self) -> None:
        gt = GroundTruth(
            vulnerable=True,
            cwe="CWE-89",
            category="sql_injection",
            location=Location(file="foo.py", line_start=10, line_end=20),
        )
        assert gt.vulnerable is True
        assert gt.cwe == "CWE-89"

    def test_negative_task_minimal(self) -> None:
        gt = GroundTruth(vulnerable=False)
        assert gt.vulnerable is False
        assert gt.cwe is None
        assert gt.category is None
        assert gt.location is None

    def test_negative_task_with_optional_cwe(self) -> None:
        gt = GroundTruth(vulnerable=False, cwe="CWE-89", category="sql_injection")
        assert gt.vulnerable is False
        assert gt.cwe == "CWE-89"


# --- Task ---


class TestTask:
    def _make_task(self, **overrides) -> Task:
        defaults = {
            "id": "test-001",
            "version": "1.0",
            "type": "true_positive",
            "max_task_points": 3,
            "repository": {"url": "https://github.com/django/django", "commit": "abc123", "language": "python"},
            "target": {"function": "my_func", "file": "app.py", "line_start": 1, "line_end": 10},
            "ground_truth": {"vulnerable": True, "cwe": "CWE-89", "category": "sql_injection"},
        }
        defaults.update(overrides)
        return Task.model_validate(defaults)

    def test_positive_task(self) -> None:
        task = self._make_task()
        assert task.type is TaskType.TRUE_POSITIVE
        assert task.max_task_points == 3

    def test_negative_task(self) -> None:
        task = self._make_task(
            id="test-002",
            type="post_patch",
            max_task_points=1,
            ground_truth={"vulnerable": False},
        )
        assert task.type is TaskType.POST_PATCH
        assert task.max_task_points == 1
        assert task.ground_truth.cwe is None

    def test_invalid_max_points(self) -> None:
        with pytest.raises(ValidationError):
            self._make_task(max_task_points=5)

    def test_metadata_defaults(self) -> None:
        task = self._make_task()
        assert task.metadata.cve_id is None
        assert task.metadata.paired_with is None

    def test_metadata_populated(self) -> None:
        task = self._make_task(metadata={"cve_id": "CVE-2024-1234", "paired_with": "test-002"})
        assert task.metadata.cve_id == "CVE-2024-1234"

    def test_json_roundtrip(self) -> None:
        task = self._make_task()
        restored = Task.model_validate_json(task.model_dump_json())
        assert restored == task


# --- ParsedOutput ---


class TestParsedOutput:
    def test_all_none_defaults(self) -> None:
        output = ParsedOutput()
        assert output.vulnerable is None
        assert output.cwe is None
        assert output.location is None

    def test_positive_response(self) -> None:
        output = ParsedOutput(
            vulnerable=True,
            cwe="CWE-89",
            location=Location(file="foo.py", line_start=10, line_end=20),
            reasoning="SQL injection via string concatenation",
        )
        assert output.vulnerable is True

    def test_negative_response(self) -> None:
        output = ParsedOutput(vulnerable=False, reasoning="No vulnerability found")
        assert output.vulnerable is False
        assert output.cwe is None
        assert output.location is None

    def test_json_schema_generation(self) -> None:
        schema = ParsedOutput.model_json_schema(mode="serialization")
        assert "properties" in schema
        assert "vulnerable" in schema["properties"]
        assert "cwe" in schema["properties"]
        assert "location" in schema["properties"]


# --- ParseResult ---


class TestParseResult:
    def test_full_parse(self) -> None:
        result = ParseResult(
            status=ParseStatus.FULL,
            output=ParsedOutput(vulnerable=True, cwe="CWE-89"),
            raw_response='{"vulnerable": true, "cwe": "CWE-89"}',
            parse_method="json_direct",
        )
        assert result.status is ParseStatus.FULL

    def test_failed_parse(self) -> None:
        result = ParseResult(
            status=ParseStatus.FAILED,
            raw_response="I think there might be a vulnerability...",
        )
        assert result.output is None


# --- TaskScore ---


class TestTaskScore:
    def test_positive_full_score(self) -> None:
        score = TaskScore(verdict=1, cwe=1, location=1, earned=3, max_task_points=3)
        assert score.earned == 3

    def test_negative_correct(self) -> None:
        score = TaskScore(verdict=1, cwe=0, location=0, earned=1, max_task_points=1)
        assert score.earned == 1

    def test_invalid_earned_exceeds_max(self) -> None:
        with pytest.raises(ValidationError):
            TaskScore(verdict=1, cwe=1, location=1, earned=4, max_task_points=3)

    def test_invalid_negative_earned(self) -> None:
        with pytest.raises(ValidationError):
            TaskScore(verdict=0, cwe=0, location=0, earned=-1, max_task_points=3)


# --- TaskMetrics ---


class TestTaskMetrics:
    def test_defaults(self) -> None:
        metrics = TaskMetrics()
        assert metrics.input_tokens == 0
        assert metrics.cost_usd == 0.0


# --- RunMetadata ---


class TestRunMetadata:
    def test_creation(self) -> None:
        meta = RunMetadata(
            model="anthropic/claude-sonnet-4-20250514",
            prompt="base",
            layer=2,
            mode="guided",
            timestamp="2026-03-09T12:00:00Z",
            seclens_version="0.1.0",
            seed=42,
        )
        assert meta.layer == 2
        assert meta.mode == "guided"

    def test_invalid_layer(self) -> None:
        with pytest.raises(ValidationError):
            RunMetadata(
                model="m", prompt="p", layer=3, mode="guided",
                timestamp="t", seclens_version="v", seed=0,
            )


# --- TaskResult ---


class TestTaskResult:
    def test_creation(self) -> None:
        result = TaskResult(
            task_id="test-001",
            task_type=TaskType.TRUE_POSITIVE,
            task_category="sql_injection",
            task_language="python",
            run_metadata=RunMetadata(
                model="m", prompt="base", layer=2, mode="guided",
                timestamp="2026-03-09T12:00:00Z", seclens_version="0.1.0", seed=42,
            ),
            parse_result=ParseResult(status=ParseStatus.FULL, raw_response="{}"),
            scores=TaskScore(verdict=1, cwe=1, location=1, earned=3, max_task_points=3),
        )
        assert result.task_id == "test-001"
        assert result.error is None
        assert result.tool_log == []

    def test_error_result(self) -> None:
        result = TaskResult(
            task_id="test-001",
            task_type=TaskType.TRUE_POSITIVE,
            task_language="python",
            run_metadata=RunMetadata(
                model="m", prompt="base", layer=2, mode="guided",
                timestamp="t", seclens_version="0.1.0", seed=42,
            ),
            parse_result=ParseResult(status=ParseStatus.FAILED, raw_response=""),
            scores=TaskScore(verdict=0, cwe=0, location=0, earned=0, max_task_points=3),
            error="API timeout",
        )
        assert result.error == "API timeout"
        assert result.scores.earned == 0

    def test_json_roundtrip(self) -> None:
        result = TaskResult(
            task_id="test-001",
            task_type=TaskType.TRUE_POSITIVE,
            task_language="python",
            run_metadata=RunMetadata(
                model="m", prompt="base", layer=2, mode="guided",
                timestamp="t", seclens_version="0.1.0", seed=42,
            ),
            parse_result=ParseResult(status=ParseStatus.FULL, raw_response="{}"),
            scores=TaskScore(verdict=1, cwe=1, location=1, earned=3, max_task_points=3),
        )
        restored = TaskResult.model_validate_json(result.model_dump_json())
        assert restored == result


# --- Report Models ---


class TestReportModels:
    def _make_ci(self, mean: float = 0.8) -> ConfidenceInterval:
        return ConfidenceInterval(mean=mean, stderr=0.05, ci_lower=0.7, ci_upper=0.9)

    def test_confidence_interval(self) -> None:
        ci = self._make_ci()
        assert ci.ci_lower < ci.mean < ci.ci_upper

    def test_core_metrics(self) -> None:
        core = CoreMetrics(
            verdict_mcc=self._make_ci(),
            cwe_accuracy=self._make_ci(),
            location_accuracy=self._make_ci(),
            task_count=50,
        )
        assert core.task_count == 50

    def test_cost_metrics_none_ratios(self) -> None:
        cost = CostMetrics(
            total_cost_usd=0.0,
            avg_cost_per_task=0.0,
            total_input_tokens=0,
            total_output_tokens=0,
            total_tokens=0,
        )
        assert cost.mcc_per_dollar is None
        assert cost.score_per_1k_tokens is None

    def test_aggregate_report(self) -> None:
        ci = self._make_ci()
        core = CoreMetrics(
            verdict_mcc=ci, cwe_accuracy=ci, location_accuracy=ci, task_count=50,
        )
        cost = CostMetrics(
            total_cost_usd=1.50, avg_cost_per_task=0.03,
            total_input_tokens=100000, total_output_tokens=50000, total_tokens=150000,
            mcc_per_dollar=0.53, score_per_1k_tokens=5.3,
        )
        report = AggregateReport(
            leaderboard_score=ci,
            core=core,
            cost=cost,
            run_metadata=RunMetadata(
                model="m", prompt="base", layer=2, mode="guided",
                timestamp="t", seclens_version="0.1.0", seed=42,
            ),
            task_count=50,
            parse_failures=2,
            errors=1,
        )
        assert report.task_count == 50
        assert report.parse_failures == 2


# --- Bootstrap Dataset Validation ---


class TestBootstrapValidation:
    @pytest.fixture()
    def bootstrap_tasks(self) -> list[Task]:
        if not BOOTSTRAP_PATH.exists():
            pytest.skip("bootstrap.jsonl not found")
        tasks = []
        with open(BOOTSTRAP_PATH) as f:
            for line in f:
                tasks.append(Task.model_validate_json(line))
        return tasks

    def test_all_tasks_parse(self, bootstrap_tasks: list[Task]) -> None:
        assert len(bootstrap_tasks) > 0

    def test_task_count(self, bootstrap_tasks: list[Task]) -> None:
        assert len(bootstrap_tasks) == 12

    def test_positive_negative_split(self, bootstrap_tasks: list[Task]) -> None:
        positive = [t for t in bootstrap_tasks if t.ground_truth.vulnerable]
        negative = [t for t in bootstrap_tasks if not t.ground_truth.vulnerable]
        assert len(positive) == 6
        assert len(negative) == 6

    def test_positive_tasks_have_max_3(self, bootstrap_tasks: list[Task]) -> None:
        for task in bootstrap_tasks:
            if task.ground_truth.vulnerable:
                assert task.max_task_points == 3

    def test_negative_tasks_have_max_1(self, bootstrap_tasks: list[Task]) -> None:
        for task in bootstrap_tasks:
            if not task.ground_truth.vulnerable:
                assert task.max_task_points == 1

    def test_positive_tasks_have_location(self, bootstrap_tasks: list[Task]) -> None:
        for task in bootstrap_tasks:
            if task.ground_truth.vulnerable:
                assert task.ground_truth.location is not None

    def test_negative_tasks_have_no_location(self, bootstrap_tasks: list[Task]) -> None:
        for task in bootstrap_tasks:
            if not task.ground_truth.vulnerable:
                assert task.ground_truth.location is None
