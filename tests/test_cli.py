"""Tests for CLI commands."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from seclens.cli.main import app
from seclens.schemas.output import ParsedOutput, ParseResult, ParseStatus
from seclens.schemas.scoring import RunMetadata, TaskMetrics, TaskResult, TaskScore
from seclens.schemas.task import TaskType

runner = CliRunner()


def _make_run_metadata(model: str = "test/model") -> RunMetadata:
    return RunMetadata(
        model=model,
        prompt="base",
        layer=1,
        mode="guided",
        timestamp="2026-03-09T12:00:00Z",
        seclens_version="0.1.0",
        seed=42,
    )


def _make_result(
    task_id: str,
    task_type: TaskType = TaskType.TRUE_POSITIVE,
    verdict: int = 1,
    model: str = "test/model",
) -> TaskResult:
    max_pts = 3 if task_type == TaskType.TRUE_POSITIVE else 1
    return TaskResult(
        task_id=task_id,
        task_type=task_type,
        task_category="sql_injection",
        task_language="python",
        run_metadata=_make_run_metadata(model),
        parse_result=ParseResult(
            status=ParseStatus.FULL,
            output=ParsedOutput(vulnerable=True),
            raw_response="",
        ),
        scores=TaskScore(
            verdict=verdict, cwe=0, location=0,
            earned=verdict, max_task_points=max_pts,
        ),
        metrics=TaskMetrics(
            input_tokens=100, output_tokens=50, total_tokens=150,
            cost_usd=0.01, turns=1,
        ),
    )


class TestCLIHelp:
    def test_no_args_shows_help(self) -> None:
        result = runner.invoke(app, [])
        # Typer exits with 0 or 2 when no_args_is_help=True
        assert result.exit_code in (0, 2)
        assert "SecLens" in result.output or "Usage" in result.output

    def test_run_help(self) -> None:
        result = runner.invoke(app, ["run", "--help"])
        assert result.exit_code == 0
        assert "--model" in result.output
        assert "--dataset" in result.output

    def test_report_help(self) -> None:
        result = runner.invoke(app, ["report", "--help"])
        assert result.exit_code == 0
        assert "--run" in result.output

    def test_compare_help(self) -> None:
        result = runner.invoke(app, ["compare", "--help"])
        assert result.exit_code == 0
        assert "--run" in result.output


class TestRunCommand:
    @patch("seclens.cli.run.create_adapter")
    @patch("seclens.cli.run.load_dataset")
    @patch("seclens.cli.run.evaluate_task")
    def test_dry_run(
        self,
        mock_eval: MagicMock,
        mock_load: MagicMock,
        mock_adapter: MagicMock,
    ) -> None:
        mock_load.return_value = [MagicMock(id="t1"), MagicMock(id="t2")]
        result = runner.invoke(app, [
            "run",
            "--model", "test/model",
            "--dataset", "test.jsonl",
            "--dry-run",
        ])
        assert result.exit_code == 0
        assert "Dry run" in result.output
        mock_eval.assert_not_called()

    @patch("seclens.cli.run.create_adapter")
    @patch("seclens.cli.run.load_dataset")
    @patch("seclens.cli.run.evaluate_task")
    @patch("seclens.cli.run.write_result")
    @patch("seclens.cli.run._run_report")
    def test_single_worker_run(
        self,
        mock_report: MagicMock,
        mock_write: MagicMock,
        mock_eval: MagicMock,
        mock_load: MagicMock,
        mock_adapter: MagicMock,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from seclens.evaluation.runner import EvalOutput

        mock_task = MagicMock()
        mock_task.id = "t1"
        mock_task.repository.url = "https://github.com/test/repo"
        mock_task.repository.language = "python"
        mock_task.ground_truth.category = "sql_injection"
        mock_load.return_value = [mock_task]
        mock_eval.return_value = EvalOutput(result=_make_result("t1"))

        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, [
            "run",
            "--model", "test/model",
            "--dataset", "test.jsonl",
            "--workers", "1",
        ])
        assert result.exit_code == 0
        assert "Evaluation complete" in result.output
        mock_eval.assert_called_once()

    @patch("seclens.cli.run.create_adapter")
    @patch("seclens.cli.run.load_dataset")
    @patch("seclens.cli.run.get_completed_ids")
    def test_resume_all_complete(
        self,
        mock_completed: MagicMock,
        mock_load: MagicMock,
        mock_adapter: MagicMock,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        mock_task = MagicMock()
        mock_task.id = "t1"
        mock_load.return_value = [mock_task]
        mock_completed.return_value = {"t1"}

        monkeypatch.chdir(tmp_path)
        out_dir = tmp_path / "out"
        out_dir.mkdir()
        # Create a file matching the output pattern so resume finds it
        # We need to patch _result_filename to return a known name
        with patch("seclens.cli.run._result_filename", return_value="results.jsonl"):
            (out_dir / "results.jsonl").touch()
            result = runner.invoke(app, [
                "run",
                "--model", "test/model",
                "--dataset", "test.jsonl",
                "--resume",
            ])
        assert result.exit_code == 0
        assert "All tasks already completed" in result.output


class TestReportCommand:
    def test_json_output(self, tmp_path: Path) -> None:
        from seclens.results.io import write_result

        results_path = tmp_path / "results.jsonl"
        for i in range(4):
            task_type = TaskType.TRUE_POSITIVE if i < 2 else TaskType.POST_PATCH
            write_result(results_path, _make_result(f"t{i}", task_type=task_type))

        json_output = tmp_path / "report.json"
        result = runner.invoke(app, [
            "report",
            "--run", str(results_path),
            "--out", str(json_output),
        ])
        assert result.exit_code == 0
        assert json_output.exists()
        assert "Report written" in result.output

    def test_terminal_output(self, tmp_path: Path) -> None:
        from seclens.results.io import write_result

        results_path = tmp_path / "results.jsonl"
        for i in range(4):
            task_type = TaskType.TRUE_POSITIVE if i < 2 else TaskType.POST_PATCH
            write_result(results_path, _make_result(f"t{i}", task_type=task_type))

        result = runner.invoke(app, [
            "report",
            "--run", str(results_path),
        ])
        assert result.exit_code == 0
        assert "Leaderboard Score" in result.output

    def test_empty_results(self, tmp_path: Path) -> None:
        results_path = tmp_path / "results.jsonl"
        results_path.write_text("")
        result = runner.invoke(app, [
            "report",
            "--run", str(results_path),
        ])
        assert result.exit_code == 1


class TestCompareCommand:
    def test_compare_two_runs(self, tmp_path: Path) -> None:
        from seclens.results.io import write_result

        run1 = tmp_path / "run1.jsonl"
        run2 = tmp_path / "run2.jsonl"

        for i in range(4):
            task_type = TaskType.TRUE_POSITIVE if i < 2 else TaskType.POST_PATCH
            write_result(run1, _make_result(f"t{i}", task_type=task_type, model="model-a"))
            write_result(run2, _make_result(f"t{i}", task_type=task_type, verdict=0, model="model-b"))

        result = runner.invoke(app, [
            "compare",
            "--run", str(run1),
            "--run", str(run2),
        ])
        assert result.exit_code == 0
        assert "Run Comparison" in result.output

    def test_compare_needs_two(self, tmp_path: Path) -> None:
        from seclens.results.io import write_result

        run1 = tmp_path / "run1.jsonl"
        write_result(run1, _make_result("t1"))

        result = runner.invoke(app, [
            "compare",
            "--run", str(run1),
        ])
        assert result.exit_code == 1
