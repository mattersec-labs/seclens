"""Tests for role-based CLI commands (report and compare)."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest
from typer.testing import CliRunner

from seclens.cli.main import app
from seclens.schemas.output import ParsedOutput, ParseResult, ParseStatus
from seclens.schemas.scoring import RunMetadata, TaskMetrics, TaskResult, TaskScore

runner = CliRunner()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_result(model: str = "test/model", verdict: int = 1) -> TaskResult:
    return TaskResult(
        task_id=f"test-{id(object())}",
        task_type="true_positive",
        task_category="Injection",
        task_language="python",
        ground_truth_cwe="CWE-89",
        task_severity="high",
        run_metadata=RunMetadata(
            model=model, prompt="base", layer="code-in-prompt", mode="guided",
            timestamp="2026-01-01T00:00:00Z", seclens_version="0.1.0", seed=42,
        ),
        parse_result=ParseResult(
            status=ParseStatus.FULL,
            output=ParsedOutput(vulnerable=True, cwe="CWE-89", reasoning="test"),
            raw_response="",
        ),
        scores=TaskScore(verdict=verdict, cwe=1, location=0.5, earned=2.5, max_task_points=3),
        metrics=TaskMetrics(cost_usd=0.01, total_tokens=1000, turns=1, wall_time_s=5.0),
    )


@pytest.fixture
def results_file(tmp_path: Path) -> Path:
    """Create a temp results JSONL with 10 tasks."""
    path = tmp_path / "results.jsonl"
    results = [_make_result() for _ in range(5)]
    results += [
        TaskResult(
            task_id=f"neg-{i}",
            task_type="post_patch",
            task_category="Injection",
            task_language="python",
            ground_truth_cwe=None,
            task_severity=None,
            run_metadata=results[0].run_metadata,
            parse_result=ParseResult(
                status=ParseStatus.FULL,
                output=ParsedOutput(vulnerable=False),
                raw_response="",
            ),
            scores=TaskScore(verdict=1, cwe=0, location=0.0, earned=1.0, max_task_points=1),
            metrics=TaskMetrics(cost_usd=0.01, total_tokens=500, turns=1, wall_time_s=3.0),
        )
        for i in range(5)
    ]
    with open(path, "w") as f:
        for r in results:
            f.write(r.model_dump_json() + "\n")
    return path


@pytest.fixture
def second_results_file(tmp_path: Path) -> Path:
    """Create a second results file with different model."""
    path = tmp_path / "results2.jsonl"
    results = [_make_result(model="other/model", verdict=0) for _ in range(5)]
    results += [
        TaskResult(
            task_id=f"neg2-{i}",
            task_type="post_patch",
            task_category="Injection",
            task_language="python",
            ground_truth_cwe=None,
            task_severity=None,
            run_metadata=RunMetadata(
                model="other/model", prompt="base", layer="code-in-prompt", mode="guided",
                timestamp="2026-01-01T00:00:00Z", seclens_version="0.1.0", seed=42,
            ),
            parse_result=ParseResult(
                status=ParseStatus.FULL,
                output=ParsedOutput(vulnerable=False),
                raw_response="",
            ),
            scores=TaskScore(verdict=1, cwe=0, location=0.0, earned=1.0, max_task_points=1),
            metrics=TaskMetrics(cost_usd=0.01, total_tokens=500, turns=1, wall_time_s=3.0),
        )
        for i in range(5)
    ]
    with open(path, "w") as f:
        for r in results:
            f.write(r.model_dump_json() + "\n")
    return path


# ---------------------------------------------------------------------------
# Report command tests
# ---------------------------------------------------------------------------

class TestReportCommand:
    def test_single_role(self, results_file: Path) -> None:
        result = runner.invoke(app, ["report", "-r", str(results_file), "--role", "ciso"])
        assert result.exit_code == 0
        assert "Security Officer" in result.output
        assert "Decision Score" in result.output

    def test_all_roles(self, results_file: Path) -> None:
        result = runner.invoke(app, ["report", "-r", str(results_file), "--all-roles"])
        assert result.exit_code == 0
        assert "Role Scores" in result.output

    def test_json_output(self, results_file: Path, tmp_path: Path) -> None:
        out = tmp_path / "report.json"
        result = runner.invoke(app, ["report", "-r", str(results_file), "--role", "ciso", "-o", str(out)])
        assert result.exit_code == 0
        data = json.loads(out.read_text())
        assert "decision_score" in data
        assert "grade" in data

    def test_all_roles_json(self, results_file: Path, tmp_path: Path) -> None:
        out = tmp_path / "multi.json"
        result = runner.invoke(app, ["report", "-r", str(results_file), "--all-roles", "-o", str(out)])
        assert result.exit_code == 0
        data = json.loads(out.read_text())
        assert "reports" in data
        assert "ranking" in data

    def test_missing_role_flag(self, results_file: Path) -> None:
        result = runner.invoke(app, ["report", "-r", str(results_file)])
        assert result.exit_code != 0

    def test_both_role_and_all_roles(self, results_file: Path) -> None:
        result = runner.invoke(app, ["report", "-r", str(results_file), "--role", "ciso", "--all-roles"])
        assert result.exit_code != 0

    def test_missing_file(self) -> None:
        result = runner.invoke(app, ["report", "-r", "nonexistent.jsonl", "--role", "ciso"])
        assert result.exit_code != 0

    def test_invalid_role(self, results_file: Path) -> None:
        result = runner.invoke(app, ["report", "-r", str(results_file), "--role", "cfo"])
        assert result.exit_code != 0


# ---------------------------------------------------------------------------
# Compare command tests
# ---------------------------------------------------------------------------

class TestCompareCommand:
    def test_single_role_compare(self, results_file: Path, second_results_file: Path) -> None:
        result = runner.invoke(app, [
            "compare",
            "-r", str(results_file),
            "-r", str(second_results_file),
            "--role", "ciso",
        ])
        assert result.exit_code == 0
        assert "Comparison" in result.output

    def test_all_roles_compare(self, results_file: Path, second_results_file: Path) -> None:
        result = runner.invoke(app, [
            "compare",
            "-r", str(results_file),
            "-r", str(second_results_file),
            "--all-roles",
        ])
        assert result.exit_code == 0
        assert "Multi-Role" in result.output

    def test_missing_role_flag(self, results_file: Path, second_results_file: Path) -> None:
        result = runner.invoke(app, [
            "compare",
            "-r", str(results_file),
            "-r", str(second_results_file),
        ])
        assert result.exit_code != 0

    def test_single_run_fails(self, results_file: Path) -> None:
        result = runner.invoke(app, [
            "compare",
            "-r", str(results_file),
            "--role", "ciso",
        ])
        assert result.exit_code != 0


# ---------------------------------------------------------------------------
# Summary command tests
# ---------------------------------------------------------------------------

class TestSummaryCommand:
    def test_summary_runs(self, results_file: Path) -> None:
        result = runner.invoke(app, ["summary", "-r", str(results_file)])
        assert result.exit_code == 0
        assert "Score" in result.output or "Leaderboard" in result.output

    def test_summary_json(self, results_file: Path, tmp_path: Path) -> None:
        out = tmp_path / "summary.json"
        result = runner.invoke(app, ["summary", "-r", str(results_file), "-o", str(out)])
        assert result.exit_code == 0
        assert out.exists()
