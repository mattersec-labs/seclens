"""Tests for aggregate metrics computation."""

from __future__ import annotations

from seclens.schemas.output import ParsedOutput, ParseResult, ParseStatus
from seclens.schemas.scoring import RunMetadata, TaskMetrics, TaskResult, TaskScore, TaskType
from seclens.scoring.aggregate import _mcc, compute_aggregate


def _make_run_metadata() -> RunMetadata:
    return RunMetadata(
        model="test/model", prompt="base", layer="tool-use", mode="guided",
        timestamp="2026-03-09T12:00:00Z", seclens_version="0.1.0", seed=42,
    )


def _make_result(
    task_id: str,
    task_type: TaskType,
    verdict: int,
    cwe: int = 0,
    location: int = 0,
    error: str | None = None,
    vulnerable_pred: bool | None = None,
    cost: float = 0.01,
    tokens: int = 1000,
) -> TaskResult:
    max_pts = 3 if task_type == TaskType.TRUE_POSITIVE else 1
    earned = verdict + cwe + location if task_type == TaskType.TRUE_POSITIVE else verdict

    if vulnerable_pred is None:
        vulnerable_pred = (verdict == 1) == (task_type == TaskType.TRUE_POSITIVE)

    return TaskResult(
        task_id=task_id,
        task_type=task_type,
        task_category="sql_injection",
        task_language="python",
        run_metadata=_make_run_metadata(),
        parse_result=ParseResult(
            status=ParseStatus.FAILED if error else ParseStatus.FULL,
            output=None if error else ParsedOutput(vulnerable=vulnerable_pred),
            raw_response="",
        ),
        scores=TaskScore(verdict=verdict, cwe=cwe, location=location, earned=earned, max_task_points=max_pts),
        metrics=TaskMetrics(
            input_tokens=tokens,
            output_tokens=tokens // 2,
            total_tokens=tokens + tokens // 2,
            cost_usd=cost,
            turns=1,
        ),
        error=error,
    )


class TestMCC:
    def test_perfect(self) -> None:
        assert _mcc([1, 1, 0, 0], [1, 1, 0, 0]) == 1.0

    def test_inverse(self) -> None:
        assert _mcc([0, 0, 1, 1], [1, 1, 0, 0]) == -1.0

    def test_random(self) -> None:
        mcc = _mcc([1, 0, 1, 0], [1, 1, 0, 0])
        assert -1.0 <= mcc <= 1.0

    def test_all_same_prediction(self) -> None:
        assert _mcc([1, 1, 1, 1], [1, 1, 0, 0]) == 0.0

    def test_empty(self) -> None:
        assert _mcc([], []) == 0.0


class TestComputeAggregate:
    def test_basic_report(self) -> None:
        results = [
            _make_result("t1", TaskType.TRUE_POSITIVE, verdict=1, cwe=1, location=1),
            _make_result("t2", TaskType.TRUE_POSITIVE, verdict=1, cwe=0, location=0),
            _make_result("t3", TaskType.POST_PATCH, verdict=1),
            _make_result("t4", TaskType.POST_PATCH, verdict=0),
        ]
        report = compute_aggregate(results, _make_run_metadata())

        assert report.task_count == 4
        assert report.errors == 0
        assert report.parse_failures == 0
        assert report.leaderboard_score.mean > 0
        assert report.core.task_count == 4

    def test_error_counted(self) -> None:
        results = [
            _make_result("t1", TaskType.TRUE_POSITIVE, verdict=0, error="timeout"),
            _make_result("t2", TaskType.POST_PATCH, verdict=1),
        ]
        report = compute_aggregate(results, _make_run_metadata())
        assert report.errors == 1

    def test_bootstrap_ci_deterministic(self) -> None:
        results = [
            _make_result(f"t{i}", TaskType.TRUE_POSITIVE, verdict=1, cwe=1, location=1)
            for i in range(10)
        ]
        r1 = compute_aggregate(results, _make_run_metadata())
        r2 = compute_aggregate(results, _make_run_metadata())
        assert r1.leaderboard_score.ci_lower == r2.leaderboard_score.ci_lower
        assert r1.leaderboard_score.ci_upper == r2.leaderboard_score.ci_upper

    def test_cost_metrics(self) -> None:
        results = [
            _make_result("t1", TaskType.TRUE_POSITIVE, verdict=1, cost=0.05, tokens=2000),
            _make_result("t2", TaskType.POST_PATCH, verdict=1, cost=0.03, tokens=1000),
        ]
        report = compute_aggregate(results, _make_run_metadata())
        assert report.cost.total_cost_usd == 0.08
        assert report.cost.avg_cost_per_task == 0.04
        assert report.cost.mcc_per_dollar is not None

    def test_breakdowns(self) -> None:
        results = [
            _make_result("t1", TaskType.TRUE_POSITIVE, verdict=1, cwe=1, location=1),
            _make_result("t2", TaskType.POST_PATCH, verdict=1),
        ]
        report = compute_aggregate(results, _make_run_metadata())
        assert "sql_injection" in report.by_category
        assert "python" in report.by_language

    def test_perfect_score(self) -> None:
        results = [
            _make_result("t1", TaskType.TRUE_POSITIVE, verdict=1, cwe=1, location=1),
            _make_result("t2", TaskType.POST_PATCH, verdict=1),
        ]
        report = compute_aggregate(results, _make_run_metadata())
        # 4 earned out of 4 max (3+1)
        assert report.leaderboard_score.mean == 1.0
