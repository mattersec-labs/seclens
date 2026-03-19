"""Tests for model report generation."""

from __future__ import annotations

import json

import pytest

from seclens.schemas.model_report import GroupBreakdown, ModelReport
from seclens.schemas.output import ParsedOutput, ParseResult, ParseStatus
from seclens.schemas.scoring import RunMetadata, TaskMetrics, TaskResult, TaskScore
from seclens.scoring.model_report import generate_model_report


def _meta() -> RunMetadata:
    return RunMetadata(
        model="test/model", prompt="base", layer="code-in-prompt", mode="guided",
        timestamp="2026-01-01T00:00:00Z", seclens_version="0.1.0", seed=42,
    )


def _make_result(
    task_type: str = "true_positive",
    verdict: int = 1,
    cwe: int = 1,
    location: float = 0.5,
    category: str = "Injection",
    language: str = "python",
    severity: str = "high",
    pred_vulnerable: bool = True,
) -> TaskResult:
    return TaskResult(
        task_id=f"test-{id(object())}",
        task_type=task_type,
        task_category=category,
        task_language=language,
        ground_truth_cwe="CWE-89",
        task_severity=severity,
        run_metadata=_meta(),
        parse_result=ParseResult(
            status=ParseStatus.FULL,
            output=ParsedOutput(vulnerable=pred_vulnerable, cwe="CWE-89" if cwe else None, reasoning="test"),
            raw_response="",
        ),
        scores=TaskScore(
            verdict=verdict, cwe=cwe, location=location,
            earned=float(verdict + cwe + location) if task_type == "true_positive" else float(verdict),
            max_task_points=3 if task_type == "true_positive" else 1,
        ),
        metrics=TaskMetrics(cost_usd=0.01, total_tokens=1000, turns=1, wall_time_s=5.0),
    )


@pytest.fixture
def results() -> list[TaskResult]:
    r = []
    for _ in range(5):
        r.append(_make_result(category="Injection", language="python"))
    for _ in range(3):
        r.append(_make_result(category="Broken Access Control", language="java"))
    for _ in range(5):
        r.append(_make_result(task_type="post_patch", verdict=1, cwe=0, location=0.0, pred_vulnerable=False))
    return r


class TestGenerateModelReport:
    def test_returns_valid_report(self, results: list[TaskResult]) -> None:
        report = generate_model_report(results, _meta(), dataset="test.jsonl")
        assert isinstance(report, ModelReport)
        assert report.model == "test/model"
        assert report.total_tasks == 13
        assert report.dataset == "test.jsonl"

    def test_contains_35_dimensions(self, results: list[TaskResult]) -> None:
        report = generate_model_report(results, _meta())
        assert len(report.dimensions) == 35
        for dim_id in [f"D{i}" for i in range(1, 36)]:
            assert dim_id in report.dimensions

    def test_dimensions_are_rounded(self, results: list[TaskResult]) -> None:
        report = generate_model_report(results, _meta())
        for value in report.dimensions.values():
            # Should have at most 4 decimal places
            assert round(value, 4) == value

    def test_has_category_breakdowns(self, results: list[TaskResult]) -> None:
        report = generate_model_report(results, _meta())
        assert "Injection" in report.by_category
        assert "Broken Access Control" in report.by_category

    def test_has_language_breakdowns(self, results: list[TaskResult]) -> None:
        report = generate_model_report(results, _meta())
        assert "python" in report.by_language
        assert "java" in report.by_language

    def test_breakdown_metrics(self, results: list[TaskResult]) -> None:
        report = generate_model_report(results, _meta())
        inj = report.by_category["Injection"]
        assert isinstance(inj, GroupBreakdown)
        assert inj.task_count > 0
        assert inj.positive_count > 0
        assert 0.0 <= inj.recall <= 1.0
        assert 0.0 <= inj.precision <= 1.0
        assert 0.0 <= inj.f1 <= 1.0
        assert inj.avg_cost > 0

    def test_has_aggregate_scores(self, results: list[TaskResult]) -> None:
        report = generate_model_report(results, _meta())
        assert report.leaderboard_score.mean > 0
        assert report.core.task_count > 0
        assert report.cost.total_cost_usd > 0

    def test_json_round_trip(self, results: list[TaskResult]) -> None:
        report = generate_model_report(results, _meta())
        json_str = report.model_dump_json()
        restored = ModelReport.model_validate_json(json_str)
        assert restored.model == report.model
        assert restored.total_tasks == report.total_tasks
        assert len(restored.dimensions) == 35
        assert len(restored.by_category) == len(report.by_category)

    def test_empty_results(self) -> None:
        report = generate_model_report([], _meta())
        assert report.total_tasks == 0
        assert report.errors == 0
        assert len(report.dimensions) == 35

    def test_error_tracking(self) -> None:
        results = [
            _make_result(),
            TaskResult(
                task_id="err",
                task_type="true_positive",
                task_category="Injection",
                task_language="python",
                ground_truth_cwe="CWE-89",
                task_severity="high",
                run_metadata=_meta(),
                parse_result=ParseResult(status=ParseStatus.FAILED, raw_response=""),
                scores=TaskScore(verdict=0, cwe=0, location=0.0, earned=0.0, max_task_points=3),
                metrics=TaskMetrics(),
                error="API timeout",
            ),
        ]
        report = generate_model_report(results, _meta())
        assert report.errors == 1
