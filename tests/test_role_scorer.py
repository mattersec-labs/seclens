"""Tests for role scoring engine."""

from __future__ import annotations

import pytest

from seclens.roles.scorer import generate_multi_role_report, generate_role_report
from seclens.roles.weights import list_roles
from seclens.schemas.output import ParsedOutput, ParseResult, ParseStatus
from seclens.schemas.role_report import MultiRoleReport, RoleReport
from seclens.schemas.scoring import RunMetadata, TaskMetrics, TaskResult, TaskScore


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _meta() -> RunMetadata:
    return RunMetadata(
        model="test/model", prompt="base", layer="tool-use", mode="guided",
        timestamp="2026-01-01T00:00:00Z", seclens_version="0.1.0", seed=42,
    )


def make_result(
    *,
    task_type: str = "true_positive",
    verdict: int = 1,
    cwe: int = 1,
    location: float = 0.8,
    category: str = "Injection",
    language: str = "python",
    severity: str | None = "high",
    pred_vulnerable: bool | None = True,
    reasoning: str | None = "Some reasoning",
    cost_usd: float = 0.1,
    total_tokens: int = 5000,
    tool_calls: int = 3,
    turns: int = 2,
    wall_time_s: float = 10.0,
    parse_status: str = "full",
    error: str | None = None,
) -> TaskResult:
    output = ParsedOutput(
        vulnerable=pred_vulnerable,
        cwe="CWE-89" if cwe else None,
        reasoning=reasoning,
    ) if parse_status != "failed" else None

    return TaskResult(
        task_id=f"test-{id(object())}",
        task_type=task_type,
        task_category=category,
        task_language=language,
        ground_truth_cwe="CWE-89",
        task_severity=severity,
        run_metadata=_meta(),
        parse_result=ParseResult(status=ParseStatus(parse_status), output=output, raw_response=""),
        scores=TaskScore(
            verdict=verdict, cwe=cwe, location=location,
            earned=float(verdict + cwe + location) if task_type == "true_positive" else float(verdict),
            max_task_points=3 if task_type == "true_positive" else 1,
        ),
        metrics=TaskMetrics(
            cost_usd=cost_usd, total_tokens=total_tokens,
            tool_calls=tool_calls, turns=turns, wall_time_s=wall_time_s,
        ),
        error=error,
    )


@pytest.fixture
def balanced_results() -> list[TaskResult]:
    results = []
    for _ in range(7):
        results.append(make_result(verdict=1))
    for _ in range(3):
        results.append(make_result(verdict=0, cwe=0, location=0.0, pred_vulnerable=False))
    for _ in range(5):
        results.append(make_result(task_type="post_patch", verdict=1, cwe=0, location=0.0, pred_vulnerable=False))
    for _ in range(5):
        results.append(make_result(task_type="post_patch", verdict=0, cwe=0, location=0.0, pred_vulnerable=True))
    return results


@pytest.fixture
def perfect_results() -> list[TaskResult]:
    results = []
    for _ in range(5):
        results.append(make_result(verdict=1, cwe=1, location=1.0))
    for _ in range(5):
        results.append(make_result(task_type="post_patch", verdict=1, cwe=0, location=0.0, pred_vulnerable=False))
    return results


@pytest.fixture
def no_severity_results() -> list[TaskResult]:
    results = []
    for _ in range(5):
        results.append(make_result(severity=None))
    for _ in range(5):
        results.append(make_result(task_type="post_patch", verdict=1, cwe=0, location=0.0, severity=None, pred_vulnerable=False))
    return results


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestGenerateRoleReport:
    @pytest.mark.parametrize("role", list_roles())
    def test_generates_valid_report(self, role: str, balanced_results: list[TaskResult]) -> None:
        report = generate_role_report(balanced_results, role)
        assert isinstance(report, RoleReport)
        assert 0 <= report.decision_score <= 100
        assert report.grade in ("A", "B", "C", "D", "F")
        assert report.role == role
        assert report.total_tasks == len(balanced_results)
        assert report.dimensions
        assert report.categories
        assert report.recommendation

    @pytest.mark.parametrize("role", list_roles())
    def test_dimensions_have_valid_scores(self, role: str, balanced_results: list[TaskResult]) -> None:
        report = generate_role_report(balanced_results, role)
        for dim in report.dimensions:
            assert 0.0 <= dim.normalized <= 1.0, f"{dim.id} normalized={dim.normalized}"
            assert dim.weight > 0
            assert dim.weighted_score >= 0

    def test_unknown_role_raises(self, balanced_results: list[TaskResult]) -> None:
        with pytest.raises(ValueError, match="Unknown role"):
            generate_role_report(balanced_results, "cfo")

    def test_empty_results(self) -> None:
        report = generate_role_report([], "ciso")
        # Empty results still produce a score (MCC=0→0.5, cost=0→1.0, etc.)
        # but grade should be F (score well below 60)
        assert report.grade == "F"
        assert report.total_tasks == 0
        assert report.decision_score < 60

    def test_auto_detects_model(self, balanced_results: list[TaskResult]) -> None:
        report = generate_role_report(balanced_results, "ciso")
        assert report.model == "test/model"

    def test_model_override(self, balanced_results: list[TaskResult]) -> None:
        report = generate_role_report(balanced_results, "ciso", model="custom/model")
        assert report.model == "custom/model"


class TestExcludedDimensions:
    def test_severity_excluded_when_missing(self, no_severity_results: list[TaskResult]) -> None:
        report = generate_role_report(no_severity_results, "ciso")
        # CISO has D28, D29 — should be excluded
        assert "D28" in report.excluded_dimensions
        assert "D29" in report.excluded_dimensions
        # Score should still be valid (reweighted)
        assert 0 <= report.decision_score <= 100

    def test_tool_dims_excluded_for_l1(self) -> None:
        """L1 results have no tool calls → tool dims excluded."""
        results = [
            make_result(tool_calls=0),
            make_result(task_type="post_patch", verdict=1, cwe=0, location=0.0, tool_calls=0, pred_vulnerable=False),
        ]
        report = generate_role_report(results, "ai_actor")
        # AI Actor has D25, D26, D27 — should be excluded for L1
        for dim_id in ("D25", "D26", "D27"):
            if dim_id in report.excluded_dimensions:
                assert True
                return
        # At least one tool dim should be excluded
        assert any(d in report.excluded_dimensions for d in ("D25", "D26", "D27"))

    def test_score_with_excluded_is_reweighted(self, no_severity_results: list[TaskResult]) -> None:
        """Score should be computed from available dimensions only."""
        report = generate_role_report(no_severity_results, "ciso")
        # With D28 (w=10) and D29 (w=8) excluded, total available weight < 80
        available_weight = sum(d.weight for d in report.dimensions)
        assert available_weight < 80


class TestGrading:
    def test_perfect_results_high_grade(self, perfect_results: list[TaskResult]) -> None:
        report = generate_role_report(perfect_results, "ciso")
        assert report.grade in ("A", "B"), f"Perfect results got grade {report.grade} ({report.decision_score})"

    def test_grade_boundaries(self) -> None:
        from seclens.roles.scorer import _score_to_grade
        assert _score_to_grade(95) == "A"
        assert _score_to_grade(75) == "A"
        assert _score_to_grade(74.9) == "B"
        assert _score_to_grade(60) == "B"
        assert _score_to_grade(59.9) == "C"
        assert _score_to_grade(50) == "C"
        assert _score_to_grade(49.9) == "D"
        assert _score_to_grade(40) == "D"
        assert _score_to_grade(39.9) == "F"
        assert _score_to_grade(0) == "F"


class TestRecommendation:
    def test_ciso_recommendation_context(self, balanced_results: list[TaskResult]) -> None:
        report = generate_role_report(balanced_results, "ciso")
        assert "security program" in report.recommendation

    def test_engineer_recommendation_context(self, balanced_results: list[TaskResult]) -> None:
        report = generate_role_report(balanced_results, "head_of_engineering")
        assert "development pipeline" in report.recommendation


class TestMultiRoleReport:
    def test_generates_all_roles(self, balanced_results: list[TaskResult]) -> None:
        multi = generate_multi_role_report(balanced_results)
        assert isinstance(multi, MultiRoleReport)
        assert len(multi.reports) == 5
        assert len(multi.ranking) == 5

    def test_ranking_sorted_descending(self, balanced_results: list[TaskResult]) -> None:
        multi = generate_multi_role_report(balanced_results)
        scores = [multi.reports[r].decision_score for r in multi.ranking]
        assert scores == sorted(scores, reverse=True)

    def test_subset_of_roles(self, balanced_results: list[TaskResult]) -> None:
        multi = generate_multi_role_report(balanced_results, roles=["ciso", "caio"])
        assert len(multi.reports) == 2
        assert "ciso" in multi.reports
        assert "caio" in multi.reports

    def test_model_detected(self, balanced_results: list[TaskResult]) -> None:
        multi = generate_multi_role_report(balanced_results)
        assert multi.model == "test/model"


class TestCategoryScores:
    def test_categories_present(self, balanced_results: list[TaskResult]) -> None:
        report = generate_role_report(balanced_results, "ciso")
        cat_names = [c.name for c in report.categories]
        assert "Detection" in cat_names

    def test_categories_sorted_by_weight(self, balanced_results: list[TaskResult]) -> None:
        report = generate_role_report(balanced_results, "ciso")
        weights = [c.total_weight for c in report.categories]
        assert weights == sorted(weights, reverse=True)

    def test_all_dimensions_in_categories(self, balanced_results: list[TaskResult]) -> None:
        report = generate_role_report(balanced_results, "ciso")
        categorized_ids = set()
        for cat in report.categories:
            for dim in cat.dimensions:
                categorized_ids.add(dim.id)
        report_ids = {d.id for d in report.dimensions}
        assert categorized_ids == report_ids


class TestJsonSerialization:
    def test_role_report_serializes(self, balanced_results: list[TaskResult]) -> None:
        report = generate_role_report(balanced_results, "ciso")
        json_str = report.model_dump_json()
        assert "decision_score" in json_str
        assert "grade" in json_str

    def test_multi_role_report_serializes(self, balanced_results: list[TaskResult]) -> None:
        multi = generate_multi_role_report(balanced_results)
        json_str = multi.model_dump_json()
        assert "ranking" in json_str
        assert "reports" in json_str
