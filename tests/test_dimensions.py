"""Tests for role dimension computation functions."""

from __future__ import annotations

import pytest

from seclens.roles.dimensions import (
    DIMENSION_FUNCTIONS,
    compute_all_dimensions,
    d01_mcc,
    d02_recall,
    d03_precision,
    d04_f1,
    d05_tnr,
    d06_cwe_accuracy,
    d07_mean_location_iou,
    d08_actionable_finding_rate,
    d09_cwe_coverage_breadth,
    d10_worst_category_floor,
    d11_cross_language_consistency,
    d12_worst_language_floor,
    d13_sast_fp_filtering,
    d14_evidence_completeness,
    d15_reasoning_presence,
    d16_reasoning_and_correct,
    d17_fp_reasoning,
    d18_cost_per_task,
    d19_cost_per_tp,
    d20_mcc_per_dollar,
    d21_wall_time_per_task,
    d22_throughput,
    d23_tokens_per_task,
    d24_tool_calls_per_task,
    d25_turns_per_task,
    d26_navigation_efficiency,
    d27_tool_effectiveness,
    d28_severity_weighted_recall,
    d29_critical_miss_rate,
    d30_severity_coverage,
    d31_parse_success_rate,
    d32_format_compliance,
    d33_error_rate,
    d34_autonomous_completion,
    d35_graceful_degradation,
)
from seclens.schemas.output import EvidenceOutput, ParsedOutput, ParseResult, ParseStatus
from seclens.schemas.scoring import RunMetadata, TaskMetrics, TaskResult, TaskScore


# ---------------------------------------------------------------------------
# Test fixture factory
# ---------------------------------------------------------------------------

def _meta() -> RunMetadata:
    return RunMetadata(
        model="test/model", prompt="base", layer=2, mode="guided",
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
    gt_cwe: str | None = "CWE-89",
    pred_vulnerable: bool | None = True,
    pred_cwe: str | None = "CWE-89",
    reasoning: str | None = None,
    evidence: EvidenceOutput | None = None,
    cost_usd: float = 0.1,
    total_tokens: int = 5000,
    tool_calls: int = 0,
    turns: int = 1,
    wall_time_s: float = 10.0,
    parse_status: str = "full",
    error: str | None = None,
) -> TaskResult:
    output = ParsedOutput(
        vulnerable=pred_vulnerable,
        cwe=pred_cwe,
        evidence=evidence,
        reasoning=reasoning,
    ) if parse_status != "failed" else None

    return TaskResult(
        task_id=f"test-{id(object())}",
        task_type=task_type,
        task_category=category,
        task_language=language,
        ground_truth_cwe=gt_cwe,
        task_severity=severity,
        run_metadata=_meta(),
        parse_result=ParseResult(
            status=ParseStatus(parse_status),
            output=output,
            raw_response="",
        ),
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


# ---------------------------------------------------------------------------
# Standard fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def balanced_results() -> list[TaskResult]:
    """10 positive (7 correct, 3 wrong) + 10 negative (8 correct, 2 wrong)."""
    results = []
    # 7 correct positives
    for i in range(7):
        results.append(make_result(verdict=1, category=f"Cat{i % 3}", language=["python", "java", "go"][i % 3]))
    # 3 wrong positives
    for i in range(3):
        results.append(make_result(verdict=0, cwe=0, location=0.0, pred_vulnerable=False, category=f"Cat{i % 3}"))
    # 8 correct negatives
    for i in range(8):
        results.append(make_result(task_type="post_patch", verdict=1, cwe=0, location=0.0, pred_vulnerable=False))
    # 2 wrong negatives (FP)
    for _ in range(2):
        results.append(make_result(task_type="post_patch", verdict=0, cwe=0, location=0.0, pred_vulnerable=True))
    return results


@pytest.fixture
def perfect_results() -> list[TaskResult]:
    """5 positive all correct + 5 negative all correct."""
    results = []
    for _ in range(5):
        results.append(make_result(verdict=1, cwe=1, location=1.0))
    for _ in range(5):
        results.append(make_result(task_type="post_patch", verdict=1, cwe=0, location=0.0, pred_vulnerable=False))
    return results


# ---------------------------------------------------------------------------
# Detection (D1-D8)
# ---------------------------------------------------------------------------

class TestDetection:
    def test_d01_mcc_perfect(self, perfect_results: list[TaskResult]) -> None:
        assert d01_mcc(perfect_results) == pytest.approx(1.0)

    def test_d01_mcc_empty(self) -> None:
        assert d01_mcc([]) == 0.0

    def test_d02_recall(self, balanced_results: list[TaskResult]) -> None:
        assert d02_recall(balanced_results) == pytest.approx(7 / 10)

    def test_d02_recall_empty(self) -> None:
        assert d02_recall([]) == 0.0

    def test_d03_precision(self, balanced_results: list[TaskResult]) -> None:
        # 7 TP, 2 FP (negative tasks predicted vulnerable)
        assert d03_precision(balanced_results) == pytest.approx(7 / 9)

    def test_d04_f1(self, balanced_results: list[TaskResult]) -> None:
        p = 7 / 9
        r = 7 / 10
        expected = 2 * p * r / (p + r)
        assert d04_f1(balanced_results) == pytest.approx(expected)

    def test_d05_tnr(self, balanced_results: list[TaskResult]) -> None:
        assert d05_tnr(balanced_results) == pytest.approx(8 / 10)

    def test_d06_cwe_accuracy(self, balanced_results: list[TaskResult]) -> None:
        # 7 correct positives, all have cwe=1
        assert d06_cwe_accuracy(balanced_results) == pytest.approx(1.0)

    def test_d07_mean_location_iou(self, balanced_results: list[TaskResult]) -> None:
        # 7 correct positives, all have location=0.8
        assert d07_mean_location_iou(balanced_results) == pytest.approx(0.8)

    def test_d08_actionable_finding_rate(self, balanced_results: list[TaskResult]) -> None:
        # 7 correct with cwe=1, location=0.8 > 0. Out of 10 positive.
        assert d08_actionable_finding_rate(balanced_results) == pytest.approx(7 / 10)


# ---------------------------------------------------------------------------
# Coverage (D9-D13)
# ---------------------------------------------------------------------------

class TestCoverage:
    def test_d09_coverage_breadth(self, balanced_results: list[TaskResult]) -> None:
        # 3 categories (Cat0, Cat1, Cat2), all have at least 1 correct
        assert d09_cwe_coverage_breadth(balanced_results) == pytest.approx(1.0)

    def test_d10_worst_category_floor(self) -> None:
        """Uses only positive tasks for per-category recall."""
        results = [
            make_result(verdict=1, category="A"),
            make_result(verdict=1, category="A"),
            make_result(verdict=1, category="A"),
            make_result(verdict=0, category="B"),
            make_result(verdict=0, category="B"),
            make_result(verdict=0, category="B"),
            # Negative tasks should be ignored
            make_result(task_type="post_patch", verdict=1, category="B"),
        ]
        assert d10_worst_category_floor(results) == pytest.approx(0.0)

    def test_d10_skips_small_categories(self) -> None:
        results = [
            make_result(verdict=1, category="A"),
            make_result(verdict=1, category="A"),
            make_result(verdict=1, category="A"),
            make_result(verdict=0, category="B"),  # Only 1 positive task — skipped
        ]
        assert d10_worst_category_floor(results) == pytest.approx(1.0)

    def test_d11_consistency_uniform(self) -> None:
        results = [
            make_result(verdict=1, language="python"),
            make_result(verdict=1, language="python"),
            make_result(verdict=1, language="java"),
            make_result(verdict=1, language="java"),
        ]
        assert d11_cross_language_consistency(results) == pytest.approx(1.0)

    def test_d12_worst_language_floor(self) -> None:
        results = [
            make_result(verdict=1, language="python"),
            make_result(verdict=1, language="python"),
            make_result(verdict=1, language="python"),
            make_result(verdict=0, language="java"),
            make_result(verdict=0, language="java"),
            make_result(verdict=0, language="java"),
        ]
        assert d12_worst_language_floor(results) == pytest.approx(0.0)

    def test_d13_sast_fp_filtering(self) -> None:
        results = [
            make_result(task_type="sast_false_positive", verdict=1, pred_vulnerable=False),
            make_result(task_type="sast_false_positive", verdict=0, pred_vulnerable=True),
        ]
        assert d13_sast_fp_filtering(results) == pytest.approx(0.5)

    def test_d13_no_sast_tasks(self) -> None:
        results = [make_result()]
        assert d13_sast_fp_filtering(results) == 0.0


# ---------------------------------------------------------------------------
# Reasoning (D14-D17)
# ---------------------------------------------------------------------------

class TestReasoning:
    def test_d14_evidence_completeness(self) -> None:
        evidence = EvidenceOutput(source="input", sink="execute", flow=["step1"])
        results = [
            make_result(evidence=evidence),
            make_result(),  # no evidence
        ]
        assert d14_evidence_completeness(results) == pytest.approx(0.5)

    def test_d15_reasoning_presence(self) -> None:
        results = [
            make_result(reasoning="This is vulnerable because..."),
            make_result(reasoning=None),
        ]
        assert d15_reasoning_presence(results) == pytest.approx(0.5)

    def test_d16_reasoning_and_correct(self) -> None:
        results = [
            make_result(verdict=1, reasoning="Correct reasoning"),
            make_result(verdict=0, reasoning="Wrong reasoning"),
            make_result(verdict=1, reasoning=None),  # no reasoning — excluded
        ]
        assert d16_reasoning_and_correct(results) == pytest.approx(0.5)

    def test_d17_fp_reasoning_no_fps(self) -> None:
        results = [make_result(task_type="post_patch", verdict=1, pred_vulnerable=False)]
        assert d17_fp_reasoning(results) == 1.0

    def test_d17_fp_reasoning_with_fps(self) -> None:
        results = [
            make_result(task_type="post_patch", verdict=0, pred_vulnerable=True, reasoning="I think..."),
            make_result(task_type="post_patch", verdict=0, pred_vulnerable=True, reasoning=None),
        ]
        assert d17_fp_reasoning(results) == pytest.approx(0.5)


# ---------------------------------------------------------------------------
# Efficiency (D18-D23)
# ---------------------------------------------------------------------------

class TestEfficiency:
    def test_d18_cost_per_task(self) -> None:
        results = [make_result(cost_usd=0.10), make_result(cost_usd=0.20)]
        assert d18_cost_per_task(results) == pytest.approx(0.15)

    def test_d19_cost_per_tp(self) -> None:
        results = [
            make_result(verdict=1, cost_usd=0.10),
            make_result(verdict=0, cost_usd=0.10),
        ]
        # total cost=0.20, 1 TP → 0.20/1 = 0.20
        assert d19_cost_per_tp(results) == pytest.approx(0.20)

    def test_d20_mcc_per_dollar(self, perfect_results: list[TaskResult]) -> None:
        result = d20_mcc_per_dollar(perfect_results)
        assert result > 0

    def test_d21_wall_time(self) -> None:
        results = [make_result(wall_time_s=5.0), make_result(wall_time_s=15.0)]
        assert d21_wall_time_per_task(results) == pytest.approx(10.0)

    def test_d22_throughput(self) -> None:
        results = [make_result(wall_time_s=30.0), make_result(wall_time_s=30.0)]
        # 2 tasks / (60s / 60) = 2 tasks/min
        assert d22_throughput(results) == pytest.approx(2.0)

    def test_d23_tokens_per_task(self) -> None:
        results = [make_result(total_tokens=3000), make_result(total_tokens=7000)]
        assert d23_tokens_per_task(results) == pytest.approx(5000.0)


# ---------------------------------------------------------------------------
# Tool-Use (D24-D27)
# ---------------------------------------------------------------------------

class TestToolUse:
    def test_d24_tool_calls_no_tools(self) -> None:
        results = [make_result(tool_calls=0)]
        assert d24_tool_calls_per_task(results) == 0.0

    def test_d24_tool_calls_with_tools(self) -> None:
        results = [make_result(tool_calls=3), make_result(tool_calls=7)]
        assert d24_tool_calls_per_task(results) == pytest.approx(5.0)

    def test_d25_turns_per_task(self) -> None:
        results = [make_result(turns=2), make_result(turns=4)]
        assert d25_turns_per_task(results) == pytest.approx(3.0)

    def test_d26_navigation_efficiency(self) -> None:
        results = [
            make_result(tool_calls=3),  # efficient
            make_result(tool_calls=5),  # efficient
            make_result(tool_calls=10),  # not efficient
        ]
        assert d26_navigation_efficiency(results) == pytest.approx(2 / 3)

    def test_d27_tool_effectiveness(self) -> None:
        results = [
            make_result(tool_calls=5, verdict=1),
            make_result(tool_calls=5, verdict=0),
        ]
        assert d27_tool_effectiveness(results) == pytest.approx(0.5)

    def test_d27_no_tool_tasks(self) -> None:
        results = [make_result(tool_calls=0)]
        assert d27_tool_effectiveness(results) == 0.0


# ---------------------------------------------------------------------------
# Severity (D28-D30)
# ---------------------------------------------------------------------------

class TestSeverity:
    def test_d28_severity_weighted_recall(self) -> None:
        results = [
            make_result(verdict=1, severity="critical"),  # 4 × 1
            make_result(verdict=0, severity="low"),        # 1 × 0
        ]
        assert d28_severity_weighted_recall(results) == pytest.approx(4 / 5)

    def test_d28_no_severity_data(self) -> None:
        results = [make_result(severity=None)]
        assert d28_severity_weighted_recall(results) == 0.0

    def test_d29_critical_miss_rate(self) -> None:
        results = [
            make_result(verdict=1, severity="critical"),
            make_result(verdict=0, severity="critical"),
            make_result(verdict=1, severity="low"),  # not critical — excluded
        ]
        assert d29_critical_miss_rate(results) == pytest.approx(0.5)

    def test_d29_no_critical_tasks(self) -> None:
        results = [make_result(severity="low")]
        assert d29_critical_miss_rate(results) == 0.0

    def test_d30_severity_coverage(self) -> None:
        results = [
            make_result(verdict=1, severity="critical"),
            make_result(verdict=0, severity="low"),
        ]
        # critical covered, low not → 1/2
        assert d30_severity_coverage(results) == pytest.approx(0.5)


# ---------------------------------------------------------------------------
# Robustness (D31-D35)
# ---------------------------------------------------------------------------

class TestRobustness:
    def test_d31_parse_success_rate(self) -> None:
        results = [
            make_result(parse_status="full"),
            make_result(parse_status="partial"),
        ]
        assert d31_parse_success_rate(results) == pytest.approx(0.5)

    def test_d32_format_compliance(self) -> None:
        results = [
            make_result(parse_status="full"),
            make_result(parse_status="partial"),
            make_result(parse_status="failed", verdict=0, cwe=0, location=0.0),
        ]
        # FULL among non-FAILED = 1/2
        assert d32_format_compliance(results) == pytest.approx(0.5)

    def test_d33_error_rate(self) -> None:
        results = [
            make_result(),
            make_result(error="API timeout"),
        ]
        assert d33_error_rate(results) == pytest.approx(0.5)

    def test_d34_autonomous_completion(self) -> None:
        results = [
            make_result(),  # clean
            make_result(error="crash"),  # error
            make_result(parse_status="failed", verdict=0, cwe=0, location=0.0),  # parse fail
        ]
        assert d34_autonomous_completion(results) == pytest.approx(1 / 3)

    def test_d35_graceful_degradation(self) -> None:
        # 4 tasks in Cat-A (common), 2 tasks in Cat-B (rare)
        results = [
            make_result(verdict=1, category="A"),
            make_result(verdict=1, category="A"),
            make_result(verdict=1, category="A"),
            make_result(verdict=1, category="A"),
            make_result(verdict=0, category="B"),
            make_result(verdict=0, category="B"),
        ]
        # common_acc=1.0, rare_acc=0.0 → 1 - |1.0 - 0.0| = 0.0
        assert d35_graceful_degradation(results) == pytest.approx(0.0)


# ---------------------------------------------------------------------------
# Registry and compute_all
# ---------------------------------------------------------------------------

class TestRegistry:
    def test_all_35_registered(self) -> None:
        assert len(DIMENSION_FUNCTIONS) == 35

    def test_all_ids_sequential(self) -> None:
        for i in range(1, 36):
            assert f"D{i}" in DIMENSION_FUNCTIONS

    def test_compute_all_returns_35(self, balanced_results: list[TaskResult]) -> None:
        result = compute_all_dimensions(balanced_results)
        assert len(result) == 35
        for dim_id, value in result.items():
            assert isinstance(value, float), f"{dim_id} returned {type(value)}"

    def test_compute_all_empty(self) -> None:
        result = compute_all_dimensions([])
        assert len(result) == 35
        # All should be 0.0 or default
        for dim_id, value in result.items():
            assert isinstance(value, float), f"{dim_id} returned {type(value)}"

    def test_compute_all_no_nan_inf(self, balanced_results: list[TaskResult]) -> None:
        import math
        result = compute_all_dimensions(balanced_results)
        for dim_id, value in result.items():
            assert not math.isnan(value), f"{dim_id} is NaN"
            assert not math.isinf(value), f"{dim_id} is Inf"

    def test_compute_all_no_nan_on_all_errors(self) -> None:
        import math
        results = [make_result(error="crash", verdict=0, cwe=0, location=0.0) for _ in range(5)]
        dims = compute_all_dimensions(results)
        for dim_id, value in dims.items():
            assert not math.isnan(value), f"{dim_id} is NaN on all-error input"
            assert not math.isinf(value), f"{dim_id} is Inf on all-error input"

    def test_compute_all_no_nan_on_single_task(self) -> None:
        import math
        dims = compute_all_dimensions([make_result()])
        for dim_id, value in dims.items():
            assert not math.isnan(value), f"{dim_id} is NaN on single task"

    def test_compute_all_no_nan_zero_wall_time(self) -> None:
        import math
        results = [make_result(wall_time_s=0.0) for _ in range(3)]
        dims = compute_all_dimensions(results)
        for dim_id, value in dims.items():
            assert not math.isnan(value), f"{dim_id} is NaN with zero wall time"
            assert not math.isinf(value), f"{dim_id} is Inf with zero wall time"


# ---------------------------------------------------------------------------
# Additional edge case tests (from code review)
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_d01_mcc_balanced(self, balanced_results: list[TaskResult]) -> None:
        """MCC with mixed results should be between -1 and 1."""
        mcc = d01_mcc(balanced_results)
        assert -1.0 <= mcc <= 1.0

    def test_d01_mcc_penalizes_errors(self) -> None:
        """Error tasks should count as FN/TN, penalizing the model."""
        # Without errors: 1 TP, 1 TN → MCC = 1.0
        clean = [
            make_result(verdict=1, pred_vulnerable=True),
            make_result(task_type="post_patch", verdict=1, pred_vulnerable=False),
        ]
        # With error on positive task: error counted as FN → MCC < 1.0
        with_error = [
            make_result(verdict=1, pred_vulnerable=True),
            make_result(task_type="post_patch", verdict=1, pred_vulnerable=False),
            make_result(error="crash", verdict=0, cwe=0, location=0.0),
        ]
        assert d01_mcc(clean) > d01_mcc(with_error)

    def test_d11_divergent_languages(self) -> None:
        """High variance in per-language accuracy → low consistency."""
        results = [
            make_result(verdict=1, language="python"),
            make_result(verdict=1, language="python"),
            make_result(verdict=1, language="python"),
            make_result(verdict=0, language="java"),
            make_result(verdict=0, language="java"),
            make_result(verdict=0, language="java"),
        ]
        consistency = d11_cross_language_consistency(results)
        assert consistency < 0.5  # High divergence → low score

    def test_d35_equal_category_counts(self) -> None:
        """When all categories have equal count, returns 0.5 (neutral)."""
        results = [
            make_result(verdict=1, category="A"),
            make_result(verdict=1, category="A"),
            make_result(verdict=0, category="B"),
            make_result(verdict=0, category="B"),
        ]
        # median=2, all categories have count=2 (<=median) → all "rare", common empty
        assert d35_graceful_degradation(results) == 0.5
