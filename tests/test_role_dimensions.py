"""Tests for all 250 role-specific dimensions across 5 roles."""

from __future__ import annotations

from seclens.schemas.output import EvidenceOutput, ParsedOutput, ParseResult, ParseStatus
from seclens.schemas.scoring import RunMetadata, TaskMetrics, TaskResult, TaskScore, TaskType


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _meta() -> RunMetadata:
    return RunMetadata(
        model="test/model", prompt="base", layer=2, mode="guided",
        timestamp="2026-03-09T12:00:00Z", seclens_version="0.1.0", seed=42,
    )


def _r(
    task_id: str = "t1",
    task_type: TaskType = TaskType.TRUE_POSITIVE,
    verdict: int = 1,
    cwe: int = 0,
    location: int = 0,
    error: str | None = None,
    cost: float = 0.01,
    tokens: int = 1000,
    tool_calls: int = 0,
    turns: int = 1,
    wall_time: float = 5.0,
    parse_status: ParseStatus = ParseStatus.FULL,
    language: str = "python",
    category: str = "sql_injection",
    vulnerable_pred: bool | None = None,
    reasoning: str | None = None,
    evidence: EvidenceOutput | None = None,
    cwe_pred: str | None = None,
) -> TaskResult:
    max_pts = 3 if task_type == TaskType.TRUE_POSITIVE else 1
    earned = verdict + cwe + location if task_type == TaskType.TRUE_POSITIVE else verdict

    if vulnerable_pred is None:
        vulnerable_pred = (verdict == 1) == (task_type == TaskType.TRUE_POSITIVE)

    output = None
    if parse_status != ParseStatus.FAILED and not error:
        output = ParsedOutput(
            vulnerable=vulnerable_pred,
            reasoning=reasoning,
            evidence=evidence,
            cwe=cwe_pred,
        )

    return TaskResult(
        task_id=task_id,
        task_type=task_type,
        task_category=category,
        task_language=language,
        run_metadata=_meta(),
        parse_result=ParseResult(
            status=parse_status,
            output=output,
            raw_response="",
        ),
        scores=TaskScore(verdict=verdict, cwe=cwe, location=location, earned=earned, max_task_points=max_pts),
        metrics=TaskMetrics(
            input_tokens=tokens,
            output_tokens=tokens // 2,
            total_tokens=tokens + tokens // 2,
            cost_usd=cost,
            tool_calls=tool_calls,
            turns=turns,
            wall_time_s=wall_time,
        ),
        error=error,
    )


def _perfect_results() -> list[TaskResult]:
    """All correct: 2 TP (perfect 3/3), 2 negatives (correct)."""
    ev = EvidenceOutput(source="user_input", sink="db.execute", flow=["param", "query"])
    return [
        _r("t1", TaskType.TRUE_POSITIVE, 1, 1, 1, category="sql_injection", language="python",
           reasoning="SQL injection via string concat", evidence=ev, cwe_pred="CWE-89",
           tool_calls=3, turns=2, wall_time=10.0, cost=0.02),
        _r("t2", TaskType.TRUE_POSITIVE, 1, 1, 1, category="xss", language="javascript",
           reasoning="Reflected XSS in template", evidence=ev, cwe_pred="CWE-79",
           tool_calls=2, turns=2, wall_time=8.0, cost=0.015),
        _r("t3", TaskType.POST_PATCH, 1, category="sql_injection", language="python",
           vulnerable_pred=False, reasoning="Patched with parameterized query"),
        _r("t4", TaskType.SAST_FALSE_POSITIVE, 1, category="xss", language="javascript",
           vulnerable_pred=False, reasoning="Not reachable"),
    ]


def _bad_results() -> list[TaskResult]:
    """All wrong verdicts."""
    return [
        _r("t1", TaskType.TRUE_POSITIVE, 0, 0, 0, vulnerable_pred=False),
        _r("t2", TaskType.TRUE_POSITIVE, 0, 0, 0, category="xss", language="javascript", vulnerable_pred=False),
        _r("t3", TaskType.POST_PATCH, 0, vulnerable_pred=True),
        _r("t4", TaskType.SAST_FALSE_POSITIVE, 0, vulnerable_pred=True),
    ]


def _mixed_results() -> list[TaskResult]:
    """Mix of correct/wrong, various categories and languages."""
    ev = EvidenceOutput(source="input", sink="output", flow=["step1"])
    return [
        _r("t1", TaskType.TRUE_POSITIVE, 1, 1, 1, category="sql_injection", language="python",
           reasoning="Found injection", evidence=ev, cwe_pred="CWE-89", tool_calls=3, turns=3),
        _r("t2", TaskType.TRUE_POSITIVE, 1, 0, 0, category="xss", language="javascript",
           reasoning="Found XSS", tool_calls=5, turns=4),
        _r("t3", TaskType.TRUE_POSITIVE, 0, 0, 0, category="auth_bypass", language="java",
           vulnerable_pred=False, tool_calls=2, turns=2),
        _r("t4", TaskType.POST_PATCH, 1, category="sql_injection", language="python",
           vulnerable_pred=False),
        _r("t5", TaskType.POST_PATCH, 0, category="xss", language="javascript",
           vulnerable_pred=True),
        _r("t6", TaskType.SAST_FALSE_POSITIVE, 1, category="auth_bypass", language="java",
           vulnerable_pred=False),
    ]


def _error_results() -> list[TaskResult]:
    """Results with errors and parse failures."""
    return [
        _r("t1", TaskType.TRUE_POSITIVE, 0, 0, 0, error="timeout"),
        _r("t2", TaskType.TRUE_POSITIVE, 0, 0, 0, parse_status=ParseStatus.FAILED),
        _r("t3", TaskType.POST_PATCH, 1, vulnerable_pred=False),
    ]


# ---------------------------------------------------------------------------
# Shared Dimensions (dimensions.py)
# ---------------------------------------------------------------------------

class TestSharedDimensions:
    def test_d01_tpr_perfect(self) -> None:
        from seclens.roles.dimensions import d01_true_positive_rate
        assert d01_true_positive_rate(_perfect_results()) == 1.0

    def test_d01_tpr_bad(self) -> None:
        from seclens.roles.dimensions import d01_true_positive_rate
        assert d01_true_positive_rate(_bad_results()) == 0.0

    def test_d01_tpr_empty(self) -> None:
        from seclens.roles.dimensions import d01_true_positive_rate
        assert d01_true_positive_rate([]) == 0.0

    def test_d02_tnr_perfect(self) -> None:
        from seclens.roles.dimensions import d02_true_negative_rate
        assert d02_true_negative_rate(_perfect_results()) == 1.0

    def test_d02_tnr_bad(self) -> None:
        from seclens.roles.dimensions import d02_true_negative_rate
        assert d02_true_negative_rate(_bad_results()) == 0.0

    def test_d03_fpr(self) -> None:
        from seclens.roles.dimensions import d03_false_positive_rate
        assert d03_false_positive_rate(_perfect_results()) == 0.0
        assert d03_false_positive_rate(_bad_results()) == 1.0

    def test_d04_fnr(self) -> None:
        from seclens.roles.dimensions import d04_false_negative_rate
        assert d04_false_negative_rate(_perfect_results()) == 0.0
        assert d04_false_negative_rate(_bad_results()) == 1.0

    def test_d05_mcc_perfect(self) -> None:
        from seclens.roles.dimensions import d05_verdict_mcc
        assert d05_verdict_mcc(_perfect_results()) == 1.0

    def test_d05_mcc_bad(self) -> None:
        from seclens.roles.dimensions import d05_verdict_mcc
        assert d05_verdict_mcc(_bad_results()) == -1.0

    def test_d06_cwe_accuracy(self) -> None:
        from seclens.roles.dimensions import d06_cwe_identification_accuracy
        assert d06_cwe_identification_accuracy(_perfect_results()) == 1.0
        assert d06_cwe_identification_accuracy(_bad_results()) == 0.0

    def test_d07_cwe_breadth(self) -> None:
        from seclens.roles.dimensions import d07_cwe_coverage_breadth
        assert d07_cwe_coverage_breadth(_perfect_results()) == 1.0

    def test_d08_rare_cwe(self) -> None:
        from seclens.roles.dimensions import d08_rare_cwe_performance
        # With 1 task per category, all are "rare"
        assert d08_rare_cwe_performance(_perfect_results()) == 1.0

    def test_d09_cross_lang(self) -> None:
        from seclens.roles.dimensions import d09_cross_language_cwe_consistency
        assert d09_cross_language_cwe_consistency(_perfect_results()) == 1.0

    def test_d10_confusion(self) -> None:
        from seclens.roles.dimensions import d10_cwe_confusion_rate
        # Perfect = no confusion
        assert d10_cwe_confusion_rate(_perfect_results()) == 1.0

    def test_d11_location(self) -> None:
        from seclens.roles.dimensions import d11_location_accuracy
        assert d11_location_accuracy(_perfect_results()) == 1.0

    def test_d12_file_accuracy(self) -> None:
        from seclens.roles.dimensions import d12_file_level_accuracy
        assert d12_file_level_accuracy(_perfect_results()) == 1.0

    def test_d13_mean_iou(self) -> None:
        from seclens.roles.dimensions import d13_mean_iou
        val = d13_mean_iou(_perfect_results())
        assert 0.0 <= val <= 1.0

    def test_d14_pinpoint(self) -> None:
        from seclens.roles.dimensions import d14_pinpoint_rate
        assert d14_pinpoint_rate(_perfect_results()) == 1.0

    def test_d15_over_scope(self) -> None:
        from seclens.roles.dimensions import d15_over_scope_rate
        val = d15_over_scope_rate(_perfect_results())
        assert 0.0 <= val <= 1.0

    def test_d16_evidence(self) -> None:
        from seclens.roles.dimensions import d16_evidence_completeness
        assert d16_evidence_completeness(_perfect_results()) > 0.0

    def test_d17_coherence(self) -> None:
        from seclens.roles.dimensions import d17_reasoning_coherence
        assert d17_reasoning_coherence(_perfect_results()) == 1.0

    def test_d18_explanation_length(self) -> None:
        from seclens.roles.dimensions import d18_explanation_length
        val = d18_explanation_length(_perfect_results())
        assert val > 0

    def test_d19_fp_reasoning(self) -> None:
        from seclens.roles.dimensions import d19_fp_reasoning_quality
        val = d19_fp_reasoning_quality(_perfect_results())
        assert 0.0 <= val <= 1.0

    def test_d20_calibration(self) -> None:
        from seclens.roles.dimensions import d20_confidence_calibration
        assert d20_confidence_calibration(_perfect_results()) == 1.0

    def test_d21_cost(self) -> None:
        from seclens.roles.dimensions import d21_cost_per_task
        val = d21_cost_per_task(_perfect_results())
        assert val > 0

    def test_d22_cost_per_tp(self) -> None:
        from seclens.roles.dimensions import d22_cost_per_correct_detection
        val = d22_cost_per_correct_detection(_perfect_results())
        assert val > 0

    def test_d23_tokens(self) -> None:
        from seclens.roles.dimensions import d23_tokens_per_task
        assert d23_tokens_per_task(_perfect_results()) > 0

    def test_d24_wall_time(self) -> None:
        from seclens.roles.dimensions import d24_wall_time_per_task
        assert d24_wall_time_per_task(_perfect_results()) > 0

    def test_d25_mcc_per_dollar(self) -> None:
        from seclens.roles.dimensions import d25_mcc_per_dollar
        assert d25_mcc_per_dollar(_perfect_results()) > 0

    def test_d26_tool_calls(self) -> None:
        from seclens.roles.dimensions import d26_tool_calls_per_task
        assert d26_tool_calls_per_task(_perfect_results()) > 0

    def test_d27_turns(self) -> None:
        from seclens.roles.dimensions import d27_turns_per_task
        assert d27_turns_per_task(_perfect_results()) >= 1.0

    def test_d28_search_eff(self) -> None:
        from seclens.roles.dimensions import d28_search_efficiency
        assert d28_search_efficiency(_perfect_results()) == 1.0

    def test_d29_convergence(self) -> None:
        from seclens.roles.dimensions import d29_navigation_convergence
        assert d29_navigation_convergence(_perfect_results()) > 0

    def test_d30_tool_error(self) -> None:
        from seclens.roles.dimensions import d30_tool_error_rate
        assert d30_tool_error_rate(_perfect_results()) == 1.0

    def test_d31_parse_success(self) -> None:
        from seclens.roles.dimensions import d31_parse_success_rate
        assert d31_parse_success_rate(_perfect_results()) == 1.0

    def test_d32_partial(self) -> None:
        from seclens.roles.dimensions import d32_partial_parse_rate
        assert d32_partial_parse_rate(_perfect_results()) == 1.0

    def test_d33_compliance(self) -> None:
        from seclens.roles.dimensions import d33_format_compliance
        assert d33_format_compliance(_perfect_results()) == 1.0

    def test_d34_stability(self) -> None:
        from seclens.roles.dimensions import d34_cross_run_stability
        assert d34_cross_run_stability(_perfect_results()) == 0.5

    def test_d35_error_rate(self) -> None:
        from seclens.roles.dimensions import d35_error_crash_rate
        assert d35_error_crash_rate(_perfect_results()) == 1.0
        assert d35_error_crash_rate(_error_results()) < 1.0

    def test_d36_critical_miss(self) -> None:
        from seclens.roles.dimensions import d36_critical_vuln_miss_rate
        assert d36_critical_vuln_miss_rate(_perfect_results()) == 1.0

    def test_d37_severity_recall(self) -> None:
        from seclens.roles.dimensions import d37_severity_weighted_recall
        val = d37_severity_weighted_recall(_perfect_results())
        assert 0.0 <= val <= 1.0

    def test_d38_worst_cat(self) -> None:
        from seclens.roles.dimensions import d38_worst_category_performance
        assert d38_worst_category_performance(_perfect_results()) == 1.0

    def test_d39_lang_gap(self) -> None:
        from seclens.roles.dimensions import d39_language_coverage_gap
        assert d39_language_coverage_gap(_perfect_results()) == 1.0

    def test_d40_overconfident(self) -> None:
        from seclens.roles.dimensions import d40_overconfident_miss_rate
        assert d40_overconfident_miss_rate(_perfect_results()) == 1.0

    def test_d41_throughput(self) -> None:
        from seclens.roles.dimensions import d41_throughput
        assert d41_throughput(_perfect_results()) > 0

    def test_d42_cost_scale(self) -> None:
        from seclens.roles.dimensions import d42_cost_at_scale
        assert d42_cost_at_scale(_perfect_results()) > 0

    def test_d43_l1l2(self) -> None:
        from seclens.roles.dimensions import d43_l1_vs_l2_delta
        assert d43_l1_vs_l2_delta([]) == 0.5

    def test_d44_prompt_sens(self) -> None:
        from seclens.roles.dimensions import d44_prompt_sensitivity
        assert d44_prompt_sensitivity([]) == 0.5

    def test_d45_resume(self) -> None:
        from seclens.roles.dimensions import d45_resume_reliability
        assert d45_resume_reliability([]) == 0.5

    def test_d46_zero_guidance(self) -> None:
        from seclens.roles.dimensions import d46_zero_guidance_accuracy
        assert d46_zero_guidance_accuracy(_perfect_results()) == 1.0

    def test_d47_self_correction(self) -> None:
        from seclens.roles.dimensions import d47_self_correction_rate
        assert d47_self_correction_rate(_perfect_results()) == 1.0

    def test_d48_unsupervised(self) -> None:
        from seclens.roles.dimensions import d48_unsupervised_decision_quality
        assert d48_unsupervised_decision_quality(_perfect_results()) == 1.0

    def test_d49_degradation(self) -> None:
        from seclens.roles.dimensions import d49_graceful_degradation
        val = d49_graceful_degradation(_perfect_results())
        assert 0.0 <= val <= 1.0

    def test_d50_autonomous(self) -> None:
        from seclens.roles.dimensions import d50_autonomous_completion_rate
        assert d50_autonomous_completion_rate(_perfect_results()) == 1.0

    def test_compute_all(self) -> None:
        from seclens.roles.dimensions import compute_all_dimensions
        dims = compute_all_dimensions(_perfect_results())
        assert len(dims) == 50
        for dim_id in range(1, 51):
            assert dim_id in dims

    def test_compute_all_empty(self) -> None:
        from seclens.roles.dimensions import compute_all_dimensions
        dims = compute_all_dimensions([])
        assert len(dims) == 50


# ---------------------------------------------------------------------------
# CISO Dimensions
# ---------------------------------------------------------------------------

class TestCISODimensions:
    def test_all_50_callable(self) -> None:
        from seclens.roles.dimensions_ciso import CISO_DIMENSIONS
        assert len(CISO_DIMENSIONS) == 50
        for dim_id, (name, fn) in CISO_DIMENSIONS.items():
            assert 1 <= dim_id <= 50
            assert callable(fn)
            assert len(name) > 0

    def test_perfect_results_high_scores(self) -> None:
        from seclens.roles.dimensions_ciso import CISO_DIMENSIONS
        results = _perfect_results()
        for dim_id, (name, fn) in CISO_DIMENSIONS.items():
            val = fn(results)
            assert isinstance(val, (int, float)), f"c{dim_id:02d} {name} returned {type(val)}"

    def test_bad_results_low_scores(self) -> None:
        from seclens.roles.dimensions_ciso import CISO_DIMENSIONS
        results = _bad_results()
        for dim_id, (name, fn) in CISO_DIMENSIONS.items():
            val = fn(results)
            assert isinstance(val, (int, float)), f"c{dim_id:02d} {name} returned {type(val)}"

    def test_empty_results(self) -> None:
        from seclens.roles.dimensions_ciso import CISO_DIMENSIONS
        for dim_id, (name, fn) in CISO_DIMENSIONS.items():
            val = fn([])
            assert isinstance(val, (int, float)), f"c{dim_id:02d} {name} failed on empty"

    def test_key_dimensions_perfect(self) -> None:
        from seclens.roles.dimensions_ciso import (
            c01_overall_detection_reliability,
            c05_balanced_accuracy,
            c06_mcc_overall,
            c14_operational_error_rate,
            c20_positive_predictive_value,
        )
        results = _perfect_results()
        assert c01_overall_detection_reliability(results) == 1.0
        assert c05_balanced_accuracy(results) == 1.0
        assert c06_mcc_overall(results) == 1.0
        assert c14_operational_error_rate(results) == 1.0
        assert c20_positive_predictive_value(results) == 1.0

    def test_key_dimensions_bad(self) -> None:
        from seclens.roles.dimensions_ciso import (
            c01_overall_detection_reliability,
            c04_false_alarm_rate,
        )
        results = _bad_results()
        assert c01_overall_detection_reliability(results) == 0.0
        assert c04_false_alarm_rate(results) == 0.0

    def test_category_specific(self) -> None:
        from seclens.roles.dimensions_ciso import (
            c31_injection_detection_rate,
            c32_xss_detection_rate,
            c44_patch_verification_accuracy,
            c45_sast_fp_rejection,
        )
        results = _perfect_results()
        assert c31_injection_detection_rate(results) == 1.0
        assert c32_xss_detection_rate(results) == 1.0
        assert c44_patch_verification_accuracy(results) == 1.0
        assert c45_sast_fp_rejection(results) == 1.0

    def test_composite_scores(self) -> None:
        from seclens.roles.dimensions_ciso import (
            c37_incident_response_utility,
            c46_board_reportable_score,
            c50_overall_ciso_confidence,
        )
        results = _perfect_results()
        assert 0.0 <= c37_incident_response_utility(results) <= 1.0
        assert 0.0 <= c46_board_reportable_score(results) <= 1.0
        assert 0.0 <= c50_overall_ciso_confidence(results) <= 1.0


# ---------------------------------------------------------------------------
# CAIO Dimensions
# ---------------------------------------------------------------------------

class TestCAIODimensions:
    def test_all_50_callable(self) -> None:
        from seclens.roles.dimensions_caio import CAIO_DIMENSIONS
        assert len(CAIO_DIMENSIONS) == 50
        for dim_id, (name, fn) in CAIO_DIMENSIONS.items():
            assert 1 <= dim_id <= 50
            assert callable(fn)

    def test_perfect_results(self) -> None:
        from seclens.roles.dimensions_caio import CAIO_DIMENSIONS
        results = _perfect_results()
        for dim_id, (name, fn) in CAIO_DIMENSIONS.items():
            val = fn(results)
            assert isinstance(val, (int, float)), f"a{dim_id:02d} {name} returned {type(val)}"

    def test_empty_results(self) -> None:
        from seclens.roles.dimensions_caio import CAIO_DIMENSIONS
        for dim_id, (name, fn) in CAIO_DIMENSIONS.items():
            val = fn([])
            assert isinstance(val, (int, float)), f"a{dim_id:02d} {name} failed on empty"

    def test_key_dimensions(self) -> None:
        from seclens.roles.dimensions_caio import (
            a01_capability_score,
            a02_full_finding_rate,
            a06_f1_score,
            a09_autonomous_completion,
            a37_new_capability_index,
            a50_overall_caio_score,
        )
        results = _perfect_results()
        assert a01_capability_score(results) == 1.0
        assert a02_full_finding_rate(results) == 1.0
        assert 0.0 < a06_f1_score(results) <= 1.0
        assert a09_autonomous_completion(results) == 1.0
        assert 0.0 < a37_new_capability_index(results) <= 1.0
        assert 0.0 < a50_overall_caio_score(results) <= 1.0

    def test_cost_dimensions(self) -> None:
        from seclens.roles.dimensions_caio import (
            a16_cost_per_task,
            a21_cost_at_scale_1k,
            a22_cost_at_scale_10k,
        )
        results = _perfect_results()
        cpt = a16_cost_per_task(results)
        assert cpt > 0
        assert a21_cost_at_scale_1k(results) == cpt * 1000
        assert a22_cost_at_scale_10k(results) == cpt * 10000

    def test_tool_uplift(self) -> None:
        from seclens.roles.dimensions_caio import a08_tool_use_uplift
        # Mixed: some with tools, some without
        results = _perfect_results()
        val = a08_tool_use_uplift(results)
        assert 0.0 <= val <= 1.0


# ---------------------------------------------------------------------------
# Security Researcher Dimensions
# ---------------------------------------------------------------------------

class TestResearcherDimensions:
    def test_all_50_callable(self) -> None:
        from seclens.roles.dimensions_researcher import RESEARCHER_DIMENSIONS
        assert len(RESEARCHER_DIMENSIONS) == 50
        for dim_id, (name, fn) in RESEARCHER_DIMENSIONS.items():
            assert 1 <= dim_id <= 50
            assert callable(fn)

    def test_perfect_results(self) -> None:
        from seclens.roles.dimensions_researcher import RESEARCHER_DIMENSIONS
        results = _perfect_results()
        for dim_id, (name, fn) in RESEARCHER_DIMENSIONS.items():
            val = fn(results)
            assert isinstance(val, (int, float)), f"r{dim_id:02d} {name} returned {type(val)}"

    def test_empty_results(self) -> None:
        from seclens.roles.dimensions_researcher import RESEARCHER_DIMENSIONS
        for dim_id, (name, fn) in RESEARCHER_DIMENSIONS.items():
            val = fn([])
            assert isinstance(val, (int, float)), f"r{dim_id:02d} {name} failed on empty"

    def test_cwe_dimensions(self) -> None:
        from seclens.roles.dimensions_researcher import (
            r05_cwe_exact_match_rate,
            r06_cwe_coverage_breadth,
            r07_rare_cwe_detection,
            r10_cwe_confusion_quality,
        )
        results = _perfect_results()
        assert r05_cwe_exact_match_rate(results) == 1.0
        assert r06_cwe_coverage_breadth(results) == 1.0
        assert r07_rare_cwe_detection(results) == 1.0
        assert r10_cwe_confusion_quality(results) == 1.0

    def test_evidence_dimensions(self) -> None:
        from seclens.roles.dimensions_researcher import (
            r16_evidence_completeness,
            r17_source_identification_rate,
            r18_sink_identification_rate,
            r19_data_flow_completeness,
        )
        results = _perfect_results()
        assert r16_evidence_completeness(results) > 0
        assert r17_source_identification_rate(results) == 1.0
        assert r18_sink_identification_rate(results) == 1.0
        assert r19_data_flow_completeness(results) == 1.0

    def test_language_dimensions(self) -> None:
        from seclens.roles.dimensions_researcher import (
            r32_python_accuracy,
            r33_javascript_accuracy,
            r37_language_gap,
        )
        results = _perfect_results()
        assert r32_python_accuracy(results) == 1.0
        assert r33_javascript_accuracy(results) == 1.0
        assert r37_language_gap(results) == 1.0

    def test_composite(self) -> None:
        from seclens.roles.dimensions_researcher import (
            r49_research_utility_index,
            r50_overall_researcher_score,
        )
        results = _perfect_results()
        assert 0.0 < r49_research_utility_index(results) <= 1.0
        assert 0.0 < r50_overall_researcher_score(results) <= 1.0


# ---------------------------------------------------------------------------
# Head of Engineering Dimensions
# ---------------------------------------------------------------------------

class TestEngineerDimensions:
    def test_all_50_callable(self) -> None:
        from seclens.roles.dimensions_engineer import ENGINEER_DIMENSIONS
        assert len(ENGINEER_DIMENSIONS) == 50
        for dim_id, (name, fn) in ENGINEER_DIMENSIONS.items():
            assert 1 <= dim_id <= 50
            assert callable(fn)

    def test_perfect_results(self) -> None:
        from seclens.roles.dimensions_engineer import ENGINEER_DIMENSIONS
        results = _perfect_results()
        for dim_id, (name, fn) in ENGINEER_DIMENSIONS.items():
            val = fn(results)
            assert isinstance(val, (int, float)), f"e{dim_id:02d} {name} returned {type(val)}"

    def test_empty_results(self) -> None:
        from seclens.roles.dimensions_engineer import ENGINEER_DIMENSIONS
        for dim_id, (name, fn) in ENGINEER_DIMENSIONS.items():
            val = fn([])
            assert isinstance(val, (int, float)), f"e{dim_id:02d} {name} failed on empty"

    def test_fp_and_precision(self) -> None:
        from seclens.roles.dimensions_engineer import (
            e01_false_positive_rate,
            e02_precision,
            e09_actionable_finding_rate,
        )
        results = _perfect_results()
        assert e01_false_positive_rate(results) == 1.0
        assert e02_precision(results) == 1.0
        assert e09_actionable_finding_rate(results) == 1.0

    def test_sla_and_speed(self) -> None:
        from seclens.roles.dimensions_engineer import (
            e13_sla_30s_compliance,
            e14_sla_60s_compliance,
            e15_throughput,
        )
        results = _perfect_results()
        assert e13_sla_30s_compliance(results) == 1.0  # All < 30s
        assert e14_sla_60s_compliance(results) == 1.0
        assert e15_throughput(results) > 0

    def test_reliability(self) -> None:
        from seclens.roles.dimensions_engineer import (
            e21_parse_success_rate,
            e23_error_rate,
            e25_overall_reliability,
        )
        results = _perfect_results()
        assert e21_parse_success_rate(results) == 1.0
        assert e23_error_rate(results) == 1.0
        assert e25_overall_reliability(results) == 1.0

    def test_cost_projections(self) -> None:
        from seclens.roles.dimensions_engineer import (
            e16_cost_per_task,
            e17_cost_per_pr,
            e18_monthly_projected_cost,
        )
        results = _perfect_results()
        cpt = e16_cost_per_task(results)
        assert e17_cost_per_pr(results) == cpt * 5
        assert e18_monthly_projected_cost(results) == cpt * 5000

    def test_composite(self) -> None:
        from seclens.roles.dimensions_engineer import (
            e45_ci_gate_readiness,
            e49_team_adoption_readiness,
            e50_overall_engineering_score,
        )
        results = _perfect_results()
        assert 0.0 < e45_ci_gate_readiness(results) <= 1.0
        assert 0.0 < e49_team_adoption_readiness(results) <= 1.0
        assert 0.0 < e50_overall_engineering_score(results) <= 1.0


# ---------------------------------------------------------------------------
# AI Actor Dimensions
# ---------------------------------------------------------------------------

class TestAIActorDimensions:
    def test_all_50_callable(self) -> None:
        from seclens.roles.dimensions_ai_actor import AI_ACTOR_DIMENSIONS
        assert len(AI_ACTOR_DIMENSIONS) == 50
        for dim_id, (name, fn) in AI_ACTOR_DIMENSIONS.items():
            assert 1 <= dim_id <= 50
            assert callable(fn)

    def test_perfect_results(self) -> None:
        from seclens.roles.dimensions_ai_actor import AI_ACTOR_DIMENSIONS
        results = _perfect_results()
        for dim_id, (name, fn) in AI_ACTOR_DIMENSIONS.items():
            val = fn(results)
            assert isinstance(val, (int, float)), f"ai{dim_id:02d} {name} returned {type(val)}"

    def test_empty_results(self) -> None:
        from seclens.roles.dimensions_ai_actor import AI_ACTOR_DIMENSIONS
        for dim_id, (name, fn) in AI_ACTOR_DIMENSIONS.items():
            val = fn([])
            assert isinstance(val, (int, float)), f"ai{dim_id:02d} {name} failed on empty"

    def test_autonomy_core(self) -> None:
        from seclens.roles.dimensions_ai_actor import (
            ai01_autonomous_completion_rate,
            ai02_unsupervised_verdict_accuracy,
            ai04_full_finding_rate,
            ai17_error_recovery,
        )
        results = _perfect_results()
        assert ai01_autonomous_completion_rate(results) == 1.0
        assert ai02_unsupervised_verdict_accuracy(results) == 1.0
        assert ai04_full_finding_rate(results) == 1.0
        assert ai17_error_recovery(results) == 1.0

    def test_tool_use(self) -> None:
        from seclens.roles.dimensions_ai_actor import (
            ai09_tool_adoption_rate,
            ai10_tool_use_effectiveness,
            ai11_tool_efficiency,
        )
        results = _perfect_results()
        assert ai09_tool_adoption_rate(results) > 0  # Some tasks have tools
        assert ai10_tool_use_effectiveness(results) == 1.0
        assert ai11_tool_efficiency(results) == 1.0

    def test_multi_turn(self) -> None:
        from seclens.roles.dimensions_ai_actor import (
            ai06_multi_turn_engagement,
            ai07_multi_turn_success,
        )
        results = _perfect_results()
        assert ai06_multi_turn_engagement(results) > 0
        assert ai07_multi_turn_success(results) == 1.0

    def test_composite(self) -> None:
        from seclens.roles.dimensions_ai_actor import (
            ai44_autonomous_triage_quality,
            ai47_human_replacement_index,
            ai50_overall_autonomy_score,
        )
        results = _perfect_results()
        assert 0.0 < ai44_autonomous_triage_quality(results) <= 1.0
        assert 0.0 < ai47_human_replacement_index(results) <= 1.0
        assert 0.0 < ai50_overall_autonomy_score(results) <= 1.0


# ---------------------------------------------------------------------------
# Weight Profiles
# ---------------------------------------------------------------------------

class TestWeightProfiles:
    def test_load_all_profiles(self) -> None:
        from seclens.roles.weights import list_available_roles, load_weight_profile
        roles = list_available_roles()
        assert len(roles) == 5
        for role in roles:
            weights = load_weight_profile(role)
            assert len(weights) == 50

    def test_weights_sum_to_100(self) -> None:
        from seclens.roles.weights import list_available_roles, load_weight_profile
        for role in list_available_roles():
            weights = load_weight_profile(role)
            total = sum(weights.values())
            assert abs(total - 100.0) < 0.1, f"{role} weights sum to {total}"

    def test_all_dimension_ids_present(self) -> None:
        from seclens.roles.weights import list_available_roles, load_weight_profile
        for role in list_available_roles():
            weights = load_weight_profile(role)
            for dim_id in range(1, 51):
                assert dim_id in weights, f"{role} missing dimension {dim_id}"

    def test_invalid_role(self) -> None:
        from seclens.roles.weights import load_weight_profile
        import pytest
        with pytest.raises(ValueError, match="Unknown role"):
            load_weight_profile("nonexistent")

    def test_normalize_ratio(self) -> None:
        from seclens.roles.weights import normalize_dimension
        assert normalize_dimension(1, 0.8) == 0.8  # Ratio passthrough
        assert normalize_dimension(1, 1.5) == 1.0  # Capped

    def test_normalize_mcc(self) -> None:
        from seclens.roles.weights import normalize_dimension
        assert normalize_dimension(5, 1.0) == 1.0
        assert normalize_dimension(5, -1.0) == 0.0
        assert normalize_dimension(5, 0.0) == 0.5

    def test_normalize_lower_is_better(self) -> None:
        from seclens.roles.weights import normalize_dimension
        # Cost per task: $0 = 1.0, $0.50 = 0.0
        assert normalize_dimension(21, 0.0) == 1.0
        assert normalize_dimension(21, 0.50) == 0.0
        assert normalize_dimension(21, 0.25) == 0.5

    def test_compute_decision_score(self) -> None:
        from seclens.roles.weights import compute_decision_score
        raw = {i: 1.0 for i in range(1, 51)}  # All perfect ratios
        weights = {i: 2.0 for i in range(1, 51)}  # Equal weights = 100
        score, details = compute_decision_score(raw, weights)
        assert len(details) == 50
        # MCC dimension (5) gets special handling, others pass through
        assert score > 0

    def test_score_to_grade(self) -> None:
        from seclens.roles.weights import score_to_grade
        assert score_to_grade(95) == "A"
        assert score_to_grade(85) == "B"
        assert score_to_grade(75) == "C"
        assert score_to_grade(65) == "D"
        assert score_to_grade(50) == "F"


# ---------------------------------------------------------------------------
# Scorer Integration
# ---------------------------------------------------------------------------

class TestRoleScorer:
    def test_generate_role_report(self) -> None:
        from seclens.roles.scorer import generate_role_report
        report = generate_role_report(_perfect_results(), "ciso")
        assert report.role == "ciso"
        assert 0 <= report.decision_score <= 100
        assert report.grade in ("A", "B", "C", "D", "F")
        assert len(report.dimensions) == 50
        assert len(report.categories) > 0
        assert report.total_tasks == 4
        assert len(report.recommendation) > 0

    def test_generate_all_roles(self) -> None:
        from seclens.roles.scorer import generate_role_report
        from seclens.roles.weights import list_available_roles
        results = _perfect_results()
        for role in list_available_roles():
            report = generate_role_report(results, role)
            assert report.role == role
            assert 0 <= report.decision_score <= 100

    def test_generate_multi_role_report(self) -> None:
        from seclens.roles.scorer import generate_multi_role_report
        multi = generate_multi_role_report(_perfect_results())
        assert len(multi.reports) == 5
        assert len(multi.ranking) == 5
        assert multi.model == "test/model"
        # Ranking should be descending by score
        scores = [multi.reports[r].decision_score for r in multi.ranking]
        assert scores == sorted(scores, reverse=True)

    def test_report_with_bad_results(self) -> None:
        from seclens.roles.scorer import generate_role_report
        report = generate_role_report(_bad_results(), "ciso")
        assert report.decision_score < 50  # Bad results → low score
        assert report.grade in ("D", "F")

    def test_report_with_mixed_results(self) -> None:
        from seclens.roles.scorer import generate_role_report
        report = generate_role_report(_mixed_results(), "caio")
        assert 0 <= report.decision_score <= 100

    def test_report_categories_cover_all_dimensions(self) -> None:
        from seclens.roles.scorer import generate_role_report
        report = generate_role_report(_perfect_results(), "security_researcher")
        total_dims = sum(len(cat.dimensions) for cat in report.categories)
        assert total_dims == 50

    def test_dimension_scores_weighted_correctly(self) -> None:
        from seclens.roles.scorer import generate_role_report
        report = generate_role_report(_perfect_results(), "ciso")
        total_weighted = sum(d.weighted_score for d in report.dimensions)
        assert abs(total_weighted - report.decision_score) < 0.01


# ---------------------------------------------------------------------------
# Dimension Registry Validation
# ---------------------------------------------------------------------------

class TestDimensionRegistries:
    def test_each_role_has_50(self) -> None:
        from seclens.roles.dimensions_ai_actor import AI_ACTOR_DIMENSIONS
        from seclens.roles.dimensions_caio import CAIO_DIMENSIONS
        from seclens.roles.dimensions_ciso import CISO_DIMENSIONS
        from seclens.roles.dimensions_engineer import ENGINEER_DIMENSIONS
        from seclens.roles.dimensions_researcher import RESEARCHER_DIMENSIONS

        for name, registry in [
            ("CISO", CISO_DIMENSIONS),
            ("CAIO", CAIO_DIMENSIONS),
            ("Researcher", RESEARCHER_DIMENSIONS),
            ("Engineer", ENGINEER_DIMENSIONS),
            ("AI Actor", AI_ACTOR_DIMENSIONS),
        ]:
            assert len(registry) == 50, f"{name} has {len(registry)} dimensions"
            assert set(registry.keys()) == set(range(1, 51)), f"{name} IDs not 1-50"

    def test_no_duplicate_names_within_role(self) -> None:
        from seclens.roles.dimensions_ai_actor import AI_ACTOR_DIMENSIONS
        from seclens.roles.dimensions_caio import CAIO_DIMENSIONS
        from seclens.roles.dimensions_ciso import CISO_DIMENSIONS
        from seclens.roles.dimensions_engineer import ENGINEER_DIMENSIONS
        from seclens.roles.dimensions_researcher import RESEARCHER_DIMENSIONS

        for name, registry in [
            ("CISO", CISO_DIMENSIONS),
            ("CAIO", CAIO_DIMENSIONS),
            ("Researcher", RESEARCHER_DIMENSIONS),
            ("Engineer", ENGINEER_DIMENSIONS),
            ("AI Actor", AI_ACTOR_DIMENSIONS),
        ]:
            names = [n for _, (n, _) in registry.items()]
            assert len(names) == len(set(names)), f"{name} has duplicate dimension names"

    def test_total_250_dimensions(self) -> None:
        from seclens.roles.dimensions_ai_actor import AI_ACTOR_DIMENSIONS
        from seclens.roles.dimensions_caio import CAIO_DIMENSIONS
        from seclens.roles.dimensions_ciso import CISO_DIMENSIONS
        from seclens.roles.dimensions_engineer import ENGINEER_DIMENSIONS
        from seclens.roles.dimensions_researcher import RESEARCHER_DIMENSIONS

        total = (len(CISO_DIMENSIONS) + len(CAIO_DIMENSIONS) +
                 len(RESEARCHER_DIMENSIONS) + len(ENGINEER_DIMENSIONS) +
                 len(AI_ACTOR_DIMENSIONS))
        assert total == 250
