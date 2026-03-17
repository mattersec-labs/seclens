"""Compute all 50 role-specific benchmark dimensions from TaskResult data.

Each function takes a list[TaskResult] and returns a raw float value.
Normalization to 0-1 is handled by the scorer module.
"""

from __future__ import annotations

import math
import statistics
from collections import defaultdict

from seclens.schemas.output import ParseStatus
from seclens.schemas.scoring import TaskResult, TaskType

# ---------------------------------------------------------------------------
# CWE severity tiers — used for risk-weighted scoring
# ---------------------------------------------------------------------------

CRITICAL_CWES = {
    "CWE-78", "CWE-79", "CWE-89", "CWE-94", "CWE-502",
    "CWE-77", "CWE-90", "CWE-91", "CWE-917", "CWE-1321",
    "CWE-287", "CWE-306", "CWE-862", "CWE-863", "CWE-918",
}

SEVERITY_TIERS: dict[str, float] = {}
for _cwe in CRITICAL_CWES:
    SEVERITY_TIERS[_cwe] = 3.0
# Default tier weight = 1.0 for unlisted CWEs

DIMENSION_NAMES: dict[int, str] = {
    1: "True Positive Rate",
    2: "True Negative Rate",
    3: "False Positive Rate",
    4: "False Negative Rate",
    5: "Verdict MCC",
    6: "CWE Identification Accuracy",
    7: "CWE Coverage Breadth",
    8: "Rare CWE Performance",
    9: "Cross-Language CWE Consistency",
    10: "CWE Confusion Rate",
    11: "Location Accuracy",
    12: "File-Level Accuracy",
    13: "Mean IoU Score",
    14: "Pinpoint Rate",
    15: "Over-Scope Rate",
    16: "Evidence Completeness",
    17: "Reasoning Coherence",
    18: "Explanation Length",
    19: "FP Reasoning Quality",
    20: "Confidence Calibration",
    21: "Cost Per Task",
    22: "Cost Per Correct Detection",
    23: "Tokens Per Task",
    24: "Wall Time Per Task",
    25: "MCC Per Dollar",
    26: "Tool Calls Per Task",
    27: "Turns Per Task",
    28: "Search Efficiency",
    29: "Navigation Convergence",
    30: "Tool Error Rate",
    31: "Parse Success Rate",
    32: "Partial Parse Rate",
    33: "Output Format Compliance",
    34: "Cross-Run Stability",
    35: "Error/Crash Rate",
    36: "Critical Vuln Miss Rate",
    37: "Severity-Weighted Recall",
    38: "Worst-Category Performance",
    39: "Language Coverage Gap",
    40: "Overconfident Miss Rate",
    41: "Throughput",
    42: "Cost at Scale",
    43: "L1 vs L2 Delta",
    44: "Prompt Sensitivity",
    45: "Resume Reliability",
    46: "Zero-Guidance Accuracy",
    47: "Self-Correction Rate",
    48: "Unsupervised Decision Quality",
    49: "Graceful Degradation",
    50: "Autonomous Completion Rate",
}

DIMENSION_CATEGORIES: dict[int, str] = {}
_CAT_RANGES = {
    "Detection Accuracy": range(1, 6),
    "Vulnerability Knowledge": range(6, 11),
    "Localization Precision": range(11, 16),
    "Reasoning Quality": range(16, 21),
    "Operational Efficiency": range(21, 26),
    "Tool-Use & Navigation": range(26, 31),
    "Robustness & Consistency": range(31, 36),
    "Risk Profile": range(36, 41),
    "Scalability & Integration": range(41, 46),
    "Autonomy Readiness": range(46, 51),
}
for _cat, _rng in _CAT_RANGES.items():
    for _i in _rng:
        DIMENSION_CATEGORIES[_i] = _cat


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _positive_results(results: list[TaskResult]) -> list[TaskResult]:
    return [r for r in results if r.task_type == TaskType.TRUE_POSITIVE]


def _negative_results(results: list[TaskResult]) -> list[TaskResult]:
    return [r for r in results if r.task_type != TaskType.TRUE_POSITIVE]


def _non_error_results(results: list[TaskResult]) -> list[TaskResult]:
    return [r for r in results if r.error is None]


def _verdict_pred(r: TaskResult) -> bool | None:
    if r.parse_result.output is not None:
        return r.parse_result.output.vulnerable
    return None


def _safe_div(num: float, den: float, default: float = 0.0) -> float:
    return num / den if den > 0 else default


# ---------------------------------------------------------------------------
# Category A: Detection Accuracy (1-5)
# ---------------------------------------------------------------------------

def d01_true_positive_rate(results: list[TaskResult]) -> float:
    """Recall: % of real vulns correctly flagged."""
    pos = _positive_results(results)
    if not pos:
        return 0.0
    correct = sum(1 for r in pos if r.scores.verdict == 1)
    return correct / len(pos)


def d02_true_negative_rate(results: list[TaskResult]) -> float:
    """Specificity: % of clean code correctly cleared."""
    neg = _negative_results(results)
    if not neg:
        return 0.0
    correct = sum(1 for r in neg if r.scores.verdict == 1)
    return correct / len(neg)


def d03_false_positive_rate(results: list[TaskResult]) -> float:
    """% of clean code incorrectly flagged as vulnerable."""
    return 1.0 - d02_true_negative_rate(results)


def d04_false_negative_rate(results: list[TaskResult]) -> float:
    """% of real vulns missed."""
    return 1.0 - d01_true_positive_rate(results)


def d05_verdict_mcc(results: list[TaskResult]) -> float:
    """Matthews Correlation Coefficient for verdicts."""
    tp = fp = tn = fn = 0
    for r in _non_error_results(results):
        pred = _verdict_pred(r)
        is_positive = r.task_type == TaskType.TRUE_POSITIVE
        if pred is None:
            if is_positive:
                fn += 1
            else:
                tn += 1
            continue
        if pred and is_positive:
            tp += 1
        elif pred and not is_positive:
            fp += 1
        elif not pred and not is_positive:
            tn += 1
        else:
            fn += 1

    num = tp * tn - fp * fn
    den = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    return num / den if den > 0 else 0.0


# ---------------------------------------------------------------------------
# Category B: Vulnerability Knowledge (6-10)
# ---------------------------------------------------------------------------

def d06_cwe_identification_accuracy(results: list[TaskResult]) -> float:
    """CWE accuracy among detected vulns (TP verdict correct)."""
    correct_pos = [r for r in _positive_results(results) if r.scores.verdict == 1]
    if not correct_pos:
        return 0.0
    return sum(r.scores.cwe for r in correct_pos) / len(correct_pos)


def d07_cwe_coverage_breadth(results: list[TaskResult]) -> float:
    """% of distinct CWE categories where model scores > 0."""
    pos = _positive_results(results)
    if not pos:
        return 0.0
    cwe_groups: dict[str, list[int]] = defaultdict(list)
    for r in pos:
        gt_cwe = r.task_category or "unknown"
        cwe_groups[gt_cwe].append(r.scores.cwe)

    if not cwe_groups:
        return 0.0
    covered = sum(1 for scores in cwe_groups.values() if any(s > 0 for s in scores))
    return covered / len(cwe_groups)


def d08_rare_cwe_performance(results: list[TaskResult]) -> float:
    """Accuracy on CWEs with <= 3 tasks in dataset."""
    pos = _positive_results(results)
    cwe_counts: dict[str, int] = defaultdict(int)
    for r in pos:
        cwe_counts[r.task_category or "unknown"] += 1

    rare_cwes = {c for c, n in cwe_counts.items() if n <= 3}
    rare_tasks = [r for r in pos if (r.task_category or "unknown") in rare_cwes]

    if not rare_tasks:
        return 0.0
    return sum(r.scores.cwe for r in rare_tasks) / len(rare_tasks)


def d09_cross_language_cwe_consistency(results: list[TaskResult]) -> float:
    """1 - StdDev of CWE accuracy across languages (lower variance = better)."""
    pos = [r for r in _positive_results(results) if r.scores.verdict == 1]
    if not pos:
        return 0.0

    lang_scores: dict[str, list[int]] = defaultdict(list)
    for r in pos:
        lang_scores[r.task_language].append(r.scores.cwe)

    if len(lang_scores) < 2:
        return 1.0

    lang_accs = [sum(s) / len(s) for s in lang_scores.values() if s]
    if len(lang_accs) < 2:
        return 1.0

    return max(0.0, 1.0 - statistics.stdev(lang_accs))


def d10_cwe_confusion_rate(results: list[TaskResult]) -> float:
    """% of CWE predictions that are wrong (lower is better, return 1 - rate)."""
    pos = [r for r in _positive_results(results) if r.scores.verdict == 1]
    if not pos:
        return 0.0

    has_cwe_pred = [
        r for r in pos
        if r.parse_result.output is not None and r.parse_result.output.cwe is not None
    ]
    if not has_cwe_pred:
        return 0.0

    wrong = sum(1 for r in has_cwe_pred if r.scores.cwe == 0)
    return 1.0 - (wrong / len(has_cwe_pred))


# ---------------------------------------------------------------------------
# Category C: Localization Precision (11-15)
# ---------------------------------------------------------------------------

def d11_location_accuracy(results: list[TaskResult]) -> float:
    """% of positive tasks with correct location (IoU > 0.5)."""
    pos = [r for r in _positive_results(results) if r.scores.verdict == 1]
    if not pos:
        return 0.0
    return sum(r.scores.location for r in pos) / len(pos)


def d12_file_level_accuracy(results: list[TaskResult]) -> float:
    """% where predicted file matches ground truth file."""
    pos = [r for r in _positive_results(results) if r.scores.verdict == 1]
    if not pos:
        return 0.0

    correct = 0
    for r in pos:
        pred_loc = r.parse_result.output.location if r.parse_result.output else None
        # We can't access GT location directly from TaskResult, so we approximate:
        # if location score is 1, file must be correct. If 0 but output has location,
        # check would need GT. Use location score as lower bound.
        if pred_loc is not None:
            # Location score 1 implies file match + IoU > 0.5
            # For file-only, we count any task where location was attempted
            # This is a conservative approximation from available data
            correct += 1 if r.scores.location == 1 else 0
    return _safe_div(correct, len(pos))


def d13_mean_iou(results: list[TaskResult]) -> float:
    """Average IoU across correctly-detected vulns.

    Note: Exact IoU values are not stored in TaskResult.
    We approximate: location=1 means IoU > 0.5 (use 0.75 estimate),
    location=0 with attempt means IoU < 0.5 (use 0.1 estimate).
    """
    pos = [r for r in _positive_results(results) if r.scores.verdict == 1]
    if not pos:
        return 0.0

    iou_estimates = []
    for r in pos:
        if r.scores.location == 1:
            iou_estimates.append(0.75)  # Conservative estimate for IoU > 0.5
        else:
            iou_estimates.append(0.1)

    return sum(iou_estimates) / len(iou_estimates) if iou_estimates else 0.0


def d14_pinpoint_rate(results: list[TaskResult]) -> float:
    """% of vulns localized with high precision.

    Approximated as location accuracy (IoU > 0.5 is our only threshold).
    With raw IoU data, this would use IoU > 0.9.
    """
    return d11_location_accuracy(results)


def d15_over_scope_rate(results: list[TaskResult]) -> float:
    """% where model flags far more lines than necessary (lower is better).

    Returns 1 - over_scope_rate so higher = better.
    Approximated: tasks with location=0 but parse succeeded are likely over-scoped.
    """
    pos = [r for r in _positive_results(results) if r.scores.verdict == 1]
    if not pos:
        return 1.0

    has_loc_attempt = [
        r for r in pos
        if r.parse_result.output is not None and r.parse_result.output.location is not None
    ]
    if not has_loc_attempt:
        return 1.0

    over_scoped = sum(1 for r in has_loc_attempt if r.scores.location == 0)
    return 1.0 - _safe_div(over_scoped, len(has_loc_attempt))


# ---------------------------------------------------------------------------
# Category D: Reasoning Quality (16-20)
# ---------------------------------------------------------------------------

def d16_evidence_completeness(results: list[TaskResult]) -> float:
    """% of responses with source, sink, and flow in evidence."""
    valid = _non_error_results(results)
    if not valid:
        return 0.0

    complete = 0
    for r in valid:
        out = r.parse_result.output
        if out and out.evidence:
            has_source = out.evidence.source is not None
            has_sink = out.evidence.sink is not None
            has_flow = len(out.evidence.flow) > 0
            if has_source and has_sink and has_flow:
                complete += 1
    return complete / len(valid)


def d17_reasoning_coherence(results: list[TaskResult]) -> float:
    """% of responses where reasoning exists and verdict was correct."""
    valid = _non_error_results(results)
    if not valid:
        return 0.0

    coherent = 0
    total = 0
    for r in valid:
        out = r.parse_result.output
        if out and out.reasoning:
            total += 1
            if r.scores.verdict == 1:
                coherent += 1

    return _safe_div(coherent, total)


def d18_explanation_length(results: list[TaskResult]) -> float:
    """Median reasoning length in characters (raw value, normalized later)."""
    lengths = []
    for r in _non_error_results(results):
        out = r.parse_result.output
        if out and out.reasoning:
            lengths.append(len(out.reasoning))

    if not lengths:
        return 0.0
    return float(statistics.median(lengths))


def d19_fp_reasoning_quality(results: list[TaskResult]) -> float:
    """Among false positives, % with reasoning present."""
    neg = _negative_results(results)
    fps = [
        r for r in neg
        if r.parse_result.output is not None and r.parse_result.output.vulnerable is True
    ]
    if not fps:
        return 1.0  # No FPs = perfect

    with_reasoning = sum(
        1 for r in fps if r.parse_result.output.reasoning is not None
    )
    return with_reasoning / len(fps)


def d20_confidence_calibration(results: list[TaskResult]) -> float:
    """Proxy: parse FULL + correct verdict = calibrated confidence.

    True calibration requires a confidence score field.
    """
    valid = _non_error_results(results)
    if not valid:
        return 0.0

    calibrated = sum(
        1 for r in valid
        if r.parse_result.status == ParseStatus.FULL and r.scores.verdict == 1
    )
    return calibrated / len(valid)


# ---------------------------------------------------------------------------
# Category E: Operational Efficiency (21-25)
# ---------------------------------------------------------------------------

def d21_cost_per_task(results: list[TaskResult]) -> float:
    """Average USD per task (raw value, lower is better)."""
    valid = _non_error_results(results)
    if not valid:
        return 0.0
    return sum(r.metrics.cost_usd for r in valid) / len(valid)


def d22_cost_per_correct_detection(results: list[TaskResult]) -> float:
    """USD per true positive found (raw, lower is better)."""
    valid = _non_error_results(results)
    total_cost = sum(r.metrics.cost_usd for r in valid)
    tp_count = sum(
        1 for r in valid
        if r.task_type == TaskType.TRUE_POSITIVE and r.scores.verdict == 1
    )
    return _safe_div(total_cost, tp_count, default=float("inf"))


def d23_tokens_per_task(results: list[TaskResult]) -> float:
    """Average total tokens per task (raw, lower is better)."""
    valid = _non_error_results(results)
    if not valid:
        return 0.0
    return sum(r.metrics.total_tokens for r in valid) / len(valid)


def d24_wall_time_per_task(results: list[TaskResult]) -> float:
    """Average wall clock seconds per task (raw, lower is better)."""
    valid = _non_error_results(results)
    if not valid:
        return 0.0
    return sum(r.metrics.wall_time_s for r in valid) / len(valid)


def d25_mcc_per_dollar(results: list[TaskResult]) -> float:
    """MCC / total cost (higher is better)."""
    mcc = d05_verdict_mcc(results)
    total_cost = sum(r.metrics.cost_usd for r in _non_error_results(results))
    return _safe_div(mcc, total_cost)


# ---------------------------------------------------------------------------
# Category F: Tool-Use & Navigation (26-30)
# ---------------------------------------------------------------------------

def d26_tool_calls_per_task(results: list[TaskResult]) -> float:
    """Average tool calls per task (raw)."""
    valid = _non_error_results(results)
    if not valid:
        return 0.0
    return sum(r.metrics.tool_calls for r in valid) / len(valid)


def d27_turns_per_task(results: list[TaskResult]) -> float:
    """Average conversation turns per task (raw)."""
    valid = _non_error_results(results)
    if not valid:
        return 0.0
    return sum(r.metrics.turns for r in valid) / len(valid)


def d28_search_efficiency(results: list[TaskResult]) -> float:
    """% of tasks with <= 5 tool calls (efficient navigation)."""
    valid = [r for r in _non_error_results(results) if r.metrics.tool_calls > 0]
    if not valid:
        return 1.0  # L1 has no tools = perfectly efficient
    efficient = sum(1 for r in valid if r.metrics.tool_calls <= 5)
    return efficient / len(valid)


def d29_navigation_convergence(results: list[TaskResult]) -> float:
    """Median turns to reach answer (lower is better, raw value)."""
    valid = _non_error_results(results)
    if not valid:
        return 0.0
    turns = [r.metrics.turns for r in valid]
    return float(statistics.median(turns))


def d30_tool_error_rate(results: list[TaskResult]) -> float:
    """% of tasks with tool use but zero earned score (inverted: 1 - rate)."""
    valid = [r for r in _non_error_results(results) if r.metrics.tool_calls > 0]
    if not valid:
        return 1.0
    wasted = sum(1 for r in valid if r.scores.earned == 0)
    return 1.0 - (wasted / len(valid))


# ---------------------------------------------------------------------------
# Category G: Robustness & Consistency (31-35)
# ---------------------------------------------------------------------------

def d31_parse_success_rate(results: list[TaskResult]) -> float:
    """% of tasks with FULL parse status."""
    valid = _non_error_results(results)
    if not valid:
        return 0.0
    full = sum(1 for r in valid if r.parse_result.status == ParseStatus.FULL)
    return full / len(valid)


def d32_partial_parse_rate(results: list[TaskResult]) -> float:
    """% with PARTIAL parse (lower is better, return 1 - rate)."""
    valid = _non_error_results(results)
    if not valid:
        return 1.0
    partial = sum(1 for r in valid if r.parse_result.status == ParseStatus.PARTIAL)
    return 1.0 - (partial / len(valid))


def d33_format_compliance(results: list[TaskResult]) -> float:
    """% FULL out of non-FAILED parses."""
    valid = _non_error_results(results)
    non_failed = [r for r in valid if r.parse_result.status != ParseStatus.FAILED]
    if not non_failed:
        return 0.0
    full = sum(1 for r in non_failed if r.parse_result.status == ParseStatus.FULL)
    return full / len(non_failed)


def d34_cross_run_stability(results: list[TaskResult]) -> float:
    """Placeholder — requires multi-seed runs. Returns 0.5 (unknown)."""
    return 0.5


def d35_error_crash_rate(results: list[TaskResult]) -> float:
    """% of tasks without errors (inverted: higher = better)."""
    if not results:
        return 0.0
    errors = sum(1 for r in results if r.error is not None)
    return 1.0 - (errors / len(results))


# ---------------------------------------------------------------------------
# Category H: Risk Profile (36-40)
# ---------------------------------------------------------------------------

def d36_critical_vuln_miss_rate(results: list[TaskResult]) -> float:
    """1 - FN rate on critical CWEs (higher = better)."""
    critical_pos = [
        r for r in _positive_results(results)
        if (r.task_category or "").upper().replace("-", "").replace("_", "") in
        {c.upper().replace("-", "").replace("_", "") for c in CRITICAL_CWES}
        or any(
            c.lower() in (r.task_category or "").lower()
            for c in ["injection", "rce", "auth", "xss", "deserialization"]
        )
    ]
    if not critical_pos:
        # Fallback: treat all positive tasks as potentially critical
        critical_pos = _positive_results(results)
    if not critical_pos:
        return 0.0
    detected = sum(1 for r in critical_pos if r.scores.verdict == 1)
    return detected / len(critical_pos)


def d37_severity_weighted_recall(results: list[TaskResult]) -> float:
    """Recall weighted by CWE severity tier."""
    pos = _positive_results(results)
    if not pos:
        return 0.0

    weighted_correct = 0.0
    total_weight = 0.0
    for r in pos:
        cat = (r.task_category or "").upper()
        severity = SEVERITY_TIERS.get(cat, 1.0)
        total_weight += severity
        if r.scores.verdict == 1:
            weighted_correct += severity

    return _safe_div(weighted_correct, total_weight)


def d38_worst_category_performance(results: list[TaskResult]) -> float:
    """Min verdict accuracy across CWE categories."""
    groups: dict[str, list[int]] = defaultdict(list)
    for r in _non_error_results(results):
        cat = r.task_category or "uncategorized"
        groups[cat].append(r.scores.verdict)

    if not groups:
        return 0.0

    accuracies = [sum(v) / len(v) for v in groups.values() if v]
    return min(accuracies) if accuracies else 0.0


def d39_language_coverage_gap(results: list[TaskResult]) -> float:
    """1 - (max accuracy - min accuracy across languages). Lower gap = better."""
    groups: dict[str, list[int]] = defaultdict(list)
    for r in _non_error_results(results):
        groups[r.task_language].append(r.scores.verdict)

    if len(groups) < 2:
        return 1.0

    accuracies = [sum(v) / len(v) for v in groups.values() if v]
    if len(accuracies) < 2:
        return 1.0

    gap = max(accuracies) - min(accuracies)
    return max(0.0, 1.0 - gap)


def d40_overconfident_miss_rate(results: list[TaskResult]) -> float:
    """1 - (FN rate among FULL-parsed responses). Higher = better."""
    pos = _positive_results(results)
    full_parsed = [r for r in pos if r.parse_result.status == ParseStatus.FULL]
    if not full_parsed:
        return 0.0
    misses = sum(1 for r in full_parsed if r.scores.verdict == 0)
    return 1.0 - (misses / len(full_parsed))


# ---------------------------------------------------------------------------
# Category I: Scalability & Integration (41-45)
# ---------------------------------------------------------------------------

def d41_throughput(results: list[TaskResult]) -> float:
    """Tasks per minute (raw value)."""
    valid = _non_error_results(results)
    if not valid:
        return 0.0
    total_wall = sum(r.metrics.wall_time_s for r in valid)
    if total_wall <= 0:
        return 0.0
    return len(valid) / (total_wall / 60.0)


def d42_cost_at_scale(results: list[TaskResult]) -> float:
    """Projected cost for 1000 tasks (raw USD, lower is better)."""
    avg = d21_cost_per_task(results)
    return avg * 1000


def d43_l1_vs_l2_delta(results: list[TaskResult]) -> float:
    """Placeholder — requires paired L1/L2 runs. Returns 0.5 (unknown)."""
    return 0.5


def d44_prompt_sensitivity(results: list[TaskResult]) -> float:
    """Placeholder — requires multi-preset runs. Returns 0.5 (unknown)."""
    return 0.5


def d45_resume_reliability(results: list[TaskResult]) -> float:
    """Placeholder — requires resume comparison. Returns 0.5 (unknown)."""
    return 0.5


# ---------------------------------------------------------------------------
# Category J: Autonomy Readiness (46-50)
# ---------------------------------------------------------------------------

def d46_zero_guidance_accuracy(results: list[TaskResult]) -> float:
    """Placeholder — requires minimal preset run. Uses current accuracy as proxy."""
    valid = _non_error_results(results)
    if not valid:
        return 0.0
    return sum(r.scores.verdict for r in valid) / len(valid)


def d47_self_correction_rate(results: list[TaskResult]) -> float:
    """% of multi-turn tasks (turns > 1) with correct verdict."""
    multi_turn = [r for r in _non_error_results(results) if r.metrics.turns > 1]
    if not multi_turn:
        return 0.0
    correct = sum(1 for r in multi_turn if r.scores.verdict == 1)
    return correct / len(multi_turn)


def d48_unsupervised_decision_quality(results: list[TaskResult]) -> float:
    """Placeholder — requires open mode run. Uses verdict accuracy as proxy."""
    return d46_zero_guidance_accuracy(results)


def d49_graceful_degradation(results: list[TaskResult]) -> float:
    """1 - delta between common CWE accuracy and rare CWE accuracy."""
    pos = _positive_results(results)
    if not pos:
        return 0.0

    cwe_counts: dict[str, int] = defaultdict(int)
    for r in pos:
        cwe_counts[r.task_category or "unknown"] += 1

    common = [r for r in pos if cwe_counts.get(r.task_category or "unknown", 0) > 3]
    rare = [r for r in pos if cwe_counts.get(r.task_category or "unknown", 0) <= 3]

    if not common or not rare:
        return 0.5

    common_acc = sum(r.scores.verdict for r in common) / len(common)
    rare_acc = sum(r.scores.verdict for r in rare) / len(rare)

    return max(0.0, 1.0 - abs(common_acc - rare_acc))


def d50_autonomous_completion_rate(results: list[TaskResult]) -> float:
    """% of tasks completed without error or parse failure."""
    if not results:
        return 0.0
    clean = sum(
        1 for r in results
        if r.error is None and r.parse_result.status != ParseStatus.FAILED
    )
    return clean / len(results)


# ---------------------------------------------------------------------------
# Registry: dimension_id -> computation function
# ---------------------------------------------------------------------------

DIMENSION_FUNCTIONS: dict[int, callable] = {
    1: d01_true_positive_rate,
    2: d02_true_negative_rate,
    3: d03_false_positive_rate,
    4: d04_false_negative_rate,
    5: d05_verdict_mcc,
    6: d06_cwe_identification_accuracy,
    7: d07_cwe_coverage_breadth,
    8: d08_rare_cwe_performance,
    9: d09_cross_language_cwe_consistency,
    10: d10_cwe_confusion_rate,
    11: d11_location_accuracy,
    12: d12_file_level_accuracy,
    13: d13_mean_iou,
    14: d14_pinpoint_rate,
    15: d15_over_scope_rate,
    16: d16_evidence_completeness,
    17: d17_reasoning_coherence,
    18: d18_explanation_length,
    19: d19_fp_reasoning_quality,
    20: d20_confidence_calibration,
    21: d21_cost_per_task,
    22: d22_cost_per_correct_detection,
    23: d23_tokens_per_task,
    24: d24_wall_time_per_task,
    25: d25_mcc_per_dollar,
    26: d26_tool_calls_per_task,
    27: d27_turns_per_task,
    28: d28_search_efficiency,
    29: d29_navigation_convergence,
    30: d30_tool_error_rate,
    31: d31_parse_success_rate,
    32: d32_partial_parse_rate,
    33: d33_format_compliance,
    34: d34_cross_run_stability,
    35: d35_error_crash_rate,
    36: d36_critical_vuln_miss_rate,
    37: d37_severity_weighted_recall,
    38: d38_worst_category_performance,
    39: d39_language_coverage_gap,
    40: d40_overconfident_miss_rate,
    41: d41_throughput,
    42: d42_cost_at_scale,
    43: d43_l1_vs_l2_delta,
    44: d44_prompt_sensitivity,
    45: d45_resume_reliability,
    46: d46_zero_guidance_accuracy,
    47: d47_self_correction_rate,
    48: d48_unsupervised_decision_quality,
    49: d49_graceful_degradation,
    50: d50_autonomous_completion_rate,
}


def compute_all_dimensions(results: list[TaskResult]) -> dict[int, float]:
    """Compute all 50 dimension raw values from results."""
    return {dim_id: fn(results) for dim_id, fn in DIMENSION_FUNCTIONS.items()}
