"""35 shared dimension computation functions for role-based scoring.

Each function takes a list[TaskResult] and returns a raw float value.
Normalization to 0-1 is handled by the normalization module.
"""

from __future__ import annotations

import math
import statistics
from collections import defaultdict
from collections.abc import Callable

from seclens.schemas.output import ParseStatus
from seclens.schemas.scoring import TaskResult
from seclens.schemas.task import TaskType

# ---------------------------------------------------------------------------
# Severity weight mapping (from advisory-reported severity)
# ---------------------------------------------------------------------------

SEVERITY_WEIGHTS: dict[str, float] = {
    "critical": 4.0,
    "high": 3.0,
    "medium": 2.0,
    "low": 1.0,
}

# ---------------------------------------------------------------------------
# Dimension metadata
# ---------------------------------------------------------------------------

DIMENSION_NAMES: dict[str, str] = {
    "D1": "MCC",
    "D2": "Recall",
    "D3": "Precision",
    "D4": "F1",
    "D5": "True Negative Rate",
    "D6": "CWE Accuracy",
    "D7": "Mean Location IoU",
    "D8": "Actionable Finding Rate",
    "D9": "CWE Coverage Breadth",
    "D10": "Worst Category Floor",
    "D11": "Cross-Language Consistency",
    "D12": "Worst Language Floor",
    "D13": "SAST FP Filtering",
    "D14": "Evidence Completeness",
    "D15": "Reasoning Presence",
    "D16": "Reasoning + Correct Verdict",
    "D17": "FP Reasoning Quality",
    "D18": "Cost per Task",
    "D19": "Cost per True Positive",
    "D20": "MCC per Dollar",
    "D21": "Wall Time per Task",
    "D22": "Throughput",
    "D23": "Tokens per Task",
    "D24": "Tool Calls per Task",
    "D25": "Turns per Task",
    "D26": "Navigation Efficiency",
    "D27": "Tool Effectiveness",
    "D28": "Severity-Weighted Recall",
    "D29": "Critical Miss Rate",
    "D30": "Severity Coverage",
    "D31": "Parse Success Rate",
    "D32": "Format Compliance",
    "D33": "Error Rate",
    "D34": "Autonomous Completion Rate",
    "D35": "Graceful Degradation",
}

DIMENSION_CATEGORIES: dict[str, str] = {
    **{f"D{i}": "Detection" for i in range(1, 9)},
    **{f"D{i}": "Coverage & Consistency" for i in range(9, 14)},
    **{f"D{i}": "Reasoning & Evidence" for i in range(14, 18)},
    **{f"D{i}": "Operational Efficiency" for i in range(18, 24)},
    **{f"D{i}": "Tool-Use & Navigation" for i in range(24, 28)},
    **{f"D{i}": "Risk & Severity" for i in range(28, 31)},
    **{f"D{i}": "Robustness" for i in range(31, 36)},
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _positive(results: list[TaskResult]) -> list[TaskResult]:
    return [r for r in results if r.task_type == TaskType.TRUE_POSITIVE]


def _negative(results: list[TaskResult]) -> list[TaskResult]:
    return [r for r in results if r.task_type != TaskType.TRUE_POSITIVE]


def _non_error(results: list[TaskResult]) -> list[TaskResult]:
    return [r for r in results if r.error is None]


def _confusion_matrix(results: list[TaskResult]) -> tuple[int, int, int, int]:
    """Return (TP, FP, TN, FN) from results.

    Error tasks are included with prediction treated as None, which counts
    as FN (positive) or TN (negative) — penalizing crashes appropriately.
    """
    tp = fp = tn = fn = 0
    for r in results:
        if r.error is not None or r.parse_result.output is None:
            pred = None
        else:
            pred = r.parse_result.output.vulnerable
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
    return tp, fp, tn, fn


def _safe_div(numerator: float, denominator: float, default: float = 0.0) -> float:
    return numerator / denominator if denominator > 0 else default


# ---------------------------------------------------------------------------
# Category A: Detection (D1-D8)
# ---------------------------------------------------------------------------

def d01_mcc(results: list[TaskResult]) -> float:
    """Matthews Correlation Coefficient."""
    tp, fp, tn, fn = _confusion_matrix(results)
    numerator = tp * tn - fp * fn
    denominator = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    return _safe_div(numerator, denominator)


def d02_recall(results: list[TaskResult]) -> float:
    """True Positive Rate."""
    pos = _positive(results)
    if not pos:
        return 0.0
    return sum(1 for r in pos if r.scores.verdict == 1) / len(pos)


def d03_precision(results: list[TaskResult]) -> float:
    """Positive Predictive Value."""
    tp, fp, _, _ = _confusion_matrix(results)
    return _safe_div(tp, tp + fp)


def d04_f1(results: list[TaskResult]) -> float:
    """Harmonic mean of Precision and Recall."""
    p = d03_precision(results)
    r = d02_recall(results)
    return _safe_div(2 * p * r, p + r)


def d05_tnr(results: list[TaskResult]) -> float:
    """True Negative Rate (Specificity)."""
    neg = _negative(results)
    if not neg:
        return 0.0
    return sum(1 for r in neg if r.scores.verdict == 1) / len(neg)


def d06_cwe_accuracy(results: list[TaskResult]) -> float:
    """CWE accuracy among correctly-detected positive tasks."""
    correct_pos = [r for r in _positive(results) if r.scores.verdict == 1]
    if not correct_pos:
        return 0.0
    return sum(r.scores.cwe for r in correct_pos) / len(correct_pos)


def d07_mean_location_iou(results: list[TaskResult]) -> float:
    """Mean continuous IoU among correctly-detected positive tasks."""
    correct_pos = [r for r in _positive(results) if r.scores.verdict == 1]
    if not correct_pos:
        return 0.0
    return sum(r.scores.location for r in correct_pos) / len(correct_pos)


def d08_actionable_finding_rate(results: list[TaskResult]) -> float:
    """Fraction of positive tasks with verdict + CWE + location all correct."""
    pos = _positive(results)
    if not pos:
        return 0.0
    actionable = sum(
        1 for r in pos
        if r.scores.verdict == 1 and r.scores.cwe == 1 and r.scores.location > 0
    )
    return actionable / len(pos)


# ---------------------------------------------------------------------------
# Category B: Coverage & Consistency (D9-D13)
# ---------------------------------------------------------------------------

def d09_cwe_coverage_breadth(results: list[TaskResult]) -> float:
    """Fraction of CWE categories with at least one correct detection."""
    pos = _positive(results)
    if not pos:
        return 0.0
    groups: dict[str, list[int]] = defaultdict(list)
    for r in pos:
        groups[r.task_category or "uncategorized"].append(r.scores.verdict)
    if not groups:
        return 0.0
    covered = sum(1 for verdicts in groups.values() if any(v == 1 for v in verdicts))
    return covered / len(groups)


def d10_worst_category_floor(results: list[TaskResult]) -> float:
    """Minimum recall across CWE categories (min 3 positive tasks per category)."""
    groups: dict[str, list[int]] = defaultdict(list)
    for r in _positive(results):
        groups[r.task_category or "uncategorized"].append(r.scores.verdict)
    accuracies = [sum(v) / len(v) for v in groups.values() if len(v) >= 3]
    return min(accuracies) if accuracies else 0.0


def d11_cross_language_consistency(results: list[TaskResult]) -> float:
    """1 - StdDev of per-language verdict accuracy."""
    groups: dict[str, list[int]] = defaultdict(list)
    for r in _non_error(results):
        groups[r.task_language].append(r.scores.verdict)
    if len(groups) < 2:
        return 1.0
    accuracies = [sum(v) / len(v) for v in groups.values() if v]
    if len(accuracies) < 2:
        return 1.0
    return max(0.0, 1.0 - statistics.stdev(accuracies))


def d12_worst_language_floor(results: list[TaskResult]) -> float:
    """Minimum verdict accuracy across languages (min 3 tasks per language)."""
    groups: dict[str, list[int]] = defaultdict(list)
    for r in _non_error(results):
        groups[r.task_language].append(r.scores.verdict)
    accuracies = [sum(v) / len(v) for v in groups.values() if len(v) >= 3]
    return min(accuracies) if accuracies else 0.0


def d13_sast_fp_filtering(results: list[TaskResult]) -> float:
    """Verdict accuracy on sast_false_positive tasks."""
    sast_fp = [r for r in results if r.task_type == TaskType.SAST_FALSE_POSITIVE]
    if not sast_fp:
        return 0.0
    return sum(1 for r in sast_fp if r.scores.verdict == 1) / len(sast_fp)


# ---------------------------------------------------------------------------
# Category C: Reasoning & Evidence (D14-D17)
# ---------------------------------------------------------------------------

def d14_evidence_completeness(results: list[TaskResult]) -> float:
    """Fraction of responses with source + sink + flow evidence."""
    valid = _non_error(results)
    if not valid:
        return 0.0
    complete = 0
    for r in valid:
        out = r.parse_result.output
        if out and out.evidence:
            if out.evidence.source and out.evidence.sink and len(out.evidence.flow) > 0:
                complete += 1
    return complete / len(valid)


def d15_reasoning_presence(results: list[TaskResult]) -> float:
    """Fraction of responses with non-empty reasoning."""
    valid = _non_error(results)
    if not valid:
        return 0.0
    with_reasoning = sum(
        1 for r in valid
        if r.parse_result.output and r.parse_result.output.reasoning
    )
    return with_reasoning / len(valid)


def d16_reasoning_and_correct(results: list[TaskResult]) -> float:
    """Among responses with reasoning, fraction with correct verdict."""
    has_reasoning = [
        r for r in _non_error(results)
        if r.parse_result.output and r.parse_result.output.reasoning
    ]
    if not has_reasoning:
        return 0.0
    return sum(1 for r in has_reasoning if r.scores.verdict == 1) / len(has_reasoning)


def d17_fp_reasoning(results: list[TaskResult]) -> float:
    """Among false positives, fraction with reasoning. 1.0 if no FPs."""
    fps = [
        r for r in _negative(_non_error(results))
        if r.parse_result.output is not None and r.parse_result.output.vulnerable is True
    ]
    if not fps:
        return 1.0
    return sum(1 for r in fps if r.parse_result.output.reasoning) / len(fps)


# ---------------------------------------------------------------------------
# Category D: Operational Efficiency (D18-D23)
# ---------------------------------------------------------------------------

def d18_cost_per_task(results: list[TaskResult]) -> float:
    """Mean USD per task (raw, lower is better)."""
    valid = _non_error(results)
    if not valid:
        return 0.0
    return sum(r.metrics.cost_usd for r in valid) / len(valid)


def d19_cost_per_tp(results: list[TaskResult]) -> float:
    """Total cost / TP count (raw USD, lower is better)."""
    valid = _non_error(results)
    total_cost = sum(r.metrics.cost_usd for r in valid)
    tp_count = sum(
        1 for r in valid
        if r.task_type == TaskType.TRUE_POSITIVE and r.scores.verdict == 1
    )
    return _safe_div(total_cost, tp_count)


def d20_mcc_per_dollar(results: list[TaskResult]) -> float:
    """MCC / total cost (raw, higher is better)."""
    mcc = d01_mcc(results)
    total_cost = sum(r.metrics.cost_usd for r in _non_error(results))
    return _safe_div(mcc, total_cost)


def d21_wall_time_per_task(results: list[TaskResult]) -> float:
    """Mean wall clock seconds per task (raw, lower is better)."""
    valid = _non_error(results)
    if not valid:
        return 0.0
    return sum(r.metrics.wall_time_s for r in valid) / len(valid)


def d22_throughput(results: list[TaskResult]) -> float:
    """Tasks per minute (raw, higher is better)."""
    valid = _non_error(results)
    if not valid:
        return 0.0
    total_wall = sum(r.metrics.wall_time_s for r in valid)
    if total_wall <= 0:
        return 0.0
    return len(valid) / (total_wall / 60.0)


def d23_tokens_per_task(results: list[TaskResult]) -> float:
    """Mean total tokens per task (raw, lower is better)."""
    valid = _non_error(results)
    if not valid:
        return 0.0
    return sum(r.metrics.total_tokens for r in valid) / len(valid)


# ---------------------------------------------------------------------------
# Category E: Tool-Use & Navigation (D24-D27)
# ---------------------------------------------------------------------------

def _tool_using(results: list[TaskResult]) -> list[TaskResult]:
    return [r for r in _non_error(results) if r.metrics.tool_calls > 0]


def d24_tool_calls_per_task(results: list[TaskResult]) -> float:
    """Mean tool calls among tool-using tasks (raw, lower is better)."""
    tool_tasks = _tool_using(results)
    if not tool_tasks:
        return 0.0
    return sum(r.metrics.tool_calls for r in tool_tasks) / len(tool_tasks)


def d25_turns_per_task(results: list[TaskResult]) -> float:
    """Mean turns per task (raw, lower is better)."""
    valid = _non_error(results)
    if not valid:
        return 0.0
    return sum(r.metrics.turns for r in valid) / len(valid)


def d26_navigation_efficiency(results: list[TaskResult]) -> float:
    """Fraction of tool-using tasks with <= 5 tool calls."""
    tool_tasks = _tool_using(results)
    if not tool_tasks:
        return 0.0
    return sum(1 for r in tool_tasks if r.metrics.tool_calls <= 5) / len(tool_tasks)


def d27_tool_effectiveness(results: list[TaskResult]) -> float:
    """Verdict accuracy among tool-using tasks."""
    tool_tasks = _tool_using(results)
    if not tool_tasks:
        return 0.0
    return sum(1 for r in tool_tasks if r.scores.verdict == 1) / len(tool_tasks)


# ---------------------------------------------------------------------------
# Category F: Risk & Severity (D28-D30)
# ---------------------------------------------------------------------------

def _has_severity(results: list[TaskResult]) -> bool:
    return any(r.task_severity is not None for r in results)


def d28_severity_weighted_recall(results: list[TaskResult]) -> float:
    """Recall weighted by severity: critical=4x, high=3x, medium=2x, low=1x."""
    pos = _positive(results)
    if not pos or not _has_severity(pos):
        return 0.0
    weighted_correct = 0.0
    total_weight = 0.0
    for r in pos:
        w = SEVERITY_WEIGHTS.get(r.task_severity or "", 1.0)
        total_weight += w
        if r.scores.verdict == 1:
            weighted_correct += w
    return _safe_div(weighted_correct, total_weight)


def d29_critical_miss_rate(results: list[TaskResult]) -> float:
    """Recall on critical+high severity tasks (1 - miss_rate)."""
    critical = [r for r in _positive(results) if r.task_severity in ("critical", "high")]
    if not critical:
        return 0.0
    return sum(1 for r in critical if r.scores.verdict == 1) / len(critical)


def d30_severity_coverage(results: list[TaskResult]) -> float:
    """Fraction of severity levels with at least one correct detection."""
    pos = _positive(results)
    if not pos or not _has_severity(pos):
        return 0.0
    groups: dict[str, list[int]] = defaultdict(list)
    for r in pos:
        if r.task_severity:
            groups[r.task_severity].append(r.scores.verdict)
    if not groups:
        return 0.0
    covered = sum(1 for verdicts in groups.values() if any(v == 1 for v in verdicts))
    return covered / len(groups)


# ---------------------------------------------------------------------------
# Category G: Robustness (D31-D35)
# ---------------------------------------------------------------------------

def d31_parse_success_rate(results: list[TaskResult]) -> float:
    """Fraction of non-error tasks with FULL parse status."""
    valid = _non_error(results)
    if not valid:
        return 0.0
    return sum(1 for r in valid if r.parse_result.status == ParseStatus.FULL) / len(valid)


def d32_format_compliance(results: list[TaskResult]) -> float:
    """Fraction of FULL parses among non-FAILED."""
    valid = _non_error(results)
    non_failed = [r for r in valid if r.parse_result.status != ParseStatus.FAILED]
    if not non_failed:
        return 0.0
    return sum(1 for r in non_failed if r.parse_result.status == ParseStatus.FULL) / len(non_failed)


def d33_error_rate(results: list[TaskResult]) -> float:
    """1 - error fraction (higher = better)."""
    if not results:
        return 0.0
    return 1.0 - sum(1 for r in results if r.error is not None) / len(results)


def d34_autonomous_completion(results: list[TaskResult]) -> float:
    """Fraction of tasks with no error AND parseable output."""
    if not results:
        return 0.0
    clean = sum(
        1 for r in results
        if r.error is None and r.parse_result.status != ParseStatus.FAILED
    )
    return clean / len(results)


def d35_graceful_degradation(results: list[TaskResult]) -> float:
    """1 - |common_category_accuracy - rare_category_accuracy|.

    Returns 0.5 (neutral) when all categories have equal task count,
    since common/rare split is not meaningful in that case.
    """
    pos = _positive(results)
    if not pos:
        return 0.0
    counts: dict[str, int] = defaultdict(int)
    for r in pos:
        counts[r.task_category or "uncategorized"] += 1
    if not counts:
        return 0.0
    median_count = statistics.median(counts.values())
    common = [r for r in pos if counts.get(r.task_category or "uncategorized", 0) > median_count]
    rare = [r for r in pos if counts.get(r.task_category or "uncategorized", 0) <= median_count]
    if not common or not rare:
        return 0.5
    common_acc = sum(r.scores.verdict for r in common) / len(common)
    rare_acc = sum(r.scores.verdict for r in rare) / len(rare)
    return max(0.0, 1.0 - abs(common_acc - rare_acc))


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

DIMENSION_FUNCTIONS: dict[str, Callable[[list[TaskResult]], float]] = {
    "D1": d01_mcc,
    "D2": d02_recall,
    "D3": d03_precision,
    "D4": d04_f1,
    "D5": d05_tnr,
    "D6": d06_cwe_accuracy,
    "D7": d07_mean_location_iou,
    "D8": d08_actionable_finding_rate,
    "D9": d09_cwe_coverage_breadth,
    "D10": d10_worst_category_floor,
    "D11": d11_cross_language_consistency,
    "D12": d12_worst_language_floor,
    "D13": d13_sast_fp_filtering,
    "D14": d14_evidence_completeness,
    "D15": d15_reasoning_presence,
    "D16": d16_reasoning_and_correct,
    "D17": d17_fp_reasoning,
    "D18": d18_cost_per_task,
    "D19": d19_cost_per_tp,
    "D20": d20_mcc_per_dollar,
    "D21": d21_wall_time_per_task,
    "D22": d22_throughput,
    "D23": d23_tokens_per_task,
    "D24": d24_tool_calls_per_task,
    "D25": d25_turns_per_task,
    "D26": d26_navigation_efficiency,
    "D27": d27_tool_effectiveness,
    "D28": d28_severity_weighted_recall,
    "D29": d29_critical_miss_rate,
    "D30": d30_severity_coverage,
    "D31": d31_parse_success_rate,
    "D32": d32_format_compliance,
    "D33": d33_error_rate,
    "D34": d34_autonomous_completion,
    "D35": d35_graceful_degradation,
}


def compute_all_dimensions(results: list[TaskResult]) -> dict[str, float]:
    """Compute all 35 dimension raw values from results."""
    return {dim_id: fn(results) for dim_id, fn in DIMENSION_FUNCTIONS.items()}
