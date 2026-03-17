"""CAIO / Head of AI — 50 dimensions.

Focus: Capability upside, new automation unlocks, risk-balanced adoption,
cost-efficiency at scale, model comparison, strategic enablement.
"""

from __future__ import annotations

import statistics
from collections import defaultdict

from seclens.roles.dimensions import (
    _negative_results,
    _non_error_results,
    _positive_results,
    _safe_div,
    _verdict_pred,
    d01_true_positive_rate,
    d02_true_negative_rate,
    d05_verdict_mcc,
)
from seclens.schemas.output import ParseStatus
from seclens.schemas.scoring import TaskResult, TaskType


def a01_capability_score(results: list[TaskResult]) -> float:
    """Overall accuracy — baseline capability signal."""
    valid = _non_error_results(results)
    if not valid:
        return 0.0
    return sum(r.scores.verdict for r in valid) / len(valid)


def a02_full_finding_rate(results: list[TaskResult]) -> float:
    """% of TP tasks where model gets verdict + CWE + location all correct."""
    pos = _positive_results(results)
    if not pos:
        return 0.0
    perfect = sum(1 for r in pos if r.scores.earned == 3)
    return perfect / len(pos)


def a03_mcc_normalized(results: list[TaskResult]) -> float:
    """MCC normalized to 0-1."""
    return (d05_verdict_mcc(results) + 1.0) / 2.0


def a04_recall(results: list[TaskResult]) -> float:
    """True positive rate."""
    return d01_true_positive_rate(results)


def a05_precision(results: list[TaskResult]) -> float:
    """PPV — among flagged vulns, % that are real."""
    valid = _non_error_results(results)
    vuln_preds = [r for r in valid if _verdict_pred(r) is True]
    if not vuln_preds:
        return 0.0
    tp = sum(1 for r in vuln_preds if r.task_type == TaskType.TRUE_POSITIVE)
    return tp / len(vuln_preds)


def a06_f1_score(results: list[TaskResult]) -> float:
    """Harmonic mean of precision and recall."""
    p = a05_precision(results)
    r = a04_recall(results)
    return _safe_div(2 * p * r, p + r)


def a07_tool_use_effectiveness(results: list[TaskResult]) -> float:
    """Among tasks with tool use, % that scored > 0."""
    tool_tasks = [r for r in _non_error_results(results) if r.metrics.tool_calls > 0]
    if not tool_tasks:
        return 1.0
    effective = sum(1 for r in tool_tasks if r.scores.earned > 0)
    return effective / len(tool_tasks)


def a08_tool_use_uplift(results: list[TaskResult]) -> float:
    """Tool tasks accuracy vs non-tool tasks — measures tool value-add."""
    valid = _non_error_results(results)
    with_tools = [r for r in valid if r.metrics.tool_calls > 0]
    without_tools = [r for r in valid if r.metrics.tool_calls == 0]
    if not with_tools or not without_tools:
        return 0.5
    acc_with = sum(r.scores.verdict for r in with_tools) / len(with_tools)
    acc_without = sum(r.scores.verdict for r in without_tools) / len(without_tools)
    delta = acc_with - acc_without
    return max(0.0, min(1.0, 0.5 + delta))


def a09_autonomous_completion(results: list[TaskResult]) -> float:
    """% completed without error or parse failure — can it run unattended?"""
    if not results:
        return 0.0
    clean = sum(1 for r in results if r.error is None and r.parse_result.status != ParseStatus.FAILED)
    return clean / len(results)


def a10_multi_turn_success(results: list[TaskResult]) -> float:
    """% of multi-turn tasks with correct verdict."""
    multi = [r for r in _non_error_results(results) if r.metrics.turns > 1]
    if not multi:
        return 0.0
    return sum(r.scores.verdict for r in multi) / len(multi)


def a11_navigation_efficiency(results: list[TaskResult]) -> float:
    """% of L2 tasks solved with <=5 tool calls."""
    tool_tasks = [r for r in _non_error_results(results) if r.metrics.tool_calls > 0]
    if not tool_tasks:
        return 1.0
    efficient = sum(1 for r in tool_tasks if r.metrics.tool_calls <= 5)
    return efficient / len(tool_tasks)


def a12_reasoning_depth(results: list[TaskResult]) -> float:
    """% of responses with evidence chain populated."""
    valid = _non_error_results(results)
    if not valid:
        return 0.0
    deep = 0
    for r in valid:
        out = r.parse_result.output
        if out and out.evidence and out.evidence.source and out.evidence.sink:
            deep += 1
    return deep / len(valid)


def a13_zero_guidance_capability(results: list[TaskResult]) -> float:
    """Accuracy proxy when no category hint given (all results used as proxy)."""
    return a01_capability_score(results)


def a14_cross_category_breadth(results: list[TaskResult]) -> float:
    """% of CWE categories where accuracy > 50%."""
    groups: dict[str, list[int]] = defaultdict(list)
    for r in _non_error_results(results):
        groups[r.task_category or "uncategorized"].append(r.scores.verdict)
    if not groups:
        return 0.0
    good = sum(1 for v in groups.values() if sum(v) / len(v) > 0.5)
    return good / len(groups)


def a15_language_breadth(results: list[TaskResult]) -> float:
    """% of languages where accuracy > 50%."""
    groups: dict[str, list[int]] = defaultdict(list)
    for r in _non_error_results(results):
        groups[r.task_language].append(r.scores.verdict)
    if not groups:
        return 0.0
    good = sum(1 for v in groups.values() if sum(v) / len(v) > 0.5)
    return good / len(groups)


def a16_cost_per_task(results: list[TaskResult]) -> float:
    """Average cost per task (raw USD)."""
    valid = _non_error_results(results)
    if not valid:
        return 0.0
    return sum(r.metrics.cost_usd for r in valid) / len(valid)


def a17_cost_per_correct_finding(results: list[TaskResult]) -> float:
    """USD per TP detected (raw)."""
    valid = _non_error_results(results)
    cost = sum(r.metrics.cost_usd for r in valid)
    tp = sum(1 for r in valid if r.task_type == TaskType.TRUE_POSITIVE and r.scores.verdict == 1)
    return _safe_div(cost, tp, float("inf"))


def a18_mcc_per_dollar(results: list[TaskResult]) -> float:
    """MCC / total cost — quality per dollar."""
    mcc = d05_verdict_mcc(results)
    cost = sum(r.metrics.cost_usd for r in _non_error_results(results))
    return _safe_div(mcc, cost)


def a19_tokens_per_task(results: list[TaskResult]) -> float:
    """Average tokens per task (raw)."""
    valid = _non_error_results(results)
    if not valid:
        return 0.0
    return sum(r.metrics.total_tokens for r in valid) / len(valid)


def a20_accuracy_per_1k_tokens(results: list[TaskResult]) -> float:
    """Correct verdicts per 1K tokens consumed."""
    valid = _non_error_results(results)
    if not valid:
        return 0.0
    tokens = sum(r.metrics.total_tokens for r in valid)
    correct = sum(r.scores.verdict for r in valid)
    if tokens == 0:
        return 0.0
    return min((correct / (tokens / 1000)) * 5, 1.0)


def a21_cost_at_scale_1k(results: list[TaskResult]) -> float:
    """Projected cost for 1000 tasks (raw $)."""
    return a16_cost_per_task(results) * 1000


def a22_cost_at_scale_10k(results: list[TaskResult]) -> float:
    """Projected cost for 10K tasks (raw $)."""
    return a16_cost_per_task(results) * 10000


def a23_wall_time_per_task(results: list[TaskResult]) -> float:
    """Average seconds per task (raw)."""
    valid = _non_error_results(results)
    if not valid:
        return 0.0
    return sum(r.metrics.wall_time_s for r in valid) / len(valid)


def a24_throughput(results: list[TaskResult]) -> float:
    """Tasks per minute (raw)."""
    valid = _non_error_results(results)
    if not valid:
        return 0.0
    total_time = sum(r.metrics.wall_time_s for r in valid)
    if total_time <= 0:
        return 0.0
    return len(valid) / (total_time / 60.0)


def a25_risk_adjusted_return(results: list[TaskResult]) -> float:
    """Capability × (1 - error_rate) / cost — Sharpe-like ratio for AI investment."""
    capability = a01_capability_score(results)
    error_penalty = 1.0 - (sum(1 for r in results if r.error) / len(results)) if results else 0
    cost = sum(r.metrics.cost_usd for r in _non_error_results(results))
    return _safe_div(capability * error_penalty, max(cost, 0.001))


def a26_parse_compliance(results: list[TaskResult]) -> float:
    """% FULL parse — structured output compliance for integration."""
    valid = _non_error_results(results)
    if not valid:
        return 0.0
    return sum(1 for r in valid if r.parse_result.status == ParseStatus.FULL) / len(valid)


def a27_error_rate(results: list[TaskResult]) -> float:
    """1 - error_rate — reliability for automated pipelines."""
    if not results:
        return 0.0
    return 1.0 - sum(1 for r in results if r.error) / len(results)


def a28_graceful_degradation(results: list[TaskResult]) -> float:
    """1 - delta between common and rare CWE performance."""
    pos = _positive_results(results)
    counts: dict[str, int] = defaultdict(int)
    for r in pos:
        counts[r.task_category or "unknown"] += 1
    common = [r for r in pos if counts.get(r.task_category or "unknown", 0) > 3]
    rare = [r for r in pos if counts.get(r.task_category or "unknown", 0) <= 3]
    if not common or not rare:
        return 0.5
    c_acc = sum(r.scores.verdict for r in common) / len(common)
    r_acc = sum(r.scores.verdict for r in rare) / len(rare)
    return max(0.0, 1.0 - abs(c_acc - r_acc))


def a29_self_correction_capability(results: list[TaskResult]) -> float:
    """Among multi-turn tasks, accuracy — proxy for iterative refinement."""
    return a10_multi_turn_success(results)


def a30_false_positive_rate(results: list[TaskResult]) -> float:
    """1 - FPR — clean code correctly cleared."""
    return d02_true_negative_rate(results)


def a31_critical_miss_rate(results: list[TaskResult]) -> float:
    """Detection rate on high-severity CWE categories."""
    pos = _positive_results(results)
    critical = [
        r for r in pos
        if any(kw in (r.task_category or "").lower()
               for kw in ["injection", "rce", "xss", "auth", "deseriali", "command"])
    ]
    if not critical:
        return d01_true_positive_rate(results)
    return sum(r.scores.verdict for r in critical) / len(critical)


def a32_worst_category_risk(results: list[TaskResult]) -> float:
    """Min accuracy across CWE categories — downside risk."""
    groups: dict[str, list[int]] = defaultdict(list)
    for r in _non_error_results(results):
        groups[r.task_category or "uncategorized"].append(r.scores.verdict)
    if not groups:
        return 0.0
    return min(sum(v) / len(v) for v in groups.values() if v)


def a33_language_consistency(results: list[TaskResult]) -> float:
    """1 - gap between best and worst language performance."""
    groups: dict[str, list[int]] = defaultdict(list)
    for r in _non_error_results(results):
        groups[r.task_language].append(r.scores.verdict)
    if len(groups) < 2:
        return 1.0
    accs = [sum(v) / len(v) for v in groups.values() if v]
    return max(0.0, 1.0 - (max(accs) - min(accs)))


def a34_overconfident_miss_prevention(results: list[TaskResult]) -> float:
    """Among FN with FULL parse, 1 - miss rate."""
    pos = _positive_results(results)
    full = [r for r in pos if r.parse_result.status == ParseStatus.FULL]
    if not full:
        return 0.0
    misses = sum(1 for r in full if r.scores.verdict == 0)
    return 1.0 - _safe_div(misses, len(full))


def a35_patch_verification(results: list[TaskResult]) -> float:
    """Accuracy on post-patch tasks — can verify fixes."""
    post_patch = [r for r in results if r.task_type == TaskType.POST_PATCH]
    if not post_patch:
        return d02_true_negative_rate(results)
    return sum(r.scores.verdict for r in post_patch) / len(post_patch)


def a36_workflow_automation_readiness(results: list[TaskResult]) -> float:
    """Composite: autonomous completion × parse compliance × low error."""
    auto = a09_autonomous_completion(results)
    parse = a26_parse_compliance(results)
    err = a27_error_rate(results)
    return (auto * 0.4 + parse * 0.3 + err * 0.3)


def a37_new_capability_index(results: list[TaskResult]) -> float:
    """What new things does this unlock? Tool uplift × multi-turn × rare CWE performance."""
    uplift = a08_tool_use_uplift(results)
    multi = a10_multi_turn_success(results)
    from seclens.roles.dimensions import d08_rare_cwe_performance
    rare = d08_rare_cwe_performance(results)
    return (uplift * 0.4 + multi * 0.3 + rare * 0.3)


def a38_competitive_differentiation(results: list[TaskResult]) -> float:
    """Full finding rate — what % of tasks does it ace completely?"""
    return a02_full_finding_rate(results)


def a39_roi_index(results: list[TaskResult]) -> float:
    """F1 / cost_per_task — return per dollar invested."""
    f1 = a06_f1_score(results)
    cost = a16_cost_per_task(results)
    if cost == 0:
        return f1  # Free model = pure capability
    return min(f1 / cost, 100.0) / 100.0


def a40_reasoning_quality(results: list[TaskResult]) -> float:
    """% with reasoning + correct verdict — quality of explanation."""
    valid = _non_error_results(results)
    if not valid:
        return 0.0
    good = sum(
        1 for r in valid
        if r.scores.verdict == 1 and r.parse_result.output and r.parse_result.output.reasoning
    )
    return good / len(valid)


def a41_confidence_calibration(results: list[TaskResult]) -> float:
    """FULL parse + correct verdict rate — proxy for well-calibrated confidence."""
    valid = _non_error_results(results)
    if not valid:
        return 0.0
    calibrated = sum(
        1 for r in valid
        if r.parse_result.status == ParseStatus.FULL and r.scores.verdict == 1
    )
    return calibrated / len(valid)


def a42_integration_readiness(results: list[TaskResult]) -> float:
    """Parse compliance + error rate + structured output — API integration ready."""
    return (a26_parse_compliance(results) * 0.4 +
            a27_error_rate(results) * 0.3 +
            a09_autonomous_completion(results) * 0.3)


def a43_cwe_knowledge_depth(results: list[TaskResult]) -> float:
    """CWE accuracy — does it understand the taxonomy?"""
    correct_pos = [r for r in _positive_results(results) if r.scores.verdict == 1]
    if not correct_pos:
        return 0.0
    return sum(r.scores.cwe for r in correct_pos) / len(correct_pos)


def a44_location_precision(results: list[TaskResult]) -> float:
    """Location accuracy — can findings be acted on?"""
    pos = [r for r in _positive_results(results) if r.scores.verdict == 1]
    if not pos:
        return 0.0
    return sum(r.scores.location for r in pos) / len(pos)


def a45_strategic_value_score(results: list[TaskResult]) -> float:
    """Composite: capability × efficiency × reliability × capability uplift."""
    cap = a01_capability_score(results)
    eff = min(1.0, 1.0 - min(a16_cost_per_task(results) / 0.5, 1.0))
    rel = a27_error_rate(results)
    new_cap = a37_new_capability_index(results)
    return (cap * 0.3 + eff * 0.2 + rel * 0.2 + new_cap * 0.3)


def a46_sast_augmentation_value(results: list[TaskResult]) -> float:
    """Performance on SAST FP tasks — can it filter existing tool noise?"""
    sast = [r for r in results if r.task_type == TaskType.SAST_FALSE_POSITIVE]
    if not sast:
        return d02_true_negative_rate(results)
    return sum(r.scores.verdict for r in sast) / len(sast)


def a47_deployment_risk(results: list[TaskResult]) -> float:
    """1 - (error_rate + parse_failure_rate) / 2 — deployment safety."""
    if not results:
        return 0.0
    errors = sum(1 for r in results if r.error) / len(results)
    parse_fail = sum(1 for r in results if r.parse_result.status == ParseStatus.FAILED) / len(results)
    return 1.0 - (errors + parse_fail) / 2.0


def a48_scalability_confidence(results: list[TaskResult]) -> float:
    """Cost predictability — low variance in per-task cost."""
    valid = _non_error_results(results)
    if len(valid) < 2:
        return 0.0
    costs = [r.metrics.cost_usd for r in valid]
    mean = sum(costs) / len(costs)
    if mean == 0:
        return 1.0
    std = statistics.stdev(costs)
    cv = std / mean
    return max(0.0, 1.0 - min(cv, 2.0) / 2.0)


def a49_business_case_strength(results: list[TaskResult]) -> float:
    """Composite for business case: capability × cost-efficiency × risk."""
    cap = a06_f1_score(results)
    efficiency = min(1.0, 1.0 - min(a16_cost_per_task(results) / 0.5, 1.0))
    risk = a47_deployment_risk(results)
    return (cap * 0.4 + efficiency * 0.3 + risk * 0.3)


def a50_overall_caio_score(results: list[TaskResult]) -> float:
    """Master CAIO score: capability upside, balanced by risk and cost."""
    capability = a37_new_capability_index(results)
    quality = a06_f1_score(results)
    risk = a47_deployment_risk(results)
    cost_eff = min(1.0, 1.0 - min(a16_cost_per_task(results) / 0.5, 1.0))
    return (capability * 0.35 + quality * 0.25 + risk * 0.2 + cost_eff * 0.2)


CAIO_DIMENSIONS: dict[int, tuple[str, callable]] = {
    1: ("Capability Score", a01_capability_score),
    2: ("Full Finding Rate", a02_full_finding_rate),
    3: ("MCC (Normalized)", a03_mcc_normalized),
    4: ("Recall", a04_recall),
    5: ("Precision", a05_precision),
    6: ("F1 Score", a06_f1_score),
    7: ("Tool-Use Effectiveness", a07_tool_use_effectiveness),
    8: ("Tool-Use Uplift", a08_tool_use_uplift),
    9: ("Autonomous Completion Rate", a09_autonomous_completion),
    10: ("Multi-Turn Success Rate", a10_multi_turn_success),
    11: ("Navigation Efficiency", a11_navigation_efficiency),
    12: ("Reasoning Depth", a12_reasoning_depth),
    13: ("Zero-Guidance Capability", a13_zero_guidance_capability),
    14: ("Cross-Category Breadth", a14_cross_category_breadth),
    15: ("Language Breadth", a15_language_breadth),
    16: ("Cost Per Task", a16_cost_per_task),
    17: ("Cost Per Correct Finding", a17_cost_per_correct_finding),
    18: ("MCC Per Dollar", a18_mcc_per_dollar),
    19: ("Tokens Per Task", a19_tokens_per_task),
    20: ("Accuracy Per 1K Tokens", a20_accuracy_per_1k_tokens),
    21: ("Cost at Scale (1K tasks)", a21_cost_at_scale_1k),
    22: ("Cost at Scale (10K tasks)", a22_cost_at_scale_10k),
    23: ("Wall Time Per Task", a23_wall_time_per_task),
    24: ("Throughput (tasks/min)", a24_throughput),
    25: ("Risk-Adjusted Return", a25_risk_adjusted_return),
    26: ("Parse Compliance", a26_parse_compliance),
    27: ("Error Rate (inverted)", a27_error_rate),
    28: ("Graceful Degradation", a28_graceful_degradation),
    29: ("Self-Correction Capability", a29_self_correction_capability),
    30: ("False Positive Prevention", a30_false_positive_rate),
    31: ("Critical Miss Prevention", a31_critical_miss_rate),
    32: ("Worst-Category Risk", a32_worst_category_risk),
    33: ("Language Consistency", a33_language_consistency),
    34: ("Overconfident Miss Prevention", a34_overconfident_miss_prevention),
    35: ("Patch Verification", a35_patch_verification),
    36: ("Workflow Automation Readiness", a36_workflow_automation_readiness),
    37: ("New Capability Index", a37_new_capability_index),
    38: ("Competitive Differentiation", a38_competitive_differentiation),
    39: ("ROI Index", a39_roi_index),
    40: ("Reasoning Quality", a40_reasoning_quality),
    41: ("Confidence Calibration", a41_confidence_calibration),
    42: ("Integration Readiness", a42_integration_readiness),
    43: ("CWE Knowledge Depth", a43_cwe_knowledge_depth),
    44: ("Location Precision", a44_location_precision),
    45: ("Strategic Value Score", a45_strategic_value_score),
    46: ("SAST Augmentation Value", a46_sast_augmentation_value),
    47: ("Deployment Risk (inverted)", a47_deployment_risk),
    48: ("Scalability Confidence", a48_scalability_confidence),
    49: ("Business Case Strength", a49_business_case_strength),
    50: ("Overall CAIO Score", a50_overall_caio_score),
}
