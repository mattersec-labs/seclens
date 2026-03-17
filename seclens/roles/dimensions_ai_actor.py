"""AI as Actor — 50 dimensions.

Focus: Autonomous operation, self-directed navigation, unsupervised decision quality,
tool-use mastery, failure recovery, output reliability without human oversight.
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


def ai01_autonomous_completion_rate(results: list[TaskResult]) -> float:
    """% of tasks completed without error or parse failure — can it finish the job?"""
    if not results:
        return 0.0
    clean = sum(1 for r in results if r.error is None and r.parse_result.status != ParseStatus.FAILED)
    return clean / len(results)


def ai02_unsupervised_verdict_accuracy(results: list[TaskResult]) -> float:
    """Overall verdict accuracy — quality without human review."""
    valid = _non_error_results(results)
    if not valid:
        return 0.0
    return sum(r.scores.verdict for r in valid) / len(valid)


def ai03_mcc_normalized(results: list[TaskResult]) -> float:
    """MCC normalized 0-1 — balanced unsupervised quality."""
    return (d05_verdict_mcc(results) + 1.0) / 2.0


def ai04_full_finding_rate(results: list[TaskResult]) -> float:
    """% of TP tasks with perfect 3/3 — complete autonomous analysis."""
    pos = _positive_results(results)
    if not pos:
        return 0.0
    return sum(1 for r in pos if r.scores.earned == 3) / len(pos)


def ai05_zero_shot_accuracy(results: list[TaskResult]) -> float:
    """Proxy for minimal-prompt accuracy (uses all results)."""
    return ai02_unsupervised_verdict_accuracy(results)


def ai06_multi_turn_engagement(results: list[TaskResult]) -> float:
    """% of tasks where model uses > 1 turn — shows investigative behavior."""
    valid = _non_error_results(results)
    if not valid:
        return 0.0
    return sum(1 for r in valid if r.metrics.turns > 1) / len(valid)


def ai07_multi_turn_success(results: list[TaskResult]) -> float:
    """Among multi-turn tasks, % with correct verdict — investigation pays off."""
    multi = [r for r in _non_error_results(results) if r.metrics.turns > 1]
    if not multi:
        return 0.0
    return sum(r.scores.verdict for r in multi) / len(multi)


def ai08_single_turn_success(results: list[TaskResult]) -> float:
    """Single-turn accuracy — quick decisive judgment."""
    single = [r for r in _non_error_results(results) if r.metrics.turns <= 1]
    if not single:
        return 0.0
    return sum(r.scores.verdict for r in single) / len(single)


def ai09_tool_adoption_rate(results: list[TaskResult]) -> float:
    """% of tasks where model uses tools — does it know when to investigate?"""
    valid = _non_error_results(results)
    if not valid:
        return 0.0
    return sum(1 for r in valid if r.metrics.tool_calls > 0) / len(valid)


def ai10_tool_use_effectiveness(results: list[TaskResult]) -> float:
    """Among tool-using tasks, % with earned > 0."""
    tool_tasks = [r for r in _non_error_results(results) if r.metrics.tool_calls > 0]
    if not tool_tasks:
        return 1.0
    return sum(1 for r in tool_tasks if r.scores.earned > 0) / len(tool_tasks)


def ai11_tool_efficiency(results: list[TaskResult]) -> float:
    """% of tool tasks with <= 5 calls — efficient, not wasteful."""
    tool_tasks = [r for r in _non_error_results(results) if r.metrics.tool_calls > 0]
    if not tool_tasks:
        return 1.0
    return sum(1 for r in tool_tasks if r.metrics.tool_calls <= 5) / len(tool_tasks)


def ai12_tool_call_productivity(results: list[TaskResult]) -> float:
    """Score earned per tool call — productive tool use."""
    tool_tasks = [r for r in _non_error_results(results) if r.metrics.tool_calls > 0]
    if not tool_tasks:
        return 0.0
    total_calls = sum(r.metrics.tool_calls for r in tool_tasks)
    total_earned = sum(r.scores.earned for r in tool_tasks)
    return min(_safe_div(total_earned, total_calls) / 0.5, 1.0)


def ai13_navigation_speed(results: list[TaskResult]) -> float:
    """Median turns — how quickly does it converge on an answer?"""
    valid = _non_error_results(results)
    if not valid:
        return 0.0
    turns = [r.metrics.turns for r in valid]
    median = statistics.median(turns)
    return max(0.0, 1.0 - min(median / 20.0, 1.0))


def ai14_wasted_effort_rate(results: list[TaskResult]) -> float:
    """1 - (tool_calls > 0 but score = 0) rate — avoids futile exploration."""
    tool_tasks = [r for r in _non_error_results(results) if r.metrics.tool_calls > 0]
    if not tool_tasks:
        return 1.0
    wasted = sum(1 for r in tool_tasks if r.scores.earned == 0)
    return 1.0 - _safe_div(wasted, len(tool_tasks))


def ai15_structured_output_compliance(results: list[TaskResult]) -> float:
    """% FULL parse — follows output format autonomously."""
    valid = _non_error_results(results)
    if not valid:
        return 0.0
    return sum(1 for r in valid if r.parse_result.status == ParseStatus.FULL) / len(valid)


def ai16_format_self_correction(results: list[TaskResult]) -> float:
    """% FULL among non-FAILED — even if not perfect, recovers to parseable."""
    valid = _non_error_results(results)
    non_failed = [r for r in valid if r.parse_result.status != ParseStatus.FAILED]
    if not non_failed:
        return 0.0
    return sum(1 for r in non_failed if r.parse_result.status == ParseStatus.FULL) / len(non_failed)


def ai17_error_recovery(results: list[TaskResult]) -> float:
    """1 - error_rate — handles exceptions gracefully."""
    if not results:
        return 0.0
    return 1.0 - sum(1 for r in results if r.error) / len(results)


def ai18_parse_failure_prevention(results: list[TaskResult]) -> float:
    """1 - parse_failure_rate."""
    valid = _non_error_results(results)
    if not valid:
        return 1.0
    failed = sum(1 for r in valid if r.parse_result.status == ParseStatus.FAILED)
    return 1.0 - _safe_div(failed, len(valid))


def ai19_evidence_generation(results: list[TaskResult]) -> float:
    """% of responses with evidence chain — self-documenting analysis."""
    valid = _non_error_results(results)
    if not valid:
        return 0.0
    return sum(1 for r in valid if r.parse_result.output and r.parse_result.output.evidence
               and r.parse_result.output.evidence.source) / len(valid)


def ai20_reasoning_generation(results: list[TaskResult]) -> float:
    """% with reasoning — can explain its decisions to downstream systems."""
    valid = _non_error_results(results)
    if not valid:
        return 0.0
    return sum(1 for r in valid if r.parse_result.output and r.parse_result.output.reasoning) / len(valid)


def ai21_confidence_calibration(results: list[TaskResult]) -> float:
    """FULL parse + correct verdict — confident AND right."""
    valid = _non_error_results(results)
    if not valid:
        return 0.0
    return sum(1 for r in valid if r.parse_result.status == ParseStatus.FULL
               and r.scores.verdict == 1) / len(valid)


def ai22_overconfident_miss_prevention(results: list[TaskResult]) -> float:
    """1 - FN rate among FULL-parsed responses."""
    pos = _positive_results(results)
    full = [r for r in pos if r.parse_result.status == ParseStatus.FULL]
    if not full:
        return 0.0
    misses = sum(1 for r in full if r.scores.verdict == 0)
    return 1.0 - _safe_div(misses, len(full))


def ai23_cwe_identification(results: list[TaskResult]) -> float:
    """CWE accuracy among TPs — autonomous classification."""
    pos = [r for r in _positive_results(results) if r.scores.verdict == 1]
    if not pos:
        return 0.0
    return sum(r.scores.cwe for r in pos) / len(pos)


def ai24_location_identification(results: list[TaskResult]) -> float:
    """Location accuracy — autonomous pinpointing."""
    pos = [r for r in _positive_results(results) if r.scores.verdict == 1]
    if not pos:
        return 0.0
    return sum(r.scores.location for r in pos) / len(pos)


def ai25_complete_analysis_rate(results: list[TaskResult]) -> float:
    """% of TPs with verdict + CWE + location — full autonomous analysis."""
    pos = [r for r in _positive_results(results) if r.scores.verdict == 1]
    if not pos:
        return 0.0
    return sum(1 for r in pos if r.scores.cwe == 1 and r.scores.location == 1) / len(pos)


def ai26_recall(results: list[TaskResult]) -> float:
    """TPR."""
    return d01_true_positive_rate(results)


def ai27_specificity(results: list[TaskResult]) -> float:
    """TNR."""
    return d02_true_negative_rate(results)


def ai28_precision(results: list[TaskResult]) -> float:
    """PPV."""
    valid = _non_error_results(results)
    vuln_preds = [r for r in valid if _verdict_pred(r) is True]
    if not vuln_preds:
        return 0.0
    return sum(1 for r in vuln_preds if r.task_type == TaskType.TRUE_POSITIVE) / len(vuln_preds)


def ai29_f1_score(results: list[TaskResult]) -> float:
    """F1."""
    p = ai28_precision(results)
    r = ai26_recall(results)
    return _safe_div(2 * p * r, p + r)


def ai30_graceful_degradation(results: list[TaskResult]) -> float:
    """1 - |common_acc - rare_acc| — handles novel patterns."""
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


def ai31_cross_language_autonomy(results: list[TaskResult]) -> float:
    """1 - language accuracy gap — works across codebases."""
    groups: dict[str, list[int]] = defaultdict(list)
    for r in _non_error_results(results):
        groups[r.task_language].append(r.scores.verdict)
    if len(groups) < 2:
        return 1.0
    accs = [sum(v) / len(v) for v in groups.values() if v]
    return max(0.0, 1.0 - (max(accs) - min(accs)))


def ai32_cross_category_autonomy(results: list[TaskResult]) -> float:
    """% of CWE categories with > 50% accuracy."""
    groups: dict[str, list[int]] = defaultdict(list)
    for r in _non_error_results(results):
        groups[r.task_category or "uncategorized"].append(r.scores.verdict)
    if not groups:
        return 0.0
    return sum(1 for v in groups.values() if sum(v) / len(v) > 0.5) / len(groups)


def ai33_worst_category(results: list[TaskResult]) -> float:
    """Min accuracy across categories — autonomous blind spots."""
    groups: dict[str, list[int]] = defaultdict(list)
    for r in _non_error_results(results):
        groups[r.task_category or "uncategorized"].append(r.scores.verdict)
    if not groups:
        return 0.0
    return min(sum(v) / len(v) for v in groups.values() if v)


def ai34_critical_vuln_autonomous_detection(results: list[TaskResult]) -> float:
    """Detection rate on critical CWEs without guidance."""
    pos = _positive_results(results)
    critical = [r for r in pos if any(kw in (r.task_category or "").lower()
                for kw in ["injection", "rce", "xss", "auth", "deseriali", "command"])]
    if not critical:
        return d01_true_positive_rate(results)
    return sum(r.scores.verdict for r in critical) / len(critical)


def ai35_post_patch_discrimination(results: list[TaskResult]) -> float:
    """Post-patch accuracy — knows when something is fixed."""
    pp = [r for r in results if r.task_type == TaskType.POST_PATCH]
    if not pp:
        return d02_true_negative_rate(results)
    return sum(r.scores.verdict for r in pp) / len(pp)


def ai36_sast_fp_discrimination(results: list[TaskResult]) -> float:
    """SAST FP rejection — doesn't blindly agree with other tools."""
    sast = [r for r in results if r.task_type == TaskType.SAST_FALSE_POSITIVE]
    if not sast:
        return d02_true_negative_rate(results)
    return sum(r.scores.verdict for r in sast) / len(sast)


def ai37_cost_efficiency(results: list[TaskResult]) -> float:
    """Average cost per task — resource consumption (raw)."""
    valid = _non_error_results(results)
    if not valid:
        return 0.0
    return sum(r.metrics.cost_usd for r in valid) / len(valid)


def ai38_token_efficiency(results: list[TaskResult]) -> float:
    """Correct verdicts per 1K tokens."""
    valid = _non_error_results(results)
    if not valid:
        return 0.0
    tokens = sum(r.metrics.total_tokens for r in valid)
    correct = sum(r.scores.verdict for r in valid)
    if tokens == 0:
        return 0.0
    return min((correct / (tokens / 1000)) * 5, 1.0)


def ai39_wall_time_autonomy(results: list[TaskResult]) -> float:
    """% completing within 60s — autonomous tasks should be timely."""
    valid = _non_error_results(results)
    if not valid:
        return 0.0
    return sum(1 for r in valid if r.metrics.wall_time_s <= 60) / len(valid)


def ai40_self_monitoring_proxy(results: list[TaskResult]) -> float:
    """FULL parse rate × correct verdict — knows when it's sure AND is right."""
    valid = _non_error_results(results)
    if not valid:
        return 0.0
    return sum(1 for r in valid if r.parse_result.status == ParseStatus.FULL
               and r.scores.verdict == 1) / len(valid)


def ai41_decision_consistency(results: list[TaskResult]) -> float:
    """Placeholder — multi-seed required. Returns 0.5."""
    return 0.5


def ai42_adversarial_robustness(results: list[TaskResult]) -> float:
    """Placeholder — requires adversarial prompts. Returns 0.5."""
    return 0.5


def ai43_task_type_coverage(results: list[TaskResult]) -> float:
    """Accuracy across all task types (TP, post-patch, SAST FP)."""
    type_groups: dict[str, list[int]] = defaultdict(list)
    for r in _non_error_results(results):
        type_groups[r.task_type].append(r.scores.verdict)
    if not type_groups:
        return 0.0
    type_accs = [sum(v) / len(v) for v in type_groups.values() if v]
    return sum(type_accs) / len(type_accs) if type_accs else 0.0


def ai44_autonomous_triage_quality(results: list[TaskResult]) -> float:
    """Composite: verdict accuracy × evidence × CWE — can it triage alone?"""
    verdict = ai02_unsupervised_verdict_accuracy(results)
    evidence = ai19_evidence_generation(results)
    cwe = ai23_cwe_identification(results)
    return (verdict * 0.4 + evidence * 0.3 + cwe * 0.3)


def ai45_autonomous_remediation_guidance(results: list[TaskResult]) -> float:
    """Composite: location + evidence + reasoning — can it guide fixes?"""
    loc = ai24_location_identification(results)
    evidence = ai19_evidence_generation(results)
    reasoning = ai20_reasoning_generation(results)
    return (loc * 0.4 + evidence * 0.3 + reasoning * 0.3)


def ai46_pipeline_integration_readiness(results: list[TaskResult]) -> float:
    """Composite: parse success + error prevention + format compliance."""
    parse = ai15_structured_output_compliance(results)
    errors = ai17_error_recovery(results)
    format_ok = ai16_format_self_correction(results)
    return (parse * 0.4 + errors * 0.3 + format_ok * 0.3)


def ai47_human_replacement_index(results: list[TaskResult]) -> float:
    """How close to human-level triage? F1 × complete_analysis × reliability."""
    f1 = ai29_f1_score(results)
    complete = ai25_complete_analysis_rate(results)
    reliable = ai01_autonomous_completion_rate(results)
    return (f1 * 0.4 + complete * 0.3 + reliable * 0.3)


def ai48_agent_loop_efficiency(results: list[TaskResult]) -> float:
    """Average turns × accuracy — efficient agent loops."""
    valid = _non_error_results(results)
    if not valid:
        return 0.0
    avg_turns = sum(r.metrics.turns for r in valid) / len(valid)
    accuracy = sum(r.scores.verdict for r in valid) / len(valid)
    # More accuracy per turn = better
    if avg_turns == 0:
        return accuracy
    return min(accuracy / max(avg_turns / 5.0, 0.1), 1.0)


def ai49_autonomous_scalability(results: list[TaskResult]) -> float:
    """Completion rate × cost efficiency — can scale autonomous ops."""
    completion = ai01_autonomous_completion_rate(results)
    cost = ai37_cost_efficiency(results)
    # Invert cost: < $0.10 = good
    cost_score = max(0.0, 1.0 - min(cost / 0.50, 1.0))
    return (completion * 0.6 + cost_score * 0.4)


def ai50_overall_autonomy_score(results: list[TaskResult]) -> float:
    """Master autonomy score: can this model operate independently on security tasks?"""
    completion = ai01_autonomous_completion_rate(results)
    quality = ai29_f1_score(results)
    tool_mastery = ai10_tool_use_effectiveness(results)
    complete_analysis = ai25_complete_analysis_rate(results)
    reliability = ai17_error_recovery(results)
    return (completion * 0.2 + quality * 0.25 + tool_mastery * 0.2 +
            complete_analysis * 0.15 + reliability * 0.2)


AI_ACTOR_DIMENSIONS: dict[int, tuple[str, callable]] = {
    1: ("Autonomous Completion Rate", ai01_autonomous_completion_rate),
    2: ("Unsupervised Verdict Accuracy", ai02_unsupervised_verdict_accuracy),
    3: ("MCC (Normalized)", ai03_mcc_normalized),
    4: ("Full Finding Rate (3/3)", ai04_full_finding_rate),
    5: ("Zero-Shot Accuracy", ai05_zero_shot_accuracy),
    6: ("Multi-Turn Engagement Rate", ai06_multi_turn_engagement),
    7: ("Multi-Turn Success Rate", ai07_multi_turn_success),
    8: ("Single-Turn Success Rate", ai08_single_turn_success),
    9: ("Tool Adoption Rate", ai09_tool_adoption_rate),
    10: ("Tool-Use Effectiveness", ai10_tool_use_effectiveness),
    11: ("Tool Efficiency (<= 5 calls)", ai11_tool_efficiency),
    12: ("Tool Call Productivity", ai12_tool_call_productivity),
    13: ("Navigation Speed", ai13_navigation_speed),
    14: ("Wasted Effort Prevention", ai14_wasted_effort_rate),
    15: ("Structured Output Compliance", ai15_structured_output_compliance),
    16: ("Format Self-Correction", ai16_format_self_correction),
    17: ("Error Recovery", ai17_error_recovery),
    18: ("Parse Failure Prevention", ai18_parse_failure_prevention),
    19: ("Evidence Generation", ai19_evidence_generation),
    20: ("Reasoning Generation", ai20_reasoning_generation),
    21: ("Confidence Calibration", ai21_confidence_calibration),
    22: ("Overconfident Miss Prevention", ai22_overconfident_miss_prevention),
    23: ("CWE Identification", ai23_cwe_identification),
    24: ("Location Identification", ai24_location_identification),
    25: ("Complete Analysis Rate", ai25_complete_analysis_rate),
    26: ("Recall (TPR)", ai26_recall),
    27: ("Specificity (TNR)", ai27_specificity),
    28: ("Precision (PPV)", ai28_precision),
    29: ("F1 Score", ai29_f1_score),
    30: ("Graceful Degradation", ai30_graceful_degradation),
    31: ("Cross-Language Autonomy", ai31_cross_language_autonomy),
    32: ("Cross-Category Autonomy", ai32_cross_category_autonomy),
    33: ("Worst Category Floor", ai33_worst_category),
    34: ("Critical Vuln Autonomous Detection", ai34_critical_vuln_autonomous_detection),
    35: ("Post-Patch Discrimination", ai35_post_patch_discrimination),
    36: ("SAST FP Discrimination", ai36_sast_fp_discrimination),
    37: ("Cost Efficiency", ai37_cost_efficiency),
    38: ("Token Efficiency", ai38_token_efficiency),
    39: ("Wall Time Autonomy (< 60s)", ai39_wall_time_autonomy),
    40: ("Self-Monitoring Proxy", ai40_self_monitoring_proxy),
    41: ("Decision Consistency", ai41_decision_consistency),
    42: ("Adversarial Robustness", ai42_adversarial_robustness),
    43: ("Task Type Coverage", ai43_task_type_coverage),
    44: ("Autonomous Triage Quality", ai44_autonomous_triage_quality),
    45: ("Autonomous Remediation Guidance", ai45_autonomous_remediation_guidance),
    46: ("Pipeline Integration Readiness", ai46_pipeline_integration_readiness),
    47: ("Human Replacement Index", ai47_human_replacement_index),
    48: ("Agent Loop Efficiency", ai48_agent_loop_efficiency),
    49: ("Autonomous Scalability", ai49_autonomous_scalability),
    50: ("Overall Autonomy Score", ai50_overall_autonomy_score),
}
