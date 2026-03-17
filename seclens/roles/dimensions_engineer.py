"""Head of Engineering — 50 dimensions.

Focus: Developer velocity, signal-to-noise, actionable findings, CI/CD integration,
low false positives, fast response, localization precision, team adoption.
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


def e01_false_positive_rate(results: list[TaskResult]) -> float:
    """TNR — how often does it correctly clear clean code? (FP = developer toil)."""
    return d02_true_negative_rate(results)


def e02_precision(results: list[TaskResult]) -> float:
    """PPV — when it says 'vulnerable', how often is it right?"""
    valid = _non_error_results(results)
    vuln_preds = [r for r in valid if _verdict_pred(r) is True]
    if not vuln_preds:
        return 0.0
    return sum(1 for r in vuln_preds if r.task_type == TaskType.TRUE_POSITIVE) / len(vuln_preds)


def e03_recall(results: list[TaskResult]) -> float:
    """TPR — what % of real vulns does it catch?"""
    return d01_true_positive_rate(results)


def e04_f1_score(results: list[TaskResult]) -> float:
    """Balanced precision-recall."""
    p = e02_precision(results)
    r = e03_recall(results)
    return _safe_div(2 * p * r, p + r)


def e05_mcc_normalized(results: list[TaskResult]) -> float:
    """MCC normalized to 0-1."""
    return (d05_verdict_mcc(results) + 1.0) / 2.0


def e06_file_level_accuracy(results: list[TaskResult]) -> float:
    """% of correct TPs with location attempted — file-level accuracy."""
    pos = [r for r in _positive_results(results) if r.scores.verdict == 1]
    if not pos:
        return 0.0
    with_loc = sum(1 for r in pos if r.parse_result.output and r.parse_result.output.location)
    return with_loc / len(pos)


def e07_location_accuracy(results: list[TaskResult]) -> float:
    """Line-level accuracy (IoU > 0.5) — can devs jump to the right code?"""
    pos = [r for r in _positive_results(results) if r.scores.verdict == 1]
    if not pos:
        return 0.0
    return sum(r.scores.location for r in pos) / len(pos)


def e08_location_precision(results: list[TaskResult]) -> float:
    """1 - over-scope rate: findings don't highlight too much code."""
    pos = [r for r in _positive_results(results) if r.scores.verdict == 1]
    attempted = [r for r in pos if r.parse_result.output and r.parse_result.output.location]
    if not attempted:
        return 1.0
    wrong = sum(1 for r in attempted if r.scores.location == 0)
    return 1.0 - _safe_div(wrong, len(attempted))


def e09_actionable_finding_rate(results: list[TaskResult]) -> float:
    """% of TPs with verdict + CWE + location — devs can act on it immediately."""
    pos = [r for r in _positive_results(results) if r.scores.verdict == 1]
    if not pos:
        return 0.0
    return sum(1 for r in pos if r.scores.cwe == 1 and r.scores.location == 1) / len(pos)


def e10_cwe_accuracy(results: list[TaskResult]) -> float:
    """CWE match — devs need to know what type of fix is needed."""
    pos = [r for r in _positive_results(results) if r.scores.verdict == 1]
    if not pos:
        return 0.0
    return sum(r.scores.cwe for r in pos) / len(pos)


def e11_wall_time_per_task(results: list[TaskResult]) -> float:
    """Average seconds per task — latency in CI/CD pipeline."""
    valid = _non_error_results(results)
    if not valid:
        return 0.0
    return sum(r.metrics.wall_time_s for r in valid) / len(valid)


def e12_p95_wall_time(results: list[TaskResult]) -> float:
    """95th percentile wall time — worst-case latency."""
    valid = _non_error_results(results)
    if not valid:
        return 0.0
    times = sorted(r.metrics.wall_time_s for r in valid)
    idx = int(len(times) * 0.95)
    return times[min(idx, len(times) - 1)]


def e13_sla_30s_compliance(results: list[TaskResult]) -> float:
    """% of tasks completing within 30 seconds — fast CI gate."""
    valid = _non_error_results(results)
    if not valid:
        return 0.0
    return sum(1 for r in valid if r.metrics.wall_time_s <= 30) / len(valid)


def e14_sla_60s_compliance(results: list[TaskResult]) -> float:
    """% of tasks completing within 60 seconds."""
    valid = _non_error_results(results)
    if not valid:
        return 0.0
    return sum(1 for r in valid if r.metrics.wall_time_s <= 60) / len(valid)


def e15_throughput(results: list[TaskResult]) -> float:
    """Tasks per minute — CI throughput."""
    valid = _non_error_results(results)
    if not valid:
        return 0.0
    total = sum(r.metrics.wall_time_s for r in valid)
    if total <= 0:
        return 0.0
    return len(valid) / (total / 60.0)


def e16_cost_per_task(results: list[TaskResult]) -> float:
    """Average USD per task (raw)."""
    valid = _non_error_results(results)
    if not valid:
        return 0.0
    return sum(r.metrics.cost_usd for r in valid) / len(valid)


def e17_cost_per_pr(results: list[TaskResult]) -> float:
    """Projected cost per PR (assume 5 functions/PR) — raw $."""
    return e16_cost_per_task(results) * 5


def e18_monthly_projected_cost(results: list[TaskResult]) -> float:
    """Projected cost for 5000 tasks/month — raw $."""
    return e16_cost_per_task(results) * 5000


def e19_tokens_per_task(results: list[TaskResult]) -> float:
    """Average tokens per task (raw)."""
    valid = _non_error_results(results)
    if not valid:
        return 0.0
    return sum(r.metrics.total_tokens for r in valid) / len(valid)


def e20_cost_per_actionable_finding(results: list[TaskResult]) -> float:
    """Cost per finding that a dev can actually act on (verdict+CWE+location)."""
    valid = _non_error_results(results)
    cost = sum(r.metrics.cost_usd for r in valid)
    actionable = sum(1 for r in _positive_results(results)
                     if r.scores.verdict == 1 and r.scores.cwe == 1 and r.scores.location == 1)
    return _safe_div(cost, actionable, float("inf"))


def e21_parse_success_rate(results: list[TaskResult]) -> float:
    """% FULL parse — clean structured output for integration."""
    valid = _non_error_results(results)
    if not valid:
        return 0.0
    return sum(1 for r in valid if r.parse_result.status == ParseStatus.FULL) / len(valid)


def e22_format_compliance(results: list[TaskResult]) -> float:
    """% FULL among non-FAILED — follows instructions reliably."""
    valid = _non_error_results(results)
    non_failed = [r for r in valid if r.parse_result.status != ParseStatus.FAILED]
    if not non_failed:
        return 0.0
    return sum(1 for r in non_failed if r.parse_result.status == ParseStatus.FULL) / len(non_failed)


def e23_error_rate(results: list[TaskResult]) -> float:
    """1 - error_rate — reliability in production."""
    if not results:
        return 0.0
    return 1.0 - sum(1 for r in results if r.error) / len(results)


def e24_parse_failure_rate(results: list[TaskResult]) -> float:
    """1 - parse_failure_rate."""
    valid = _non_error_results(results)
    if not valid:
        return 1.0
    failed = sum(1 for r in valid if r.parse_result.status == ParseStatus.FAILED)
    return 1.0 - _safe_div(failed, len(valid))


def e25_overall_reliability(results: list[TaskResult]) -> float:
    """Composite: no errors AND parseable output."""
    if not results:
        return 0.0
    clean = sum(1 for r in results if r.error is None and r.parse_result.status != ParseStatus.FAILED)
    return clean / len(results)


def e26_reasoning_for_devs(results: list[TaskResult]) -> float:
    """% with reasoning — devs need to understand why code is flagged."""
    valid = _non_error_results(results)
    if not valid:
        return 0.0
    return sum(1 for r in valid if r.parse_result.output and r.parse_result.output.reasoning) / len(valid)


def e27_evidence_for_fix(results: list[TaskResult]) -> float:
    """% of TPs with source + sink — tells devs what to fix."""
    pos = [r for r in _positive_results(results) if r.scores.verdict == 1]
    if not pos:
        return 0.0
    return sum(1 for r in pos if r.parse_result.output and r.parse_result.output.evidence
               and r.parse_result.output.evidence.source and r.parse_result.output.evidence.sink) / len(pos)


def e28_patch_verification(results: list[TaskResult]) -> float:
    """Post-patch accuracy — can it verify fixes in PR review?"""
    pp = [r for r in results if r.task_type == TaskType.POST_PATCH]
    if not pp:
        return d02_true_negative_rate(results)
    return sum(r.scores.verdict for r in pp) / len(pp)


def e29_sast_noise_reduction(results: list[TaskResult]) -> float:
    """SAST FP rejection — can it filter existing SAST noise?"""
    sast = [r for r in results if r.task_type == TaskType.SAST_FALSE_POSITIVE]
    if not sast:
        return d02_true_negative_rate(results)
    return sum(r.scores.verdict for r in sast) / len(sast)


def e30_developer_trust_score(results: list[TaskResult]) -> float:
    """PPV × parse success — findings that devs can trust AND act on."""
    ppv = e02_precision(results)
    parse = e21_parse_success_rate(results)
    return ppv * parse


def e31_python_accuracy(results: list[TaskResult]) -> float:
    """Python-specific accuracy."""
    py = [r for r in _non_error_results(results) if r.task_language.lower() == "python"]
    if not py:
        return 0.0
    return sum(r.scores.verdict for r in py) / len(py)


def e32_javascript_accuracy(results: list[TaskResult]) -> float:
    """JS/TS accuracy."""
    js = [r for r in _non_error_results(results) if r.task_language.lower() in ("javascript", "typescript", "js", "ts")]
    if not js:
        return 0.0
    return sum(r.scores.verdict for r in js) / len(js)


def e33_java_accuracy(results: list[TaskResult]) -> float:
    """Java accuracy."""
    java = [r for r in _non_error_results(results) if r.task_language.lower() == "java"]
    if not java:
        return 0.0
    return sum(r.scores.verdict for r in java) / len(java)


def e34_go_accuracy(results: list[TaskResult]) -> float:
    """Go accuracy."""
    go = [r for r in _non_error_results(results) if r.task_language.lower() in ("go", "golang")]
    if not go:
        return 0.0
    return sum(r.scores.verdict for r in go) / len(go)


def e35_language_parity(results: list[TaskResult]) -> float:
    """1 - language accuracy gap — consistent across the stack."""
    groups: dict[str, list[int]] = defaultdict(list)
    for r in _non_error_results(results):
        groups[r.task_language].append(r.scores.verdict)
    if len(groups) < 2:
        return 1.0
    accs = [sum(v) / len(v) for v in groups.values() if v]
    return max(0.0, 1.0 - (max(accs) - min(accs)))


def e36_tool_call_efficiency(results: list[TaskResult]) -> float:
    """% of tool-using tasks with <= 5 calls — not wasting API budget."""
    tool_tasks = [r for r in _non_error_results(results) if r.metrics.tool_calls > 0]
    if not tool_tasks:
        return 1.0
    return sum(1 for r in tool_tasks if r.metrics.tool_calls <= 5) / len(tool_tasks)


def e37_turn_efficiency(results: list[TaskResult]) -> float:
    """% of tasks completing in <= 3 turns."""
    valid = _non_error_results(results)
    if not valid:
        return 0.0
    return sum(1 for r in valid if r.metrics.turns <= 3) / len(valid)


def e38_wasted_tool_rate(results: list[TaskResult]) -> float:
    """1 - (tool_calls > 0 but score = 0) rate."""
    tool_tasks = [r for r in _non_error_results(results) if r.metrics.tool_calls > 0]
    if not tool_tasks:
        return 1.0
    wasted = sum(1 for r in tool_tasks if r.scores.earned == 0)
    return 1.0 - _safe_div(wasted, len(tool_tasks))


def e39_cost_predictability(results: list[TaskResult]) -> float:
    """1 - CV of cost distribution — predictable billing."""
    valid = _non_error_results(results)
    if len(valid) < 2:
        return 0.0
    costs = [r.metrics.cost_usd for r in valid]
    mean = sum(costs) / len(costs)
    if mean == 0:
        return 1.0
    std = statistics.stdev(costs)
    return max(0.0, 1.0 - min(std / mean, 2.0) / 2.0)


def e40_worst_language_accuracy(results: list[TaskResult]) -> float:
    """Min accuracy across languages — no language is a blind spot."""
    groups: dict[str, list[int]] = defaultdict(list)
    for r in _non_error_results(results):
        groups[r.task_language].append(r.scores.verdict)
    if not groups:
        return 0.0
    return min(sum(v) / len(v) for v in groups.values() if v)


def e41_injection_detection(results: list[TaskResult]) -> float:
    """Injection detection rate — top OWASP concern."""
    pos = _positive_results(results)
    inj = [r for r in pos if "injection" in (r.task_category or "").lower()
           or "sqli" in (r.task_category or "").lower()
           or "command" in (r.task_category or "").lower()]
    if not inj:
        return d01_true_positive_rate(results)
    return sum(r.scores.verdict for r in inj) / len(inj)


def e42_xss_detection(results: list[TaskResult]) -> float:
    """XSS detection rate — frontend concern."""
    pos = _positive_results(results)
    xss = [r for r in pos if "xss" in (r.task_category or "").lower()]
    if not xss:
        return d01_true_positive_rate(results)
    return sum(r.scores.verdict for r in xss) / len(xss)


def e43_auth_detection(results: list[TaskResult]) -> float:
    """Auth/access control detection."""
    pos = _positive_results(results)
    auth = [r for r in pos if any(kw in (r.task_category or "").lower()
            for kw in ["auth", "access", "privilege"])]
    if not auth:
        return d01_true_positive_rate(results)
    return sum(r.scores.verdict for r in auth) / len(auth)


def e44_negative_predictive_value(results: list[TaskResult]) -> float:
    """Among 'not vuln' predictions, % correct — can devs trust a clean bill?"""
    valid = _non_error_results(results)
    not_vuln = [r for r in valid if _verdict_pred(r) is False]
    if not not_vuln:
        return 0.0
    return sum(1 for r in not_vuln if r.task_type != TaskType.TRUE_POSITIVE) / len(not_vuln)


def e45_ci_gate_readiness(results: list[TaskResult]) -> float:
    """Composite: fast + reliable + structured output."""
    speed = e14_sla_60s_compliance(results)
    reliable = e25_overall_reliability(results)
    structured = e21_parse_success_rate(results)
    return (speed * 0.3 + reliable * 0.4 + structured * 0.3)


def e46_noise_to_signal_ratio(results: list[TaskResult]) -> float:
    """PPV — what % of alerts are worth looking at."""
    return e02_precision(results)


def e47_developer_productivity_index(results: list[TaskResult]) -> float:
    """Actionable findings / total time — findings per minute that devs can use."""
    valid = _non_error_results(results)
    if not valid:
        return 0.0
    total_time = sum(r.metrics.wall_time_s for r in valid)
    actionable = sum(1 for r in _positive_results(results)
                     if r.scores.verdict == 1 and r.scores.cwe == 1 and r.scores.location == 1)
    if total_time <= 0:
        return 0.0
    return min((actionable / (total_time / 60.0)) / 10.0, 1.0)


def e48_full_finding_rate(results: list[TaskResult]) -> float:
    """% of TP tasks with perfect 3/3 score — gold-standard findings."""
    pos = _positive_results(results)
    if not pos:
        return 0.0
    return sum(1 for r in pos if r.scores.earned == 3) / len(pos)


def e49_team_adoption_readiness(results: list[TaskResult]) -> float:
    """Composite: low FP + fast + reliable + actionable — will devs actually use it?"""
    low_fp = e01_false_positive_rate(results)
    fast = e14_sla_60s_compliance(results)
    reliable = e25_overall_reliability(results)
    actionable = e09_actionable_finding_rate(results)
    return (low_fp * 0.3 + fast * 0.2 + reliable * 0.25 + actionable * 0.25)


def e50_overall_engineering_score(results: list[TaskResult]) -> float:
    """Master engineering score: precision, speed, reliability, actionability."""
    precision = e02_precision(results)
    speed = e14_sla_60s_compliance(results)
    reliability = e25_overall_reliability(results)
    actionable = e09_actionable_finding_rate(results)
    location = e07_location_accuracy(results)
    return (precision * 0.25 + speed * 0.15 + reliability * 0.2 + actionable * 0.2 + location * 0.2)


ENGINEER_DIMENSIONS: dict[int, tuple[str, callable]] = {
    1: ("False Positive Prevention (TNR)", e01_false_positive_rate),
    2: ("Precision (PPV)", e02_precision),
    3: ("Recall (TPR)", e03_recall),
    4: ("F1 Score", e04_f1_score),
    5: ("MCC (Normalized)", e05_mcc_normalized),
    6: ("File-Level Accuracy", e06_file_level_accuracy),
    7: ("Location Accuracy (IoU>0.5)", e07_location_accuracy),
    8: ("Location Precision", e08_location_precision),
    9: ("Actionable Finding Rate", e09_actionable_finding_rate),
    10: ("CWE Accuracy", e10_cwe_accuracy),
    11: ("Wall Time Per Task (avg)", e11_wall_time_per_task),
    12: ("P95 Wall Time", e12_p95_wall_time),
    13: ("SLA Compliance (30s)", e13_sla_30s_compliance),
    14: ("SLA Compliance (60s)", e14_sla_60s_compliance),
    15: ("Throughput (tasks/min)", e15_throughput),
    16: ("Cost Per Task", e16_cost_per_task),
    17: ("Cost Per PR (projected)", e17_cost_per_pr),
    18: ("Monthly Cost (projected)", e18_monthly_projected_cost),
    19: ("Tokens Per Task", e19_tokens_per_task),
    20: ("Cost Per Actionable Finding", e20_cost_per_actionable_finding),
    21: ("Parse Success Rate", e21_parse_success_rate),
    22: ("Format Compliance", e22_format_compliance),
    23: ("Error Rate (inverted)", e23_error_rate),
    24: ("Parse Failure Prevention", e24_parse_failure_rate),
    25: ("Overall Reliability", e25_overall_reliability),
    26: ("Reasoning for Developers", e26_reasoning_for_devs),
    27: ("Evidence for Fix (source+sink)", e27_evidence_for_fix),
    28: ("Patch Verification", e28_patch_verification),
    29: ("SAST Noise Reduction", e29_sast_noise_reduction),
    30: ("Developer Trust Score", e30_developer_trust_score),
    31: ("Python Accuracy", e31_python_accuracy),
    32: ("JavaScript Accuracy", e32_javascript_accuracy),
    33: ("Java Accuracy", e33_java_accuracy),
    34: ("Go Accuracy", e34_go_accuracy),
    35: ("Language Parity", e35_language_parity),
    36: ("Tool Call Efficiency", e36_tool_call_efficiency),
    37: ("Turn Efficiency", e37_turn_efficiency),
    38: ("Wasted Tool Prevention", e38_wasted_tool_rate),
    39: ("Cost Predictability", e39_cost_predictability),
    40: ("Worst Language Accuracy", e40_worst_language_accuracy),
    41: ("Injection Detection", e41_injection_detection),
    42: ("XSS Detection", e42_xss_detection),
    43: ("Auth Detection", e43_auth_detection),
    44: ("Negative Predictive Value", e44_negative_predictive_value),
    45: ("CI Gate Readiness", e45_ci_gate_readiness),
    46: ("Noise-to-Signal Ratio", e46_noise_to_signal_ratio),
    47: ("Developer Productivity Index", e47_developer_productivity_index),
    48: ("Full Finding Rate (3/3)", e48_full_finding_rate),
    49: ("Team Adoption Readiness", e49_team_adoption_readiness),
    50: ("Overall Engineering Score", e50_overall_engineering_score),
}
