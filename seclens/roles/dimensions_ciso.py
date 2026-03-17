"""CISO-specific 50 dimensions.

Focus: Risk governance, compliance readiness, trust in security program,
organizational liability, detection reliability, audit defensibility.
"""

from __future__ import annotations

from collections import defaultdict

from seclens.roles.dimensions import (
    CRITICAL_CWES,
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


def c01_overall_detection_reliability(results: list[TaskResult]) -> float:
    """Verdict accuracy across all tasks — the top-line trust metric."""
    valid = _non_error_results(results)
    if not valid:
        return 0.0
    return sum(r.scores.verdict for r in valid) / len(valid)


def c02_critical_vuln_detection_rate(results: list[TaskResult]) -> float:
    """Recall on injection, RCE, auth bypass, XSS, deserialization CWEs."""
    pos = _positive_results(results)
    critical = [
        r for r in pos
        if any(kw in (r.task_category or "").lower()
               for kw in ["injection", "rce", "xss", "auth", "deseriali", "command"])
    ]
    if not critical:
        return d01_true_positive_rate(results)
    return _safe_div(sum(r.scores.verdict for r in critical), len(critical))


def c03_false_negative_on_critical(results: list[TaskResult]) -> float:
    """% of critical vulns missed (inverted: 1 - miss_rate)."""
    return c02_critical_vuln_detection_rate(results)


def c04_false_alarm_rate(results: list[TaskResult]) -> float:
    """FP rate — organizational noise cost. (1 - FPR = better)."""
    return d02_true_negative_rate(results)


def c05_balanced_accuracy(results: list[TaskResult]) -> float:
    """(TPR + TNR) / 2 — balanced view of detection."""
    tpr = d01_true_positive_rate(results)
    tnr = d02_true_negative_rate(results)
    return (tpr + tnr) / 2.0


def c06_mcc_overall(results: list[TaskResult]) -> float:
    """Matthews Correlation Coefficient — the definitive balanced metric."""
    return (d05_verdict_mcc(results) + 1.0) / 2.0  # Normalized to 0-1


def c07_audit_trail_completeness(results: list[TaskResult]) -> float:
    """% of responses with full evidence chain (source + sink + flow)."""
    valid = _non_error_results(results)
    if not valid:
        return 0.0
    complete = 0
    for r in valid:
        out = r.parse_result.output
        if out and out.evidence:
            if out.evidence.source and out.evidence.sink and out.evidence.flow:
                complete += 1
    return complete / len(valid)


def c08_cwe_classification_accuracy(results: list[TaskResult]) -> float:
    """Correct CWE among TP detections — needed for compliance reporting."""
    correct_pos = [r for r in _positive_results(results) if r.scores.verdict == 1]
    if not correct_pos:
        return 0.0
    return sum(r.scores.cwe for r in correct_pos) / len(correct_pos)


def c09_zero_day_readiness(results: list[TaskResult]) -> float:
    """Performance on rare CWE categories (<=3 tasks) — proxy for novel vuln detection."""
    pos = _positive_results(results)
    counts: dict[str, int] = defaultdict(int)
    for r in pos:
        counts[r.task_category or "unknown"] += 1
    rare = [r for r in pos if counts.get(r.task_category or "unknown", 0) <= 3]
    if not rare:
        return 0.0
    return sum(r.scores.verdict for r in rare) / len(rare)


def c10_severity_weighted_recall(results: list[TaskResult]) -> float:
    """Recall weighted by assumed severity — high-impact misses cost more."""
    pos = _positive_results(results)
    if not pos:
        return 0.0
    weighted_correct = 0.0
    total_weight = 0.0
    for r in pos:
        is_critical = any(kw in (r.task_category or "").lower()
                          for kw in ["injection", "rce", "xss", "auth", "deseriali"])
        w = 3.0 if is_critical else 1.0
        total_weight += w
        if r.scores.verdict == 1:
            weighted_correct += w
    return _safe_div(weighted_correct, total_weight)


def c11_worst_category_floor(results: list[TaskResult]) -> float:
    """Minimum accuracy across all CWE categories — no blind spots allowed."""
    groups: dict[str, list[int]] = defaultdict(list)
    for r in _non_error_results(results):
        groups[r.task_category or "uncategorized"].append(r.scores.verdict)
    if not groups:
        return 0.0
    accs = [sum(v) / len(v) for v in groups.values() if v]
    return min(accs) if accs else 0.0


def c12_language_parity(results: list[TaskResult]) -> float:
    """1 - (max - min) accuracy gap across languages — consistent coverage."""
    groups: dict[str, list[int]] = defaultdict(list)
    for r in _non_error_results(results):
        groups[r.task_language].append(r.scores.verdict)
    if len(groups) < 2:
        return 1.0
    accs = [sum(v) / len(v) for v in groups.values() if v]
    return max(0.0, 1.0 - (max(accs) - min(accs)))


def c13_overconfident_miss_rate(results: list[TaskResult]) -> float:
    """Among missed vulns with FULL parse (confident answers), what % missed? (1 - rate)."""
    pos = _positive_results(results)
    full_parsed = [r for r in pos if r.parse_result.status == ParseStatus.FULL]
    if not full_parsed:
        return 0.0
    misses = sum(1 for r in full_parsed if r.scores.verdict == 0)
    return 1.0 - _safe_div(misses, len(full_parsed))


def c14_operational_error_rate(results: list[TaskResult]) -> float:
    """% of tasks that completed without crash/error (1 - error_rate)."""
    if not results:
        return 0.0
    return 1.0 - sum(1 for r in results if r.error) / len(results)


def c15_parse_reliability(results: list[TaskResult]) -> float:
    """% of tasks with parseable output (FULL or PARTIAL)."""
    valid = _non_error_results(results)
    if not valid:
        return 0.0
    parseable = sum(1 for r in valid if r.parse_result.status != ParseStatus.FAILED)
    return parseable / len(valid)


def c16_structured_output_rate(results: list[TaskResult]) -> float:
    """% of responses that fully comply with JSON schema."""
    valid = _non_error_results(results)
    if not valid:
        return 0.0
    full = sum(1 for r in valid if r.parse_result.status == ParseStatus.FULL)
    return full / len(valid)


def c17_location_accuracy_for_remediation(results: list[TaskResult]) -> float:
    """Location score — needed for triage teams to act on findings."""
    pos = [r for r in _positive_results(results) if r.scores.verdict == 1]
    if not pos:
        return 0.0
    return sum(r.scores.location for r in pos) / len(pos)


def c18_finding_actionability(results: list[TaskResult]) -> float:
    """% of TP detections with both CWE and location — fully actionable findings."""
    pos = [r for r in _positive_results(results) if r.scores.verdict == 1]
    if not pos:
        return 0.0
    actionable = sum(1 for r in pos if r.scores.cwe == 1 and r.scores.location == 1)
    return actionable / len(pos)


def c19_negative_predictive_value(results: list[TaskResult]) -> float:
    """Among 'not vulnerable' predictions, % that are actually clean."""
    valid = _non_error_results(results)
    not_vuln_preds = [r for r in valid if _verdict_pred(r) is False]
    if not not_vuln_preds:
        return 0.0
    true_neg = sum(1 for r in not_vuln_preds if r.task_type != TaskType.TRUE_POSITIVE)
    return true_neg / len(not_vuln_preds)


def c20_positive_predictive_value(results: list[TaskResult]) -> float:
    """Precision — among 'vulnerable' predictions, % that are real vulns."""
    valid = _non_error_results(results)
    vuln_preds = [r for r in valid if _verdict_pred(r) is True]
    if not vuln_preds:
        return 0.0
    true_pos = sum(1 for r in vuln_preds if r.task_type == TaskType.TRUE_POSITIVE)
    return true_pos / len(vuln_preds)


def c21_cost_per_task(results: list[TaskResult]) -> float:
    """Average cost per task — budget planning."""
    valid = _non_error_results(results)
    if not valid:
        return 0.0
    return sum(r.metrics.cost_usd for r in valid) / len(valid)


def c22_cost_per_true_positive(results: list[TaskResult]) -> float:
    """Cost per real detection — ROI metric."""
    valid = _non_error_results(results)
    total_cost = sum(r.metrics.cost_usd for r in valid)
    tp = sum(1 for r in valid if r.task_type == TaskType.TRUE_POSITIVE and r.scores.verdict == 1)
    return _safe_div(total_cost, tp, float("inf"))


def c23_budget_predictability(results: list[TaskResult]) -> float:
    """1 - CV of cost distribution — consistent spend is easier to budget."""
    valid = _non_error_results(results)
    if len(valid) < 2:
        return 0.0
    costs = [r.metrics.cost_usd for r in valid]
    mean = sum(costs) / len(costs)
    if mean == 0:
        return 1.0
    import statistics
    std = statistics.stdev(costs)
    cv = std / mean
    return max(0.0, 1.0 - min(cv, 2.0) / 2.0)


def c24_annual_projected_cost(results: list[TaskResult]) -> float:
    """Projected cost for 10K tasks/year (raw $, lower is better)."""
    return c21_cost_per_task(results) * 10000


def c25_compliance_report_readiness(results: list[TaskResult]) -> float:
    """% of findings with CWE + evidence + location — auditor-ready."""
    pos = [r for r in _positive_results(results) if r.scores.verdict == 1]
    if not pos:
        return 0.0
    ready = 0
    for r in pos:
        out = r.parse_result.output
        has_cwe = r.scores.cwe == 1
        has_loc = r.scores.location == 1
        has_evidence = out and out.evidence and out.evidence.source
        if has_cwe and has_loc and has_evidence:
            ready += 1
    return ready / len(pos)


def c26_reasoning_transparency(results: list[TaskResult]) -> float:
    """% of responses with reasoning field populated — explainability."""
    valid = _non_error_results(results)
    if not valid:
        return 0.0
    with_reasoning = sum(
        1 for r in valid
        if r.parse_result.output and r.parse_result.output.reasoning
    )
    return with_reasoning / len(valid)


def c27_cross_run_consistency(results: list[TaskResult]) -> float:
    """Placeholder — requires multi-seed comparison. Returns 0.5."""
    return 0.5


def c28_regression_risk(results: list[TaskResult]) -> float:
    """Placeholder — requires version comparison. Returns 0.5."""
    return 0.5


def c29_supply_chain_cwe_coverage(results: list[TaskResult]) -> float:
    """Performance on dependency/supply-chain related CWEs."""
    pos = _positive_results(results)
    supply_chain = [
        r for r in pos
        if any(kw in (r.task_category or "").lower()
               for kw in ["dependency", "supply", "package", "deserialization", "untrusted"])
    ]
    if not supply_chain:
        return d01_true_positive_rate(results)  # Fallback
    return sum(r.scores.verdict for r in supply_chain) / len(supply_chain)


def c30_authentication_bypass_detection(results: list[TaskResult]) -> float:
    """Performance on auth/authz CWEs specifically."""
    pos = _positive_results(results)
    auth = [
        r for r in pos
        if any(kw in (r.task_category or "").lower()
               for kw in ["auth", "session", "access_control", "privilege"])
    ]
    if not auth:
        return d01_true_positive_rate(results)
    return sum(r.scores.verdict for r in auth) / len(auth)


def c31_injection_detection_rate(results: list[TaskResult]) -> float:
    """Detection rate for injection class vulns (SQL, command, LDAP, etc)."""
    pos = _positive_results(results)
    injection = [
        r for r in pos
        if any(kw in (r.task_category or "").lower()
               for kw in ["injection", "sqli", "command", "ldap", "xpath"])
    ]
    if not injection:
        return d01_true_positive_rate(results)
    return sum(r.scores.verdict for r in injection) / len(injection)


def c32_xss_detection_rate(results: list[TaskResult]) -> float:
    """Detection rate for XSS vulns."""
    pos = _positive_results(results)
    xss = [r for r in pos if "xss" in (r.task_category or "").lower()
           or "cross_site" in (r.task_category or "").lower()]
    if not xss:
        return d01_true_positive_rate(results)
    return sum(r.scores.verdict for r in xss) / len(xss)


def c33_data_exposure_detection(results: list[TaskResult]) -> float:
    """Detection rate for data exposure/information disclosure."""
    pos = _positive_results(results)
    exposure = [
        r for r in pos
        if any(kw in (r.task_category or "").lower()
               for kw in ["exposure", "disclosure", "leak", "sensitive", "information"])
    ]
    if not exposure:
        return d01_true_positive_rate(results)
    return sum(r.scores.verdict for r in exposure) / len(exposure)


def c34_crypto_weakness_detection(results: list[TaskResult]) -> float:
    """Detection rate for crypto/random/hash weaknesses."""
    pos = _positive_results(results)
    crypto = [
        r for r in pos
        if any(kw in (r.task_category or "").lower()
               for kw in ["crypto", "random", "hash", "cipher", "key", "tls", "ssl"])
    ]
    if not crypto:
        return d01_true_positive_rate(results)
    return sum(r.scores.verdict for r in crypto) / len(crypto)


def c35_mean_time_to_detect(results: list[TaskResult]) -> float:
    """Average wall time per task — response latency for security ops."""
    valid = _non_error_results(results)
    if not valid:
        return 0.0
    avg_time = sum(r.metrics.wall_time_s for r in valid) / len(valid)
    # Normalize: <10s = 1.0, >120s = 0.0
    return max(0.0, 1.0 - min(avg_time / 120.0, 1.0))


def c36_throughput_for_scanning(results: list[TaskResult]) -> float:
    """Effective tasks/minute — can it keep up with CI/CD volume?"""
    valid = _non_error_results(results)
    if not valid:
        return 0.0
    total_time = sum(r.metrics.wall_time_s for r in valid)
    if total_time <= 0:
        return 0.0
    tpm = len(valid) / (total_time / 60.0)
    return min(tpm / 30.0, 1.0)  # Cap at 30 tasks/min = 1.0


def c37_incident_response_utility(results: list[TaskResult]) -> float:
    """Combined: high recall + fast response + actionable findings."""
    tpr = d01_true_positive_rate(results)
    speed = c35_mean_time_to_detect(results)
    actionable = c18_finding_actionability(results)
    return (tpr * 0.5 + speed * 0.2 + actionable * 0.3)


def c38_vendor_risk_assessment_utility(results: list[TaskResult]) -> float:
    """Cross-language consistency + CWE breadth — useful for assessing vendor code."""
    lang_parity = c12_language_parity(results)
    from seclens.roles.dimensions import d07_cwe_coverage_breadth
    breadth = d07_cwe_coverage_breadth(results)
    return (lang_parity * 0.5 + breadth * 0.5)


def c39_regulatory_mapping_accuracy(results: list[TaskResult]) -> float:
    """CWE accuracy — CWEs map to regulations (PCI-DSS, SOC2, HIPAA)."""
    return c08_cwe_classification_accuracy(results)


def c40_triage_noise_ratio(results: list[TaskResult]) -> float:
    """PPV — what % of alerts are worth investigating."""
    return c20_positive_predictive_value(results)


def c41_sla_compliance_rate(results: list[TaskResult]) -> float:
    """% of tasks completing within 60 seconds — SLA target."""
    valid = _non_error_results(results)
    if not valid:
        return 0.0
    within_sla = sum(1 for r in valid if r.metrics.wall_time_s <= 60)
    return within_sla / len(valid)


def c42_token_efficiency(results: list[TaskResult]) -> float:
    """Accuracy per 1K tokens consumed — efficiency of reasoning."""
    valid = _non_error_results(results)
    if not valid:
        return 0.0
    total_tokens = sum(r.metrics.total_tokens for r in valid)
    total_correct = sum(r.scores.verdict for r in valid)
    if total_tokens == 0:
        return 0.0
    return min((total_correct / (total_tokens / 1000)) * 10, 1.0)


def c43_multi_language_coverage(results: list[TaskResult]) -> float:
    """Number of distinct languages with >50% accuracy / total languages."""
    groups: dict[str, list[int]] = defaultdict(list)
    for r in _non_error_results(results):
        groups[r.task_language].append(r.scores.verdict)
    if not groups:
        return 0.0
    good = sum(1 for v in groups.values() if sum(v) / len(v) > 0.5)
    return good / len(groups)


def c44_patch_verification_accuracy(results: list[TaskResult]) -> float:
    """Accuracy on post-patch (negative) tasks — can it confirm fixes?"""
    post_patch = [r for r in results if r.task_type == TaskType.POST_PATCH]
    if not post_patch:
        return d02_true_negative_rate(results)
    return sum(r.scores.verdict for r in post_patch) / len(post_patch)


def c45_sast_fp_rejection(results: list[TaskResult]) -> float:
    """Accuracy on SAST false positive tasks — can it filter SAST noise?"""
    sast_fp = [r for r in results if r.task_type == TaskType.SAST_FALSE_POSITIVE]
    if not sast_fp:
        return d02_true_negative_rate(results)
    return sum(r.scores.verdict for r in sast_fp) / len(sast_fp)


def c46_board_reportable_score(results: list[TaskResult]) -> float:
    """Single number for board reporting: severity-weighted F1."""
    tpr = c10_severity_weighted_recall(results)
    ppv = c20_positive_predictive_value(results)
    if tpr + ppv == 0:
        return 0.0
    return 2 * tpr * ppv / (tpr + ppv)


def c47_risk_exposure_index(results: list[TaskResult]) -> float:
    """Composite: critical miss rate × overconfidence penalty. Higher = less risk."""
    critical_detect = c02_critical_vuln_detection_rate(results)
    overconf = c13_overconfident_miss_rate(results)
    return (critical_detect * 0.6 + overconf * 0.4)


def c48_defense_in_depth_contribution(results: list[TaskResult]) -> float:
    """How much does this model add if used alongside SAST? (unique TP detection)."""
    # Proxy: performance on tasks that are hardest (rare CWEs + multi-turn needed)
    return c09_zero_day_readiness(results)


def c49_model_stability_for_prod(results: list[TaskResult]) -> float:
    """Error rate + parse reliability combined — production readiness."""
    error = c14_operational_error_rate(results)
    parse = c15_parse_reliability(results)
    return (error * 0.5 + parse * 0.5)


def c50_overall_ciso_confidence(results: list[TaskResult]) -> float:
    """Composite CISO score: balanced accuracy + risk + reliability."""
    balanced = c05_balanced_accuracy(results)
    risk = c47_risk_exposure_index(results)
    reliability = c49_model_stability_for_prod(results)
    return (balanced * 0.4 + risk * 0.35 + reliability * 0.25)


CISO_DIMENSIONS: dict[int, tuple[str, callable]] = {
    1: ("Overall Detection Reliability", c01_overall_detection_reliability),
    2: ("Critical Vulnerability Detection Rate", c02_critical_vuln_detection_rate),
    3: ("Critical Vulnerability Miss Prevention", c03_false_negative_on_critical),
    4: ("False Alarm Suppression", c04_false_alarm_rate),
    5: ("Balanced Detection Accuracy", c05_balanced_accuracy),
    6: ("Overall MCC Score", c06_mcc_overall),
    7: ("Audit Trail Completeness", c07_audit_trail_completeness),
    8: ("CWE Classification Accuracy", c08_cwe_classification_accuracy),
    9: ("Zero-Day Readiness", c09_zero_day_readiness),
    10: ("Severity-Weighted Recall", c10_severity_weighted_recall),
    11: ("Worst-Category Floor", c11_worst_category_floor),
    12: ("Language Parity", c12_language_parity),
    13: ("Overconfident Miss Prevention", c13_overconfident_miss_rate),
    14: ("Operational Error Rate", c14_operational_error_rate),
    15: ("Parse Reliability", c15_parse_reliability),
    16: ("Structured Output Compliance", c16_structured_output_rate),
    17: ("Location Accuracy for Remediation", c17_location_accuracy_for_remediation),
    18: ("Finding Actionability", c18_finding_actionability),
    19: ("Negative Predictive Value", c19_negative_predictive_value),
    20: ("Positive Predictive Value (Precision)", c20_positive_predictive_value),
    21: ("Cost Per Task", c21_cost_per_task),
    22: ("Cost Per True Positive", c22_cost_per_true_positive),
    23: ("Budget Predictability", c23_budget_predictability),
    24: ("Annual Projected Cost", c24_annual_projected_cost),
    25: ("Compliance Report Readiness", c25_compliance_report_readiness),
    26: ("Reasoning Transparency", c26_reasoning_transparency),
    27: ("Cross-Run Consistency", c27_cross_run_consistency),
    28: ("Regression Risk", c28_regression_risk),
    29: ("Supply Chain CWE Coverage", c29_supply_chain_cwe_coverage),
    30: ("Authentication Bypass Detection", c30_authentication_bypass_detection),
    31: ("Injection Detection Rate", c31_injection_detection_rate),
    32: ("XSS Detection Rate", c32_xss_detection_rate),
    33: ("Data Exposure Detection", c33_data_exposure_detection),
    34: ("Cryptographic Weakness Detection", c34_crypto_weakness_detection),
    35: ("Mean Time to Detect", c35_mean_time_to_detect),
    36: ("Scanning Throughput", c36_throughput_for_scanning),
    37: ("Incident Response Utility", c37_incident_response_utility),
    38: ("Vendor Risk Assessment Utility", c38_vendor_risk_assessment_utility),
    39: ("Regulatory Mapping Accuracy", c39_regulatory_mapping_accuracy),
    40: ("Triage Noise Ratio", c40_triage_noise_ratio),
    41: ("SLA Compliance Rate", c41_sla_compliance_rate),
    42: ("Token Efficiency", c42_token_efficiency),
    43: ("Multi-Language Coverage", c43_multi_language_coverage),
    44: ("Patch Verification Accuracy", c44_patch_verification_accuracy),
    45: ("SAST False Positive Rejection", c45_sast_fp_rejection),
    46: ("Board-Reportable Score", c46_board_reportable_score),
    47: ("Risk Exposure Index", c47_risk_exposure_index),
    48: ("Defense-in-Depth Contribution", c48_defense_in_depth_contribution),
    49: ("Production Stability", c49_model_stability_for_prod),
    50: ("Overall CISO Confidence", c50_overall_ciso_confidence),
}
