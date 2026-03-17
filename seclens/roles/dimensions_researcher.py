"""Security Researcher — 50 dimensions.

Focus: Vulnerability reasoning depth, CWE taxonomy mastery, evidence quality,
novel pattern detection, cross-language analysis, research reproducibility.
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


def r01_vulnerability_detection_recall(results: list[TaskResult]) -> float:
    """True positive rate — can it find what's there?"""
    return d01_true_positive_rate(results)


def r02_vulnerability_detection_precision(results: list[TaskResult]) -> float:
    """Among 'vulnerable' predictions, % correct."""
    valid = _non_error_results(results)
    vuln_preds = [r for r in valid if _verdict_pred(r) is True]
    if not vuln_preds:
        return 0.0
    return sum(1 for r in vuln_preds if r.task_type == TaskType.TRUE_POSITIVE) / len(vuln_preds)


def r03_f1_score(results: list[TaskResult]) -> float:
    """Harmonic mean of precision and recall."""
    p = r02_vulnerability_detection_precision(results)
    r = r01_vulnerability_detection_recall(results)
    return _safe_div(2 * p * r, p + r)


def r04_mcc_normalized(results: list[TaskResult]) -> float:
    """MCC normalized to 0-1."""
    return (d05_verdict_mcc(results) + 1.0) / 2.0


def r05_cwe_exact_match_rate(results: list[TaskResult]) -> float:
    """Exact CWE ID match among correctly detected vulns."""
    pos = [r for r in _positive_results(results) if r.scores.verdict == 1]
    if not pos:
        return 0.0
    return sum(r.scores.cwe for r in pos) / len(pos)


def r06_cwe_coverage_breadth(results: list[TaskResult]) -> float:
    """% of distinct CWE categories where model gets >=1 correct CWE."""
    pos = _positive_results(results)
    groups: dict[str, list[int]] = defaultdict(list)
    for r in pos:
        groups[r.task_category or "unknown"].append(r.scores.cwe)
    if not groups:
        return 0.0
    covered = sum(1 for v in groups.values() if any(s > 0 for s in v))
    return covered / len(groups)


def r07_rare_cwe_detection(results: list[TaskResult]) -> float:
    """Verdict accuracy on rare CWEs (<=3 tasks in dataset)."""
    pos = _positive_results(results)
    counts: dict[str, int] = defaultdict(int)
    for r in pos:
        counts[r.task_category or "unknown"] += 1
    rare = [r for r in pos if counts.get(r.task_category or "unknown", 0) <= 3]
    if not rare:
        return 0.0
    return sum(r.scores.verdict for r in rare) / len(rare)


def r08_rare_cwe_identification(results: list[TaskResult]) -> float:
    """CWE match accuracy on rare CWEs."""
    pos = _positive_results(results)
    counts: dict[str, int] = defaultdict(int)
    for r in pos:
        counts[r.task_category or "unknown"] += 1
    rare = [r for r in pos if counts.get(r.task_category or "unknown", 0) <= 3 and r.scores.verdict == 1]
    if not rare:
        return 0.0
    return sum(r.scores.cwe for r in rare) / len(rare)


def r09_cross_language_consistency(results: list[TaskResult]) -> float:
    """1 - StdDev of CWE accuracy across languages."""
    pos = [r for r in _positive_results(results) if r.scores.verdict == 1]
    lang_scores: dict[str, list[int]] = defaultdict(list)
    for r in pos:
        lang_scores[r.task_language].append(r.scores.cwe)
    if len(lang_scores) < 2:
        return 1.0
    accs = [sum(s) / len(s) for s in lang_scores.values() if s]
    if len(accs) < 2:
        return 1.0
    return max(0.0, 1.0 - statistics.stdev(accs))


def r10_cwe_confusion_quality(results: list[TaskResult]) -> float:
    """Among wrong CWE predictions, 1 - confusion rate."""
    pos = [r for r in _positive_results(results) if r.scores.verdict == 1]
    has_pred = [r for r in pos if r.parse_result.output and r.parse_result.output.cwe]
    if not has_pred:
        return 0.0
    wrong = sum(1 for r in has_pred if r.scores.cwe == 0)
    return 1.0 - _safe_div(wrong, len(has_pred))


def r11_location_accuracy(results: list[TaskResult]) -> float:
    """Location score (IoU > 0.5) among correct TP verdicts."""
    pos = [r for r in _positive_results(results) if r.scores.verdict == 1]
    if not pos:
        return 0.0
    return sum(r.scores.location for r in pos) / len(pos)


def r12_file_identification_rate(results: list[TaskResult]) -> float:
    """% of correct TPs with location attempted (proxy for file accuracy)."""
    pos = [r for r in _positive_results(results) if r.scores.verdict == 1]
    if not pos:
        return 0.0
    attempted = sum(1 for r in pos if r.parse_result.output and r.parse_result.output.location)
    return attempted / len(pos)


def r13_mean_iou_estimate(results: list[TaskResult]) -> float:
    """Estimated mean IoU: location=1 → 0.75, location=0 → 0.1."""
    pos = [r for r in _positive_results(results) if r.scores.verdict == 1]
    if not pos:
        return 0.0
    ious = [0.75 if r.scores.location == 1 else 0.1 for r in pos]
    return sum(ious) / len(ious)


def r14_pinpoint_rate(results: list[TaskResult]) -> float:
    """Same as location accuracy (our best approximation)."""
    return r11_location_accuracy(results)


def r15_over_scope_prevention(results: list[TaskResult]) -> float:
    """1 - (location-attempted but wrong / total attempted)."""
    pos = [r for r in _positive_results(results) if r.scores.verdict == 1]
    attempted = [r for r in pos if r.parse_result.output and r.parse_result.output.location]
    if not attempted:
        return 1.0
    wrong = sum(1 for r in attempted if r.scores.location == 0)
    return 1.0 - _safe_div(wrong, len(attempted))


def r16_evidence_completeness(results: list[TaskResult]) -> float:
    """% with full evidence chain (source + sink + flow)."""
    valid = _non_error_results(results)
    if not valid:
        return 0.0
    complete = 0
    for r in valid:
        out = r.parse_result.output
        if out and out.evidence and out.evidence.source and out.evidence.sink and out.evidence.flow:
            complete += 1
    return complete / len(valid)


def r17_source_identification_rate(results: list[TaskResult]) -> float:
    """% of TP detections with source identified."""
    pos = [r for r in _positive_results(results) if r.scores.verdict == 1]
    if not pos:
        return 0.0
    return sum(1 for r in pos if r.parse_result.output and r.parse_result.output.evidence
               and r.parse_result.output.evidence.source) / len(pos)


def r18_sink_identification_rate(results: list[TaskResult]) -> float:
    """% of TP detections with sink identified."""
    pos = [r for r in _positive_results(results) if r.scores.verdict == 1]
    if not pos:
        return 0.0
    return sum(1 for r in pos if r.parse_result.output and r.parse_result.output.evidence
               and r.parse_result.output.evidence.sink) / len(pos)


def r19_data_flow_completeness(results: list[TaskResult]) -> float:
    """% of TP detections with non-empty flow chain."""
    pos = [r for r in _positive_results(results) if r.scores.verdict == 1]
    if not pos:
        return 0.0
    return sum(1 for r in pos if r.parse_result.output and r.parse_result.output.evidence
               and r.parse_result.output.evidence.flow and len(r.parse_result.output.evidence.flow) > 0) / len(pos)


def r20_reasoning_presence(results: list[TaskResult]) -> float:
    """% of responses with reasoning field."""
    valid = _non_error_results(results)
    if not valid:
        return 0.0
    return sum(1 for r in valid if r.parse_result.output and r.parse_result.output.reasoning) / len(valid)


def r21_reasoning_length_median(results: list[TaskResult]) -> float:
    """Median reasoning length in chars (raw)."""
    lengths = []
    for r in _non_error_results(results):
        out = r.parse_result.output
        if out and out.reasoning:
            lengths.append(len(out.reasoning))
    return float(statistics.median(lengths)) if lengths else 0.0


def r22_reasoning_with_correct_verdict(results: list[TaskResult]) -> float:
    """% of tasks with reasoning AND correct verdict — coherent analysis."""
    valid = _non_error_results(results)
    if not valid:
        return 0.0
    return sum(1 for r in valid if r.scores.verdict == 1
               and r.parse_result.output and r.parse_result.output.reasoning) / len(valid)


def r23_false_positive_reasoning_quality(results: list[TaskResult]) -> float:
    """Among FPs, % with reasoning — at least the mistake is explained."""
    neg = _negative_results(results)
    fps = [r for r in neg if _verdict_pred(r) is True]
    if not fps:
        return 1.0
    return sum(1 for r in fps if r.parse_result.output and r.parse_result.output.reasoning) / len(fps)


def r24_injection_class_mastery(results: list[TaskResult]) -> float:
    """CWE accuracy on injection-class vulns."""
    pos = _positive_results(results)
    injection = [r for r in pos if any(kw in (r.task_category or "").lower()
                 for kw in ["injection", "sqli", "command", "ldap"]) and r.scores.verdict == 1]
    if not injection:
        return 0.0
    return sum(r.scores.cwe for r in injection) / len(injection)


def r25_xss_class_mastery(results: list[TaskResult]) -> float:
    """CWE accuracy on XSS vulns."""
    pos = _positive_results(results)
    xss = [r for r in pos if "xss" in (r.task_category or "").lower() and r.scores.verdict == 1]
    if not xss:
        return d01_true_positive_rate(results)
    return sum(r.scores.cwe for r in xss) / len(xss)


def r26_auth_class_mastery(results: list[TaskResult]) -> float:
    """CWE accuracy on auth/access control vulns."""
    pos = _positive_results(results)
    auth = [r for r in pos if any(kw in (r.task_category or "").lower()
            for kw in ["auth", "access", "privilege"]) and r.scores.verdict == 1]
    if not auth:
        return d01_true_positive_rate(results)
    return sum(r.scores.cwe for r in auth) / len(auth)


def r27_crypto_class_mastery(results: list[TaskResult]) -> float:
    """CWE accuracy on crypto vulns."""
    pos = _positive_results(results)
    crypto = [r for r in pos if any(kw in (r.task_category or "").lower()
              for kw in ["crypto", "random", "hash", "cipher"]) and r.scores.verdict == 1]
    if not crypto:
        return d01_true_positive_rate(results)
    return sum(r.scores.cwe for r in crypto) / len(crypto)


def r28_deserialization_mastery(results: list[TaskResult]) -> float:
    """Detection rate on deserialization vulns."""
    pos = _positive_results(results)
    deser = [r for r in pos if "deseriali" in (r.task_category or "").lower()]
    if not deser:
        return d01_true_positive_rate(results)
    return sum(r.scores.verdict for r in deser) / len(deser)


def r29_worst_cwe_category(results: list[TaskResult]) -> float:
    """Minimum accuracy across CWE categories — blind spot indicator."""
    groups: dict[str, list[int]] = defaultdict(list)
    for r in _non_error_results(results):
        groups[r.task_category or "uncategorized"].append(r.scores.verdict)
    if not groups:
        return 0.0
    return min(sum(v) / len(v) for v in groups.values() if v)


def r30_best_cwe_category(results: list[TaskResult]) -> float:
    """Maximum accuracy across CWE categories — peak capability."""
    groups: dict[str, list[int]] = defaultdict(list)
    for r in _non_error_results(results):
        groups[r.task_category or "uncategorized"].append(r.scores.verdict)
    if not groups:
        return 0.0
    return max(sum(v) / len(v) for v in groups.values() if v)


def r31_category_variance(results: list[TaskResult]) -> float:
    """1 - StdDev of accuracy across CWE categories (lower variance = better)."""
    groups: dict[str, list[int]] = defaultdict(list)
    for r in _non_error_results(results):
        groups[r.task_category or "uncategorized"].append(r.scores.verdict)
    accs = [sum(v) / len(v) for v in groups.values() if v]
    if len(accs) < 2:
        return 1.0
    return max(0.0, 1.0 - statistics.stdev(accs))


def r32_python_accuracy(results: list[TaskResult]) -> float:
    """Accuracy specifically on Python tasks."""
    py = [r for r in _non_error_results(results) if r.task_language.lower() == "python"]
    if not py:
        return 0.0
    return sum(r.scores.verdict for r in py) / len(py)


def r33_javascript_accuracy(results: list[TaskResult]) -> float:
    """Accuracy on JavaScript/TypeScript tasks."""
    js = [r for r in _non_error_results(results) if r.task_language.lower() in ("javascript", "typescript", "js", "ts")]
    if not js:
        return 0.0
    return sum(r.scores.verdict for r in js) / len(js)


def r34_java_accuracy(results: list[TaskResult]) -> float:
    """Accuracy on Java tasks."""
    java = [r for r in _non_error_results(results) if r.task_language.lower() == "java"]
    if not java:
        return 0.0
    return sum(r.scores.verdict for r in java) / len(java)


def r35_c_cpp_accuracy(results: list[TaskResult]) -> float:
    """Accuracy on C/C++ tasks."""
    c = [r for r in _non_error_results(results) if r.task_language.lower() in ("c", "c++", "cpp")]
    if not c:
        return 0.0
    return sum(r.scores.verdict for r in c) / len(c)


def r36_go_accuracy(results: list[TaskResult]) -> float:
    """Accuracy on Go tasks."""
    go = [r for r in _non_error_results(results) if r.task_language.lower() in ("go", "golang")]
    if not go:
        return 0.0
    return sum(r.scores.verdict for r in go) / len(go)


def r37_language_gap(results: list[TaskResult]) -> float:
    """1 - (best language - worst language accuracy gap)."""
    groups: dict[str, list[int]] = defaultdict(list)
    for r in _non_error_results(results):
        groups[r.task_language].append(r.scores.verdict)
    if len(groups) < 2:
        return 1.0
    accs = [sum(v) / len(v) for v in groups.values() if v]
    return max(0.0, 1.0 - (max(accs) - min(accs)))


def r38_post_patch_discrimination(results: list[TaskResult]) -> float:
    """Can it tell patched from unpatched? Accuracy on post-patch tasks."""
    pp = [r for r in results if r.task_type == TaskType.POST_PATCH]
    if not pp:
        return d02_true_negative_rate(results)
    return sum(r.scores.verdict for r in pp) / len(pp)


def r39_sast_fp_discrimination(results: list[TaskResult]) -> float:
    """Can it identify SAST false positives?"""
    sast = [r for r in results if r.task_type == TaskType.SAST_FALSE_POSITIVE]
    if not sast:
        return d02_true_negative_rate(results)
    return sum(r.scores.verdict for r in sast) / len(sast)


def r40_negative_task_accuracy(results: list[TaskResult]) -> float:
    """Overall accuracy on negative tasks (specificity)."""
    return d02_true_negative_rate(results)


def r41_complete_finding_rate(results: list[TaskResult]) -> float:
    """% of TP tasks with all 3 points — perfect analysis."""
    pos = _positive_results(results)
    if not pos:
        return 0.0
    return sum(1 for r in pos if r.scores.earned == 3) / len(pos)


def r42_tool_use_for_deep_analysis(results: list[TaskResult]) -> float:
    """Multi-turn accuracy — does more investigation yield better results?"""
    multi = [r for r in _non_error_results(results) if r.metrics.turns > 1]
    if not multi:
        return 0.0
    return sum(r.scores.verdict for r in multi) / len(multi)


def r43_novel_pattern_detection(results: list[TaskResult]) -> float:
    """Performance on rare CWEs — proxy for novel vulnerability patterns."""
    return r07_rare_cwe_detection(results)


def r44_graceful_degradation(results: list[TaskResult]) -> float:
    """1 - |common_acc - rare_acc| — consistent regardless of frequency."""
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


def r45_parse_success_rate(results: list[TaskResult]) -> float:
    """% FULL parse status — can the model follow instructions?"""
    valid = _non_error_results(results)
    if not valid:
        return 0.0
    return sum(1 for r in valid if r.parse_result.status == ParseStatus.FULL) / len(valid)


def r46_error_rate(results: list[TaskResult]) -> float:
    """1 - error_rate."""
    if not results:
        return 0.0
    return 1.0 - sum(1 for r in results if r.error) / len(results)


def r47_reproducibility_proxy(results: list[TaskResult]) -> float:
    """Placeholder — requires multi-seed runs. Returns 0.5."""
    return 0.5


def r48_prompt_robustness(results: list[TaskResult]) -> float:
    """Placeholder — requires multi-preset runs. Returns 0.5."""
    return 0.5


def r49_research_utility_index(results: list[TaskResult]) -> float:
    """Composite: CWE depth × evidence quality × rare CWE performance."""
    cwe = r05_cwe_exact_match_rate(results)
    evidence = r16_evidence_completeness(results)
    rare = r07_rare_cwe_detection(results)
    return (cwe * 0.4 + evidence * 0.3 + rare * 0.3)


def r50_overall_researcher_score(results: list[TaskResult]) -> float:
    """Master researcher score: knowledge depth, reasoning, coverage."""
    detection = r03_f1_score(results)
    cwe = r05_cwe_exact_match_rate(results)
    evidence = r16_evidence_completeness(results)
    breadth = r06_cwe_coverage_breadth(results)
    location = r11_location_accuracy(results)
    return (detection * 0.25 + cwe * 0.25 + evidence * 0.2 + breadth * 0.15 + location * 0.15)


RESEARCHER_DIMENSIONS: dict[int, tuple[str, callable]] = {
    1: ("Vulnerability Detection Recall", r01_vulnerability_detection_recall),
    2: ("Vulnerability Detection Precision", r02_vulnerability_detection_precision),
    3: ("F1 Score", r03_f1_score),
    4: ("MCC (Normalized)", r04_mcc_normalized),
    5: ("CWE Exact Match Rate", r05_cwe_exact_match_rate),
    6: ("CWE Coverage Breadth", r06_cwe_coverage_breadth),
    7: ("Rare CWE Detection", r07_rare_cwe_detection),
    8: ("Rare CWE Identification", r08_rare_cwe_identification),
    9: ("Cross-Language CWE Consistency", r09_cross_language_consistency),
    10: ("CWE Confusion Quality", r10_cwe_confusion_quality),
    11: ("Location Accuracy (IoU>0.5)", r11_location_accuracy),
    12: ("File Identification Rate", r12_file_identification_rate),
    13: ("Mean IoU Estimate", r13_mean_iou_estimate),
    14: ("Pinpoint Rate", r14_pinpoint_rate),
    15: ("Over-Scope Prevention", r15_over_scope_prevention),
    16: ("Evidence Completeness", r16_evidence_completeness),
    17: ("Source Identification Rate", r17_source_identification_rate),
    18: ("Sink Identification Rate", r18_sink_identification_rate),
    19: ("Data Flow Completeness", r19_data_flow_completeness),
    20: ("Reasoning Presence", r20_reasoning_presence),
    21: ("Reasoning Length (median chars)", r21_reasoning_length_median),
    22: ("Reasoning + Correct Verdict", r22_reasoning_with_correct_verdict),
    23: ("FP Reasoning Quality", r23_false_positive_reasoning_quality),
    24: ("Injection Class Mastery", r24_injection_class_mastery),
    25: ("XSS Class Mastery", r25_xss_class_mastery),
    26: ("Auth Class Mastery", r26_auth_class_mastery),
    27: ("Crypto Class Mastery", r27_crypto_class_mastery),
    28: ("Deserialization Mastery", r28_deserialization_mastery),
    29: ("Worst CWE Category", r29_worst_cwe_category),
    30: ("Best CWE Category", r30_best_cwe_category),
    31: ("Category Variance (inverted)", r31_category_variance),
    32: ("Python Accuracy", r32_python_accuracy),
    33: ("JavaScript Accuracy", r33_javascript_accuracy),
    34: ("Java Accuracy", r34_java_accuracy),
    35: ("C/C++ Accuracy", r35_c_cpp_accuracy),
    36: ("Go Accuracy", r36_go_accuracy),
    37: ("Language Gap (inverted)", r37_language_gap),
    38: ("Post-Patch Discrimination", r38_post_patch_discrimination),
    39: ("SAST FP Discrimination", r39_sast_fp_discrimination),
    40: ("Negative Task Accuracy", r40_negative_task_accuracy),
    41: ("Complete Finding Rate (3/3)", r41_complete_finding_rate),
    42: ("Tool-Use for Deep Analysis", r42_tool_use_for_deep_analysis),
    43: ("Novel Pattern Detection", r43_novel_pattern_detection),
    44: ("Graceful Degradation", r44_graceful_degradation),
    45: ("Parse Success Rate", r45_parse_success_rate),
    46: ("Error Rate (inverted)", r46_error_rate),
    47: ("Reproducibility Proxy", r47_reproducibility_proxy),
    48: ("Prompt Robustness", r48_prompt_robustness),
    49: ("Research Utility Index", r49_research_utility_index),
    50: ("Overall Researcher Score", r50_overall_researcher_score),
}
