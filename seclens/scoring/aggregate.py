"""Aggregate metrics — leaderboard score, MCC, bootstrap CIs."""

from __future__ import annotations

import math

import numpy as np

from seclens.schemas.report import (
    AggregateReport,
    ConfidenceInterval,
    CoreMetrics,
    CostMetrics,
)
from seclens.schemas.scoring import RunMetadata, TaskResult


def compute_aggregate(results: list[TaskResult], run_metadata: RunMetadata) -> AggregateReport:
    """Compute aggregate metrics from a list of task results.

    Args:
        results: All task results from a run.
        run_metadata: Metadata for the run.

    Returns:
        Full aggregate report with bootstrap CIs.
    """
    seed = run_metadata.seed

    # Separate results
    errors = [r for r in results if r.error is not None]
    parse_failures = [r for r in results if r.parse_result.output is None and r.error is None]
    scored = [r for r in results if r.error is None]

    # Leaderboard score
    leaderboard = _bootstrap_ci(
        [r.scores.earned for r in scored],
        [r.scores.max_task_points for r in scored],
        _weighted_ratio,
        seed,
    )

    # Core metrics
    core = _compute_core_metrics(scored, seed)

    # Cost metrics
    cost = _compute_cost_metrics(scored, core.verdict_mcc.mean, leaderboard.mean)

    # Breakdowns
    by_category = _compute_breakdowns(scored, lambda r: r.task_category or "uncategorized", seed)
    by_language = _compute_breakdowns(scored, lambda r: r.task_language, seed)

    return AggregateReport(
        leaderboard_score=leaderboard,
        core=core,
        cost=cost,
        by_category=by_category,
        by_language=by_language,
        run_metadata=run_metadata,
        task_count=len(results),
        parse_failures=len(parse_failures),
        errors=len(errors),
    )


def _compute_core_metrics(results: list[TaskResult], seed: int) -> CoreMetrics:
    """Compute verdict MCC, CWE accuracy, and location accuracy with CIs."""
    # Verdict MCC
    verdicts_pred = []
    verdicts_gt = []
    for r in results:
        if r.parse_result.output is not None and r.parse_result.output.vulnerable is not None:
            verdicts_pred.append(int(r.parse_result.output.vulnerable))
        else:
            verdicts_pred.append(0)
        # Ground truth from task_type
        verdicts_gt.append(1 if r.task_type == "true_positive" else 0)

    mcc_ci = _bootstrap_ci(verdicts_pred, verdicts_gt, _mcc, seed)

    # CWE accuracy: among positive tasks with correct verdict
    correct_positives = [
        r for r in results
        if r.task_type == "true_positive" and r.scores.verdict == 1
    ]
    cwe_scores = [r.scores.cwe for r in correct_positives]
    cwe_ci = _bootstrap_ci(cwe_scores, None, _mean_ratio, seed) if cwe_scores else _zero_ci()

    # Location accuracy: mean IoU among positive tasks with correct verdict
    loc_scores = [r.scores.location for r in correct_positives]
    loc_ci = _bootstrap_ci(loc_scores, None, _mean_ratio, seed) if loc_scores else _zero_ci()

    return CoreMetrics(
        verdict_mcc=mcc_ci,
        cwe_accuracy=cwe_ci,
        location_accuracy=loc_ci,
        task_count=len(results),
    )


def _compute_cost_metrics(
    results: list[TaskResult], mcc: float, leaderboard: float
) -> CostMetrics:
    """Compute cost and token usage metrics."""
    total_cost = sum(r.metrics.cost_usd for r in results)
    total_input = sum(r.metrics.input_tokens for r in results)
    total_output = sum(r.metrics.output_tokens for r in results)
    total_tokens = sum(r.metrics.total_tokens for r in results)
    n = len(results) or 1

    return CostMetrics(
        total_cost_usd=total_cost,
        avg_cost_per_task=total_cost / n,
        total_input_tokens=total_input,
        total_output_tokens=total_output,
        total_tokens=total_tokens,
        mcc_per_dollar=mcc / total_cost if total_cost > 0 else None,
        score_per_1k_tokens=leaderboard / (total_tokens / 1000) if total_tokens > 0 else None,
    )


def _compute_breakdowns(
    results: list[TaskResult],
    key_fn: callable,
    seed: int,
) -> dict[str, CoreMetrics]:
    """Compute per-group core metrics."""
    groups: dict[str, list[TaskResult]] = {}
    for r in results:
        k = key_fn(r)
        groups.setdefault(k, []).append(r)

    return {k: _compute_core_metrics(v, seed) for k, v in groups.items()}


def _bootstrap_ci(
    values: list,
    weights: list | None,
    metric_fn: callable,
    seed: int,
    n_iterations: int = 1000,
) -> ConfidenceInterval:
    """Compute bootstrap confidence interval for a metric.

    Args:
        values: Primary values (predictions, scores, etc.).
        weights: Optional secondary values (ground truth, max points, etc.).
        metric_fn: Function(values, weights) -> float.
        seed: Random seed for reproducibility.
        n_iterations: Number of bootstrap iterations.
    """
    if not values:
        return _zero_ci()

    point_estimate = metric_fn(values, weights)
    rng = np.random.default_rng(seed)
    n = len(values)

    bootstrap_estimates = []
    for _ in range(n_iterations):
        indices = rng.integers(0, n, size=n)
        sampled_values = [values[i] for i in indices]
        sampled_weights = [weights[i] for i in indices] if weights is not None else None
        estimate = metric_fn(sampled_values, sampled_weights)
        bootstrap_estimates.append(estimate)

    bootstrap_arr = np.array(bootstrap_estimates)
    stderr = float(np.std(bootstrap_arr, ddof=1))
    ci_lower = float(np.percentile(bootstrap_arr, 2.5))
    ci_upper = float(np.percentile(bootstrap_arr, 97.5))

    return ConfidenceInterval(
        mean=point_estimate,
        stderr=stderr,
        ci_lower=ci_lower,
        ci_upper=ci_upper,
    )


def _zero_ci() -> ConfidenceInterval:
    """Return a zero confidence interval."""
    return ConfidenceInterval(mean=0.0, stderr=0.0, ci_lower=0.0, ci_upper=0.0)


def _weighted_ratio(values: list, weights: list) -> float:
    """Compute sum(values) / sum(weights)."""
    total_w = sum(weights)
    if total_w == 0:
        return 0.0
    return sum(values) / total_w


def _mean_ratio(values: list, _weights: list | None) -> float:
    """Compute mean of values."""
    if not values:
        return 0.0
    return sum(values) / len(values)


def _mcc(predictions: list, ground_truth: list) -> float:
    """Compute Matthews Correlation Coefficient."""
    tp = fp = tn = fn = 0
    for pred, gt in zip(predictions, ground_truth):
        if pred == 1 and gt == 1:
            tp += 1
        elif pred == 1 and gt == 0:
            fp += 1
        elif pred == 0 and gt == 0:
            tn += 1
        else:
            fn += 1

    numerator = tp * tn - fp * fn
    denominator = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))

    if denominator == 0:
        return 0.0
    return numerator / denominator
