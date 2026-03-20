"""Model report generation — pre-computes all metrics for a single evaluation run."""

from __future__ import annotations

from collections.abc import Callable

from collections import defaultdict
from datetime import datetime, timezone

import seclens
from seclens.roles.dimensions import compute_all_dimensions
from seclens.schemas.model_report import GroupBreakdown, ModelReport
from seclens.schemas.scoring import RunMetadata, TaskResult
from seclens.schemas.task import TaskType
from seclens.scoring.aggregate import compute_aggregate


def generate_model_report(
    results: list[TaskResult],
    run_metadata: RunMetadata,
    dataset: str = "",
) -> ModelReport:
    """Generate a complete pre-computed model report.

    Args:
        results: All task results from a run.
        run_metadata: Metadata for the run.
        dataset: Dataset identifier string.

    Returns:
        ModelReport with aggregate scores, 35 dimensions, and breakdowns.
    """
    # Existing aggregate
    aggregate = compute_aggregate(results, run_metadata)

    # All 35 dimensions
    dimensions = compute_all_dimensions(results)
    # Round to 4 decimal places
    dimensions = {k: round(v, 4) for k, v in dimensions.items()}

    # Split results by task type
    positive_results = [r for r in results if r.task_type == TaskType.TRUE_POSITIVE]
    negative_results = [r for r in results if r.task_type != TaskType.TRUE_POSITIVE]

    # Per-category breakdowns (true_positive only)
    by_category = _compute_group_breakdowns(
        positive_results, lambda r: r.task_category or "uncategorized",
    )

    # Per-language breakdowns (true_positive only)
    by_language = _compute_group_breakdowns(
        positive_results, lambda r: r.task_language,
    )

    # Post-patch / negative task breakdowns (grouped by category)
    by_postpatch = _compute_group_breakdowns(
        negative_results, lambda r: r.task_category or "uncategorized",
    )

    errors = sum(1 for r in results if r.error is not None)
    parse_failures = sum(1 for r in results if r.parse_result.output is None and r.error is None)

    return ModelReport(
        run_metadata=run_metadata,
        model=run_metadata.model,
        dataset=dataset,
        total_tasks=len(results),
        errors=errors,
        parse_failures=parse_failures,
        leaderboard_score=aggregate.leaderboard_score,
        core=aggregate.core,
        cost=aggregate.cost,
        dimensions=dimensions,
        by_category=by_category,
        by_language=by_language,
        by_postpatch=by_postpatch,
        generated_at=datetime.now(timezone.utc).isoformat(),
        seclens_version=seclens.__version__,
    )


def _compute_group_breakdowns(
    results: list[TaskResult],
    key_fn: Callable,
) -> dict[str, GroupBreakdown]:
    """Compute per-group breakdowns with full metric set."""
    groups: dict[str, list[TaskResult]] = defaultdict(list)
    for r in results:
        if r.error is None:
            groups[key_fn(r)].append(r)

    return {name: _breakdown(group) for name, group in groups.items()}


def _breakdown(results: list[TaskResult]) -> GroupBreakdown:
    """Compute metrics for a single group."""
    positive = [r for r in results if r.task_type == TaskType.TRUE_POSITIVE]
    negative = [r for r in results if r.task_type != TaskType.TRUE_POSITIVE]

    # Verdict accuracy: correct verdicts across ALL tasks in group
    verdict_accuracy = sum(r.scores.verdict for r in results) / len(results) if results else 0.0

    # Recall: correct positive verdicts / total positive
    recall = sum(r.scores.verdict for r in positive) / len(positive) if positive else 0.0

    # Precision: TP / (TP + FP)
    tp = sum(1 for r in positive if r.scores.verdict == 1)
    fp = sum(
        1 for r in negative
        if r.parse_result.output is not None and r.parse_result.output.vulnerable is True
    )
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0

    # F1
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

    # CWE accuracy among correct positives
    correct_pos = [r for r in positive if r.scores.verdict == 1]
    cwe_accuracy = (
        sum(r.scores.cwe for r in correct_pos) / len(correct_pos)
        if correct_pos else 0.0
    )

    # Mean location IoU among correct positives
    mean_iou = (
        sum(r.scores.location for r in correct_pos) / len(correct_pos)
        if correct_pos else 0.0
    )

    # Actionable finding rate
    actionable = sum(
        1 for r in positive
        if r.scores.verdict == 1 and r.scores.cwe == 1 and r.scores.location > 0
    )
    actionable_rate = actionable / len(positive) if positive else 0.0

    # Cost and tokens
    avg_cost = sum(r.metrics.cost_usd for r in results) / len(results) if results else 0.0
    avg_tokens = sum(r.metrics.total_tokens for r in results) / len(results) if results else 0.0

    return GroupBreakdown(
        task_count=len(results),
        positive_count=len(positive),
        negative_count=len(negative),
        verdict_accuracy=round(verdict_accuracy, 4),
        recall=round(recall, 4),
        precision=round(precision, 4),
        f1=round(f1, 4),
        cwe_accuracy=round(cwe_accuracy, 4),
        mean_location_iou=round(mean_iou, 4),
        actionable_rate=round(actionable_rate, 4),
        avg_cost=round(avg_cost, 6),
        avg_tokens=round(avg_tokens, 1),
    )
