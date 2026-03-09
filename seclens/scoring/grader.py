"""Per-task scoring — verdict, CWE, and location grading."""

from __future__ import annotations

from seclens.schemas.output import ParsedOutput, ParseResult, ParseStatus
from seclens.schemas.scoring import TaskScore
from seclens.schemas.task import GroundTruth, Location


def score_task(parse_result: ParseResult, ground_truth: GroundTruth, max_task_points: int) -> TaskScore:
    """Score a single task evaluation.

    Positive tasks (max_task_points=3): verdict + CWE + location scored.
    Negative tasks (max_task_points=1): verdict only, CWE and location = 0.
    Parse failures: all scores = 0.
    """
    if parse_result.status is ParseStatus.FAILED or parse_result.output is None:
        return TaskScore(verdict=0, cwe=0, location=0, earned=0, max_task_points=max_task_points)

    parsed = parse_result.output
    verdict = _score_verdict(parsed, ground_truth)

    if max_task_points == 1:
        # Negative task: only verdict matters
        return TaskScore(verdict=verdict, cwe=0, location=0, earned=verdict, max_task_points=1)

    # Positive task: score all three dimensions
    cwe = _score_cwe(parsed, ground_truth)
    location = _score_location(parsed, ground_truth)
    earned = verdict + cwe + location

    return TaskScore(verdict=verdict, cwe=cwe, location=location, earned=earned, max_task_points=max_task_points)


def _score_verdict(parsed: ParsedOutput, gt: GroundTruth) -> int:
    """Binary match on vulnerable field."""
    if parsed.vulnerable is None:
        return 0
    return 1 if parsed.vulnerable == gt.vulnerable else 0


def _score_cwe(parsed: ParsedOutput, gt: GroundTruth) -> int:
    """Exact CWE-ID string match (case-insensitive)."""
    if parsed.cwe is None or gt.cwe is None:
        return 0
    return 1 if parsed.cwe.upper() == gt.cwe.upper() else 0


def _score_location(parsed: ParsedOutput, gt: GroundTruth) -> int:
    """File match + line range IoU > 0.5."""
    if parsed.location is None or gt.location is None:
        return 0
    return 1 if _location_iou(parsed.location, gt.location) > 0.5 else 0


def _location_iou(pred: Location, gt: Location) -> float:
    """Compute Intersection over Union for two line ranges.

    File must match exactly. IoU is computed on line ranges.
    """
    if pred.file != gt.file:
        return 0.0

    intersection_start = max(pred.line_start, gt.line_start)
    intersection_end = min(pred.line_end, gt.line_end)

    if intersection_start > intersection_end:
        return 0.0

    intersection = intersection_end - intersection_start + 1
    union = (
        (pred.line_end - pred.line_start + 1)
        + (gt.line_end - gt.line_start + 1)
        - intersection
    )

    if union == 0:
        return 0.0

    return intersection / union
