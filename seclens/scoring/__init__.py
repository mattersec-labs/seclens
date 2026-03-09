"""Scoring — per-task grading and aggregate metrics."""

from seclens.scoring.aggregate import compute_aggregate
from seclens.scoring.grader import score_task

__all__ = ["compute_aggregate", "score_task"]
