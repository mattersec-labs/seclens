"""Model report schema — pre-computed evaluation report for a single run."""

from __future__ import annotations

from pydantic import BaseModel

from seclens.schemas.report import ConfidenceInterval, CoreMetrics, CostMetrics
from seclens.schemas.scoring import RunMetadata


class GroupBreakdown(BaseModel):
    """Per-category or per-language metrics breakdown."""

    task_count: int
    positive_count: int
    negative_count: int
    recall: float
    precision: float
    f1: float
    cwe_accuracy: float
    mean_location_iou: float
    actionable_rate: float
    avg_cost: float
    avg_tokens: float


class ModelReport(BaseModel):
    """Pre-computed evaluation report — generated once, read many times."""

    # Run identity
    run_metadata: RunMetadata
    model: str
    dataset: str
    total_tasks: int
    errors: int
    parse_failures: int

    # Aggregate scores
    leaderboard_score: ConfidenceInterval
    core: CoreMetrics
    cost: CostMetrics

    # All 35 raw dimensions
    dimensions: dict[str, float]

    # Breakdowns
    by_category: dict[str, GroupBreakdown]
    by_language: dict[str, GroupBreakdown]

    # Metadata
    generated_at: str
    seclens_version: str
