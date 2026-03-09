"""Report models — aggregate metrics and confidence intervals."""

from __future__ import annotations

from pydantic import BaseModel

from seclens.schemas.scoring import RunMetadata


class ConfidenceInterval(BaseModel):
    """Bootstrap confidence interval — all values on 0-1 ratio scale."""

    mean: float
    stderr: float
    ci_lower: float
    ci_upper: float


class CoreMetrics(BaseModel):
    """Core evaluation metrics with bootstrap CIs."""

    verdict_mcc: ConfidenceInterval
    cwe_accuracy: ConfidenceInterval
    location_accuracy: ConfidenceInterval
    task_count: int


class CostMetrics(BaseModel):
    """Cost and token usage metrics."""

    total_cost_usd: float
    avg_cost_per_task: float
    total_input_tokens: int
    total_output_tokens: int
    total_tokens: int
    mcc_per_dollar: float | None = None
    score_per_1k_tokens: float | None = None


class AggregateReport(BaseModel):
    """Full aggregate report for an evaluation run."""

    leaderboard_score: ConfidenceInterval
    core: CoreMetrics
    cost: CostMetrics
    by_category: dict[str, CoreMetrics] = {}
    by_language: dict[str, CoreMetrics] = {}
    run_metadata: RunMetadata
    task_count: int
    parse_failures: int
    errors: int
