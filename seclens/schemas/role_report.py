"""Report models for role-based dimension scoring."""

from __future__ import annotations

from pydantic import BaseModel, Field

from seclens.schemas.task import EvalLayer


class DimensionScore(BaseModel):
    """Score for a single dimension within a role report."""

    id: str
    name: str
    category: str
    raw_value: float
    normalized: float = Field(ge=0.0, le=1.0)
    weight: float
    weighted_score: float


class CategoryScore(BaseModel):
    """Aggregate score for a dimension category."""

    name: str
    total_weight: float
    weighted_score: float
    dimensions: list[DimensionScore]


class RoleReport(BaseModel):
    """Complete role-specific evaluation report."""

    role: str
    role_name: str
    role_description: str
    decision_score: float = Field(ge=0.0, le=100.0)
    grade: str
    categories: list[CategoryScore]
    dimensions: list[DimensionScore]
    model: str
    layer: EvalLayer
    total_tasks: int
    recommendation: str
    excluded_dimensions: list[str] = []
    excluded_reasons: dict[str, str] = {}
    layer_note: str | None = None


class MultiRoleReport(BaseModel):
    """Reports across all roles for a single model."""

    model: str
    reports: dict[str, RoleReport]
    ranking: list[str]


class ModelRoleSummary(BaseModel):
    """Lightweight summary for cross-model comparison."""

    model: str
    decision_score: float
    grade: str
    top_strengths: list[str]
    top_weaknesses: list[str]
