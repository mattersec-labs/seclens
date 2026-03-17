"""Pydantic models for role-specific benchmark reports."""

from __future__ import annotations

from pydantic import BaseModel, Field


class DimensionScore(BaseModel):
    """Score for a single dimension (0-1 normalized)."""

    id: int
    name: str
    category: str
    raw_value: float = Field(description="Raw computed value")
    normalized: float = Field(ge=0.0, le=1.0, description="Normalized to 0-1 scale")
    weight: float = Field(ge=0.0, description="Weight for this role")
    weighted_score: float = Field(description="normalized * weight")
    description: str = ""


class CategoryScore(BaseModel):
    """Aggregate score for a dimension category."""

    name: str
    total_weight: float
    weighted_score: float
    dimensions: list[DimensionScore]


class RoleReport(BaseModel):
    """Complete role-specific benchmark report."""

    role: str
    role_description: str
    decision_score: float = Field(ge=0.0, le=100.0, description="Composite 0-100 score")
    grade: str = Field(description="Letter grade: A/B/C/D/F")
    categories: list[CategoryScore]
    dimensions: list[DimensionScore]
    model: str
    layer: int
    total_tasks: int
    recommendation: str = Field(description="Natural-language recommendation for this role")


class MultiRoleReport(BaseModel):
    """Comparative report across all roles for one model."""

    model: str
    reports: dict[str, RoleReport]
    ranking: list[str] = Field(description="Roles ranked by decision score descending")


class ModelComparison(BaseModel):
    """Compare multiple models through one role lens."""

    role: str
    models: list[ModelRoleSummary]


class ModelRoleSummary(BaseModel):
    """Summary of one model through one role lens."""

    model: str
    decision_score: float
    grade: str
    top_strengths: list[str]
    top_weaknesses: list[str]
