"""Run configuration for evaluation."""

from __future__ import annotations

from pydantic import BaseModel, Field

from seclens.schemas.task import EvalLayer


class RunConfig(BaseModel):
    """Configuration for an evaluation run."""

    model: str
    dataset: str
    prompt: str = "base"
    layer: EvalLayer = EvalLayer.TOOL_USE
    mode: str = "guided"
    max_turns: int = Field(default=200, ge=1)
    max_cost: float | None = None
    workers: int = Field(default=5, ge=1)
    seed: int = 42
    resume: bool = False
    dry_run: bool = False
    location_recall_threshold: float = Field(default=1.0, ge=0.0, le=1.0)
