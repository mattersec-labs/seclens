"""Run configuration for evaluation."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field


class RunConfig(BaseModel):
    """Configuration for an evaluation run."""

    model: str
    dataset: str = "sidds020/SecLens:test"
    prompt: str = "base"
    layer: Literal[1, 2] = 2
    mode: Literal["guided", "open"] = "guided"
    max_turns: int = Field(default=20, ge=1)
    max_cost: float | None = None
    workers: int = Field(default=5, ge=1)
    seed: int = 42
    output: Path | None = None
    resume: bool = False
    dry_run: bool = False
