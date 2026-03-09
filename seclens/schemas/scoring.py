"""Scoring models — per-task scores, metrics, and results."""

from __future__ import annotations

from typing import Literal

from engine_harness import ToolCallRecord
from pydantic import BaseModel, Field

from seclens.schemas.output import ParseResult
from seclens.schemas.task import TaskType


class TaskScore(BaseModel):
    """Per-task scoring across three dimensions.

    Negative tasks: cwe=0, location=0 hardcoded — only verdict scored.
    Positive tasks: all three dimensions scored.
    """

    verdict: Literal[0, 1]
    cwe: Literal[0, 1]
    location: Literal[0, 1]
    earned: int = Field(ge=0, le=3)
    max_task_points: Literal[1, 3]


class TaskMetrics(BaseModel):
    """Resource usage metrics for a single task evaluation."""

    input_tokens: int = 0
    output_tokens: int = 0
    total_tokens: int = 0
    cost_usd: float = 0.0
    tool_calls: int = 0
    turns: int = 0
    wall_time_s: float = 0.0


class RunMetadata(BaseModel):
    """Metadata for an evaluation run."""

    model: str
    prompt: str
    layer: Literal[1, 2]
    mode: Literal["guided", "open"]
    timestamp: str
    seclens_version: str
    seed: int


class TaskResult(BaseModel):
    """Complete result for a single task evaluation."""

    task_id: str
    task_type: TaskType
    task_category: str | None = None
    task_language: str
    run_metadata: RunMetadata
    parse_result: ParseResult
    scores: TaskScore
    tool_log: list[ToolCallRecord] = []
    metrics: TaskMetrics = Field(default_factory=TaskMetrics)
    error: str | None = None
