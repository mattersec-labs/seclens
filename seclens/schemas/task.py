"""Task models — dataset schema for evaluation inputs."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, Field, field_validator


class TaskType(StrEnum):
    """Type of evaluation task."""

    TRUE_POSITIVE = "true_positive"
    POST_PATCH = "post_patch"
    SAST_FALSE_POSITIVE = "sast_false_positive"


class Repository(BaseModel):
    """Source repository for a task."""

    url: str
    commit: str
    language: str


class Target(BaseModel):
    """Target function to analyze."""

    function: str
    file: str
    line_start: int
    line_end: int


class Location(BaseModel):
    """File path and line range identifying a code region."""

    file: str
    line_start: int
    line_end: int


class GroundTruth(BaseModel):
    """Ground truth for a task.

    All fields except ``vulnerable`` are optional.
    Positive tasks have all fields populated.
    Negative tasks have ``vulnerable=False``, ``location=None``,
    and cwe/category optionally inherited from paired positive.
    """

    vulnerable: bool
    cwe: str | None = None
    category: str | None = None
    location: Location | None = None


class TaskMetadata(BaseModel):
    """Optional metadata for a task."""

    disclosure_date: str | None = None
    cve_id: str | None = None

    @field_validator("disclosure_date", mode="before")
    @classmethod
    def _coerce_date(cls, v: str | datetime | None) -> str | None:
        if isinstance(v, datetime):
            return v.strftime("%Y-%m-%d")
        return v
    paired_with: str | None = None
    sast_rule: str | None = None
    sast_tool: str | None = None


class Task(BaseModel):
    """A single evaluation task from the dataset."""

    id: str
    version: str
    type: TaskType
    max_task_points: Literal[1, 3] = Field(description="3 for positive tasks, 1 for negative tasks")
    repository: Repository
    target: Target
    ground_truth: GroundTruth
    metadata: TaskMetadata = Field(default_factory=TaskMetadata)
