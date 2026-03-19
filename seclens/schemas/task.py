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


class EvalLayer(StrEnum):
    """Evaluation layer."""

    CODE_IN_PROMPT = "code-in-prompt"
    TOOL_USE = "tool-use"

    @property
    def short(self) -> str:
        """Short form for filenames: cip / tu."""
        return "cip" if self == EvalLayer.CODE_IN_PROMPT else "tu"

    @property
    def layer_number(self) -> int:
        """Numeric form for prompt template keys (user_l1 / user_l2)."""
        return 1 if self == EvalLayer.CODE_IN_PROMPT else 2

    @classmethod
    def from_input(cls, value: str | int) -> EvalLayer:
        """Parse from CLI input — accepts enum values, short forms, or numbers."""
        mapping = {
            "1": cls.CODE_IN_PROMPT,
            "2": cls.TOOL_USE,
            "cip": cls.CODE_IN_PROMPT,
            "tu": cls.TOOL_USE,
            "code-in-prompt": cls.CODE_IN_PROMPT,
            "tool-use": cls.TOOL_USE,
        }
        result = mapping.get(str(value).lower())
        if result is None:
            valid = ", ".join(sorted(mapping.keys()))
            raise ValueError(f"Invalid layer: {value!r}. Valid: {valid}")
        return result


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
    severity: Literal["critical", "high", "medium", "low"] | None = None
    location: Location | None = None


class TaskMetadata(BaseModel):
    """Optional metadata for a task."""

    disclosure_date: str | None = None
    cve_id: str | None = None
    paired_with: str | None = None
    sast_rule: str | None = None
    sast_tool: str | None = None

    @field_validator("disclosure_date", mode="before")
    @classmethod
    def _coerce_date(cls, v: str | datetime | None) -> str | None:
        if isinstance(v, datetime):
            return v.strftime("%Y-%m-%d")
        return v


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
