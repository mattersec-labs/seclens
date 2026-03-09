"""Evaluation orchestration — config and per-task runner."""

from seclens.evaluation.config import RunConfig
from seclens.evaluation.runner import evaluate_task

__all__ = ["RunConfig", "evaluate_task"]
