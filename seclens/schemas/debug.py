"""Debug output schema — full message chain for per-task diagnosis."""

from __future__ import annotations

from engine_harness import Message
from pydantic import BaseModel


class DebugRecord(BaseModel):
    """Debug record capturing the full LLM conversation for a task."""

    task_id: str
    msg_chain: list[Message]
