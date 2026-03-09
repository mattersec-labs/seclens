"""Output models — parsed model response."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel

from seclens.schemas.task import Location


class ParseStatus(StrEnum):
    """Status of response parsing."""

    FULL = "full"
    PARTIAL = "partial"
    FAILED = "failed"


class EvidenceOutput(BaseModel):
    """Evidence details from model response — logged not scored in v1."""

    source: str | None = None
    sink: str | None = None
    flow: list[str] = []


class ParsedOutput(BaseModel):
    """Structured output parsed from model response.

    All fields are optional — LLM returns null for cwe/location on
    negative verdicts. ``vulnerable=None`` indicates a parse failure.
    """

    vulnerable: bool | None = None
    cwe: str | None = None
    location: Location | None = None
    evidence: EvidenceOutput | None = None
    reasoning: str | None = None


class ParseResult(BaseModel):
    """Result of parsing a model response."""

    status: ParseStatus
    output: ParsedOutput | None = None
    raw_response: str
    parse_method: str | None = None
