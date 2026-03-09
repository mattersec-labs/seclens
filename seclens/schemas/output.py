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
    """Source, sink, and data-flow evidence supporting the finding."""

    source: str | None = None
    sink: str | None = None
    flow: list[str] = []


class ParsedOutput(BaseModel):
    """Security audit finding.

    Set ``vulnerable`` to true or false. Provide ``cwe``, ``location``,
    and ``evidence`` when a vulnerability is found; use null otherwise.
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
