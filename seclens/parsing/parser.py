"""Response parser — extract structured output from LLM responses."""

from __future__ import annotations

import json
import re

from pydantic import ValidationError

from seclens.schemas.output import ParsedOutput, ParseResult, ParseStatus
from seclens.schemas.task import Location


def parse_response(raw: str) -> ParseResult:
    """Parse a raw LLM response into structured output.

    Attempts three stages in order:
        1. Direct JSON parse
        2. Extract from markdown code blocks
        3. Regex extraction for individual fields

    Verdict is minimum viable extraction — no verdict means failed.
    """
    # Stage 1: Direct JSON parse
    result = _try_json_direct(raw)
    if result is not None:
        return result

    # Stage 2: Extract from markdown code blocks
    result = _try_markdown_block(raw)
    if result is not None:
        return result

    # Stage 3: Regex extraction
    result = _try_regex(raw)
    if result is not None:
        return result

    return ParseResult(status=ParseStatus.FAILED, raw_response=raw)


def _try_json_direct(raw: str) -> ParseResult | None:
    """Attempt direct JSON parse of the entire response."""
    stripped = raw.strip()
    if not stripped.startswith("{"):
        return None
    try:
        output = ParsedOutput.model_validate_json(stripped)
        return ParseResult(
            status=ParseStatus.FULL,
            output=output,
            raw_response=raw,
            parse_method="json_direct",
        )
    except (ValidationError, json.JSONDecodeError):
        return None


def _try_markdown_block(raw: str) -> ParseResult | None:
    """Extract JSON from markdown code blocks (```json ... ```)."""
    pattern = r"```(?:json)?\s*\n?(.*?)\n?\s*```"
    matches = re.findall(pattern, raw, re.DOTALL)
    for match in matches:
        stripped = match.strip()
        if not stripped.startswith("{"):
            continue
        try:
            output = ParsedOutput.model_validate_json(stripped)
            return ParseResult(
                status=ParseStatus.FULL,
                output=output,
                raw_response=raw,
                parse_method="markdown_block",
            )
        except (ValidationError, json.JSONDecodeError):
            continue
    return None


def _try_regex(raw: str) -> ParseResult | None:
    """Extract individual fields via regex as last resort."""
    vulnerable = _extract_verdict(raw)
    if vulnerable is None:
        return None

    cwe = _extract_cwe(raw)
    location = _extract_location(raw)

    output = ParsedOutput(vulnerable=vulnerable, cwe=cwe, location=location)

    has_all = cwe is not None and location is not None
    status = ParseStatus.FULL if vulnerable and has_all else ParseStatus.PARTIAL

    return ParseResult(
        status=status,
        output=output,
        raw_response=raw,
        parse_method="regex",
    )


def _extract_verdict(raw: str) -> bool | None:
    """Extract vulnerable verdict from raw text."""
    lower = raw.lower()

    # Check JSON-like patterns first
    true_pattern = re.search(r'"vulnerable"\s*:\s*true', lower)
    false_pattern = re.search(r'"vulnerable"\s*:\s*false', lower)

    if true_pattern and not false_pattern:
        return True
    if false_pattern and not true_pattern:
        return False

    # Natural language fallback
    if "is vulnerable" in lower or "vulnerability found" in lower or "contains a vulnerability" in lower:
        return True
    if "not vulnerable" in lower or "no vulnerability" in lower or "is safe" in lower:
        return False

    return None


def _extract_cwe(raw: str) -> str | None:
    """Extract CWE identifier from raw text."""
    match = re.search(r"CWE-\d+", raw, re.IGNORECASE)
    if match:
        return match.group(0).upper()
    return None


def _extract_location(raw: str) -> Location | None:
    """Extract file location from raw text."""
    # Look for file path with line numbers
    match = re.search(
        r'"file"\s*:\s*"([^"]+)".*?"line_start"\s*:\s*(\d+).*?"line_end"\s*:\s*(\d+)',
        raw,
        re.DOTALL,
    )
    if match:
        return Location(file=match.group(1), line_start=int(match.group(2)), line_end=int(match.group(3)))
    return None
