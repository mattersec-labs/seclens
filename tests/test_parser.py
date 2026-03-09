"""Tests for response parser."""

from __future__ import annotations

import json

from seclens.parsing.parser import parse_response
from seclens.schemas.output import ParseStatus


class TestJsonDirect:
    def test_valid_positive(self) -> None:
        raw = json.dumps({
            "vulnerable": True,
            "cwe": "CWE-89",
            "location": {"file": "app.py", "line_start": 10, "line_end": 20},
            "evidence": None,
            "reasoning": "SQL injection",
        })
        result = parse_response(raw)
        assert result.status is ParseStatus.FULL
        assert result.output is not None
        assert result.output.vulnerable is True
        assert result.output.cwe == "CWE-89"
        assert result.parse_method == "json_direct"

    def test_valid_negative(self) -> None:
        raw = json.dumps({
            "vulnerable": False,
            "cwe": None,
            "location": None,
            "evidence": None,
            "reasoning": "No vulnerability found",
        })
        result = parse_response(raw)
        assert result.status is ParseStatus.FULL
        assert result.output is not None
        assert result.output.vulnerable is False

    def test_minimal_json(self) -> None:
        raw = '{"vulnerable": true}'
        result = parse_response(raw)
        assert result.status is ParseStatus.FULL
        assert result.output.vulnerable is True
        assert result.output.cwe is None

    def test_whitespace_around_json(self) -> None:
        raw = '  \n{"vulnerable": false}\n  '
        result = parse_response(raw)
        assert result.status is ParseStatus.FULL


class TestMarkdownBlock:
    def test_json_in_code_block(self) -> None:
        raw = """Here's my analysis:

```json
{"vulnerable": true, "cwe": "CWE-79", "location": null, "evidence": null, "reasoning": "XSS"}
```

The function is vulnerable to XSS."""
        result = parse_response(raw)
        assert result.status is ParseStatus.FULL
        assert result.output.cwe == "CWE-79"
        assert result.parse_method == "markdown_block"

    def test_code_block_without_json_tag(self) -> None:
        raw = """Analysis:

```
{"vulnerable": false, "cwe": null, "location": null, "evidence": null, "reasoning": "safe"}
```"""
        result = parse_response(raw)
        assert result.status is ParseStatus.FULL
        assert result.output.vulnerable is False

    def test_multiple_code_blocks_picks_valid(self) -> None:
        raw = """```python
def foo():
    pass
```

```json
{"vulnerable": true, "cwe": "CWE-89"}
```"""
        result = parse_response(raw)
        assert result.status is ParseStatus.FULL
        assert result.output.vulnerable is True


class TestRegexFallback:
    def test_extracts_verdict_and_cwe(self) -> None:
        raw = 'The function "vulnerable": true and has CWE-89 vulnerability.'
        result = parse_response(raw)
        assert result.status is ParseStatus.PARTIAL
        assert result.output.vulnerable is True
        assert result.output.cwe == "CWE-89"
        assert result.parse_method == "regex"

    def test_natural_language_vulnerable(self) -> None:
        raw = "The code is vulnerable to SQL injection (CWE-89)."
        result = parse_response(raw)
        assert result.status is ParseStatus.PARTIAL
        assert result.output.vulnerable is True
        assert result.output.cwe == "CWE-89"

    def test_natural_language_not_vulnerable(self) -> None:
        raw = "The code is not vulnerable. No security issues found."
        result = parse_response(raw)
        assert result.status is ParseStatus.PARTIAL
        assert result.output.vulnerable is False

    def test_extracts_location_from_json_fragment(self) -> None:
        raw = '"vulnerable": true, "cwe": "CWE-89", "file": "app.py", "line_start": 10, "line_end": 20'
        result = parse_response(raw)
        assert result.output.location is not None
        assert result.output.location.file == "app.py"
        assert result.output.location.line_start == 10


class TestFailedParse:
    def test_no_verdict(self) -> None:
        raw = "I'm not sure about this code."
        result = parse_response(raw)
        assert result.status is ParseStatus.FAILED
        assert result.output is None

    def test_empty_response(self) -> None:
        raw = ""
        result = parse_response(raw)
        assert result.status is ParseStatus.FAILED

    def test_garbage_response(self) -> None:
        raw = "asdfghjkl 12345"
        result = parse_response(raw)
        assert result.status is ParseStatus.FAILED

    def test_raw_preserved(self) -> None:
        raw = "Some random text"
        result = parse_response(raw)
        assert result.raw_response == raw
