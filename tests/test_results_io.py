"""Tests for JSONL result I/O."""

from __future__ import annotations

import threading
from pathlib import Path

import pytest

from seclens.results.io import get_completed_ids, read_results, write_result
from seclens.schemas.output import ParsedOutput, ParseResult, ParseStatus
from seclens.schemas.scoring import RunMetadata, TaskMetrics, TaskResult, TaskScore
from seclens.schemas.task import TaskType


def _make_run_metadata() -> RunMetadata:
    return RunMetadata(
        model="test/model",
        prompt="base",
        layer="code-in-prompt",
        mode="guided",
        timestamp="2026-03-09T12:00:00Z",
        seclens_version="0.1.0",
        seed=42,
    )


def _make_result(task_id: str, verdict: int = 1) -> TaskResult:
    return TaskResult(
        task_id=task_id,
        task_type=TaskType.TRUE_POSITIVE,
        task_category="sql_injection",
        task_language="python",
        run_metadata=_make_run_metadata(),
        parse_result=ParseResult(
            status=ParseStatus.FULL,
            output=ParsedOutput(vulnerable=True),
            raw_response="",
        ),
        scores=TaskScore(
            verdict=verdict, cwe=0, location=0,
            earned=verdict, max_task_points=3,
        ),
        metrics=TaskMetrics(
            input_tokens=100, output_tokens=50, total_tokens=150,
            cost_usd=0.01, turns=1,
        ),
    )


class TestWriteResult:
    def test_creates_file(self, tmp_path: Path) -> None:
        path = tmp_path / "results.jsonl"
        result = _make_result("t1")
        write_result(path, result)
        assert path.exists()
        lines = path.read_text().strip().split("\n")
        assert len(lines) == 1

    def test_appends_multiple(self, tmp_path: Path) -> None:
        path = tmp_path / "results.jsonl"
        write_result(path, _make_result("t1"))
        write_result(path, _make_result("t2"))
        write_result(path, _make_result("t3"))
        lines = path.read_text().strip().split("\n")
        assert len(lines) == 3

    def test_thread_safety(self, tmp_path: Path) -> None:
        path = tmp_path / "results.jsonl"
        threads = []
        for i in range(20):
            t = threading.Thread(
                target=write_result,
                args=(path, _make_result(f"t{i}")),
            )
            threads.append(t)
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        lines = path.read_text().strip().split("\n")
        assert len(lines) == 20


class TestReadResults:
    def test_roundtrip(self, tmp_path: Path) -> None:
        path = tmp_path / "results.jsonl"
        original = [_make_result(f"t{i}") for i in range(5)]
        for r in original:
            write_result(path, r)
        loaded = read_results(path)
        assert len(loaded) == 5
        assert all(isinstance(r, TaskResult) for r in loaded)
        assert [r.task_id for r in loaded] == [f"t{i}" for i in range(5)]

    def test_file_not_found(self) -> None:
        with pytest.raises(FileNotFoundError):
            read_results(Path("/nonexistent/results.jsonl"))

    def test_invalid_json_raises(self, tmp_path: Path) -> None:
        path = tmp_path / "results.jsonl"
        path.write_text("not json\n")
        with pytest.raises(ValueError, match="Invalid result at line 1"):
            read_results(path)

    def test_empty_lines_skipped(self, tmp_path: Path) -> None:
        path = tmp_path / "results.jsonl"
        write_result(path, _make_result("t1"))
        with open(path, "a") as f:
            f.write("\n\n")
        write_result(path, _make_result("t2"))
        loaded = read_results(path)
        assert len(loaded) == 2

    def test_preserves_all_fields(self, tmp_path: Path) -> None:
        path = tmp_path / "results.jsonl"
        original = _make_result("t1")
        write_result(path, original)
        loaded = read_results(path)[0]
        assert loaded.task_id == original.task_id
        assert loaded.scores.verdict == original.scores.verdict
        assert loaded.metrics.cost_usd == original.metrics.cost_usd
        assert loaded.run_metadata.model == original.run_metadata.model


class TestGetCompletedIds:
    def test_returns_ids(self, tmp_path: Path) -> None:
        path = tmp_path / "results.jsonl"
        for i in range(5):
            write_result(path, _make_result(f"task-{i}"))
        ids = get_completed_ids(path)
        assert ids == {f"task-{i}" for i in range(5)}

    def test_nonexistent_file_returns_empty(self, tmp_path: Path) -> None:
        path = tmp_path / "missing.jsonl"
        ids = get_completed_ids(path)
        assert ids == set()

    def test_skips_malformed_lines(self, tmp_path: Path) -> None:
        path = tmp_path / "results.jsonl"
        write_result(path, _make_result("good"))
        with open(path, "a") as f:
            f.write("not json\n")
        write_result(path, _make_result("also-good"))
        ids = get_completed_ids(path)
        assert ids == {"good", "also-good"}

    def test_skips_empty_lines(self, tmp_path: Path) -> None:
        path = tmp_path / "results.jsonl"
        write_result(path, _make_result("t1"))
        with open(path, "a") as f:
            f.write("\n\n\n")
        ids = get_completed_ids(path)
        assert ids == {"t1"}
