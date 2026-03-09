"""JSONL result I/O with thread-safe writes and resumability support."""

from __future__ import annotations

import json
import threading
from pathlib import Path

from seclens.schemas.scoring import TaskResult

# Module-level lock for thread-safe file appends across workers.
_write_lock = threading.Lock()


def write_result(path: Path, result: TaskResult) -> None:
    """Append a single TaskResult as one JSON line to a JSONL file.

    Thread-safe: uses a module-level lock so multiple workers can safely
    append to the same file concurrently.

    Args:
        path: Path to the output JSONL file.
        result: The task result to serialize and append.
    """
    line = result.model_dump_json()
    with _write_lock:
        with open(path, "a") as f:
            f.write(line + "\n")


def read_results(path: Path) -> list[TaskResult]:
    """Read all TaskResults from a JSONL file.

    Args:
        path: Path to the results JSONL file.

    Returns:
        List of validated TaskResult objects.

    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If a line contains invalid JSON or fails validation.
    """
    if not path.exists():
        raise FileNotFoundError(f"Results file not found: {path}")

    results: list[TaskResult] = []
    with open(path) as f:
        for line_num, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                results.append(TaskResult.model_validate_json(line))
            except Exception as exc:
                raise ValueError(
                    f"Invalid result at line {line_num} in {path}: {exc}"
                ) from exc
    return results


def get_completed_ids(path: Path) -> set[str]:
    """Extract task IDs from a results JSONL without full deserialization.

    Lightweight scan for resumability — only parses the ``task_id`` field
    from each line rather than validating the entire TaskResult.

    Args:
        path: Path to the results JSONL file.

    Returns:
        Set of task IDs that have already been evaluated.
    """
    if not path.exists():
        return set()

    ids: set[str] = set()
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                task_id = data.get("task_id")
                if task_id is not None:
                    ids.add(task_id)
            except json.JSONDecodeError:
                continue
    return ids
