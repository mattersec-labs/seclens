"""Dataset loading — HuggingFace (primary) and local JSONL (dev convenience)."""

from __future__ import annotations

from pathlib import Path

import datasets as hf_datasets

from seclens.schemas.task import Task, TaskType


def load_dataset(dataset_string: str) -> list[Task]:
    """Load evaluation tasks from HuggingFace or local JSONL.

    Format detection:
        - Ends with ``.jsonl`` → local file
        - Otherwise → HuggingFace dataset (``{repo}:{split}`` or ``{repo}@{version}:{split}``)

    Args:
        dataset_string: Dataset identifier or path to local JSONL file.

    Returns:
        List of validated Task objects.
    """
    if dataset_string.endswith(".jsonl"):
        return _load_local_jsonl(dataset_string)
    return _load_huggingface(dataset_string)


def filter_tasks(
    tasks: list[Task],
    *,
    task_type: TaskType | None = None,
    language: str | None = None,
    cwe: str | None = None,
    category: str | None = None,
) -> list[Task]:
    """Filter tasks by type, language, CWE, or category."""
    filtered = tasks
    if task_type is not None:
        filtered = [t for t in filtered if t.type == task_type]
    if language is not None:
        filtered = [t for t in filtered if t.repository.language == language]
    if cwe is not None:
        filtered = [t for t in filtered if t.ground_truth.cwe and t.ground_truth.cwe.upper() == cwe.upper()]
    if category is not None:
        filtered = [t for t in filtered if t.ground_truth.category == category]
    return filtered


def _load_local_jsonl(path: str) -> list[Task]:
    """Load tasks from a local JSONL file."""
    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"Dataset file not found: {path}")

    tasks = []
    with open(file_path) as f:
        for line_num, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                tasks.append(Task.model_validate_json(line))
            except Exception as exc:
                raise ValueError(f"Invalid task at line {line_num} in {path}: {exc}") from exc
    return tasks


def _load_huggingface(dataset_string: str) -> list[Task]:
    """Load tasks from HuggingFace datasets.

    Parses formats:
        - ``{repo}:{split}``
        - ``{repo}@{version}:{split}``
    """
    repo, split, version = _parse_hf_string(dataset_string)

    kwargs = {"split": split}
    if version:
        kwargs["revision"] = version

    ds = hf_datasets.load_dataset(repo, **kwargs)

    tasks = []
    for i, row in enumerate(ds):
        try:
            tasks.append(Task.model_validate(row))
        except Exception as exc:
            raise ValueError(f"Invalid task at index {i} in {dataset_string}: {exc}") from exc
    return tasks


def _parse_hf_string(dataset_string: str) -> tuple[str, str, str | None]:
    """Parse a HuggingFace dataset string into (repo, split, version).

    Formats:
        - ``repo:split`` → (repo, split, None)
        - ``repo@version:split`` → (repo, split, version)
    """
    version = None

    if ":" not in dataset_string:
        raise ValueError(
            f"Invalid dataset string: {dataset_string!r}. "
            "Expected format: 'repo:split' or 'repo@version:split'"
        )

    if "@" in dataset_string:
        repo_version, split = dataset_string.rsplit(":", 1)
        repo, version = repo_version.split("@", 1)
    else:
        repo, split = dataset_string.rsplit(":", 1)

    return repo.strip(), split.strip(), version.strip() if version else None
