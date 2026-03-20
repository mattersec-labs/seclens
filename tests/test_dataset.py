"""Tests for dataset loading."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from seclens.dataset.loader import (
    _parse_hf_string,
    filter_tasks,
    load_dataset,
)
from seclens.schemas.task import Task, TaskType

BOOTSTRAP_PATH = Path(__file__).parent.parent.parent / "benchmark-harness-research" / "bootstrap.jsonl"


class TestParseHfString:
    def test_repo_split(self) -> None:
        repo, split, version = _parse_hf_string("test-org/test-dataset:test")
        assert repo == "test-org/test-dataset"
        assert split == "test"
        assert version is None

    def test_repo_version_split(self) -> None:
        repo, split, version = _parse_hf_string("test-org/test-dataset@v1.0:test")
        assert repo == "test-org/test-dataset"
        assert split == "test"
        assert version == "v1.0"

    def test_no_split_raises(self) -> None:
        with pytest.raises(ValueError, match="Invalid dataset string"):
            _parse_hf_string("test-org/test-dataset")


class TestLoadLocalJsonl:
    def test_load_bootstrap(self) -> None:
        if not BOOTSTRAP_PATH.exists():
            pytest.skip("bootstrap.jsonl not found")
        tasks = load_dataset(str(BOOTSTRAP_PATH))
        assert len(tasks) == 12
        assert all(isinstance(t, Task) for t in tasks)

    def test_file_not_found(self) -> None:
        with pytest.raises(FileNotFoundError):
            load_dataset("/nonexistent/path.jsonl")

    def test_invalid_json_raises(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            f.write("not valid json\n")
            f.flush()
            with pytest.raises(ValueError, match="Invalid task at line 1"):
                load_dataset(f.name)
            Path(f.name).unlink()

    def test_empty_lines_skipped(self) -> None:
        if not BOOTSTRAP_PATH.exists():
            pytest.skip("bootstrap.jsonl not found")
        # Create a file with empty lines mixed in
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            with open(BOOTSTRAP_PATH) as src:
                for line in src:
                    f.write(line)
                    f.write("\n")  # extra empty line
            f.flush()
            tasks = load_dataset(f.name)
            assert len(tasks) == 12
            Path(f.name).unlink()


class TestFilterTasks:
    @pytest.fixture()
    def tasks(self) -> list[Task]:
        if not BOOTSTRAP_PATH.exists():
            pytest.skip("bootstrap.jsonl not found")
        return load_dataset(str(BOOTSTRAP_PATH))

    def test_filter_by_type_positive(self, tasks: list[Task]) -> None:
        filtered = filter_tasks(tasks, task_type=TaskType.TRUE_POSITIVE)
        assert all(t.type == TaskType.TRUE_POSITIVE for t in filtered)
        assert len(filtered) == 6

    def test_filter_by_type_negative(self, tasks: list[Task]) -> None:
        filtered = filter_tasks(tasks, task_type=TaskType.POST_PATCH)
        assert all(t.type == TaskType.POST_PATCH for t in filtered)
        assert len(filtered) == 6

    def test_filter_by_language(self, tasks: list[Task]) -> None:
        filtered = filter_tasks(tasks, language="python")
        assert len(filtered) == 6  # half are python, half javascript

    def test_filter_by_nonexistent_language(self, tasks: list[Task]) -> None:
        filtered = filter_tasks(tasks, language="rust")
        assert len(filtered) == 0

    def test_filter_no_criteria(self, tasks: list[Task]) -> None:
        filtered = filter_tasks(tasks)
        assert len(filtered) == len(tasks)

    def test_filter_combined(self, tasks: list[Task]) -> None:
        filtered = filter_tasks(tasks, task_type=TaskType.TRUE_POSITIVE, language="python")
        assert len(filtered) == 3


class TestLoadHuggingFace:
    @pytest.mark.integration
    def test_load_from_hf(self) -> None:
        tasks = load_dataset("test-org/test-dataset:test")
        assert len(tasks) > 0
        assert all(isinstance(t, Task) for t in tasks)
