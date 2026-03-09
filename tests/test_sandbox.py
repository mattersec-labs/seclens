"""Tests for sandbox management."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from seclens.sandbox.manager import (
    SandboxManager,
    _parse_github_url,
    fetch_target_code,
)
from seclens.schemas.task import Target

BOOTSTRAP_PATH = Path(__file__).parent.parent.parent / "benchmark-harness-research" / "bootstrap.jsonl"


class TestParseGithubUrl:
    def test_https_url(self) -> None:
        owner, repo = _parse_github_url("https://github.com/django/django")
        assert owner == "django"
        assert repo == "django"

    def test_url_with_trailing_slash(self) -> None:
        owner, repo = _parse_github_url("https://github.com/django/django/")
        assert owner == "django"
        assert repo == "django"

    def test_url_with_extra_path(self) -> None:
        owner, repo = _parse_github_url("https://github.com/django/django/tree/main")
        assert owner == "django"
        assert repo == "django"

    def test_invalid_url(self) -> None:
        with pytest.raises(ValueError, match="Cannot parse"):
            _parse_github_url("https://github.com/django")


class TestSandboxManager:
    def test_default_base_dir(self) -> None:
        manager = SandboxManager()
        assert manager.base_dir.exists()
        assert "seclens_" in manager.base_dir.name

    def test_custom_base_dir(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            manager = SandboxManager(base_dir=Path(tmp))
            assert manager.base_dir == Path(tmp)

    def test_cleanup_removes_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            manager = SandboxManager(base_dir=Path(tmp))
            task_dir = Path(tmp) / "test-task"
            task_dir.mkdir()
            (task_dir / "file.txt").write_text("content")

            manager.cleanup("test-task")
            assert not task_dir.exists()

    def test_cleanup_nonexistent_is_noop(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            manager = SandboxManager(base_dir=Path(tmp))
            manager.cleanup("nonexistent")  # should not raise

    @patch("seclens.sandbox.manager.subprocess.run")
    def test_create_calls_git_commands(self, mock_run: MagicMock) -> None:
        mock_run.return_value = MagicMock(returncode=0)
        with tempfile.TemporaryDirectory() as tmp:
            manager = SandboxManager(base_dir=Path(tmp))
            manager.create("task-1", "https://github.com/django/django", "abc123")

            assert mock_run.call_count == 3
            # Verify git clone
            clone_args = mock_run.call_args_list[0]
            assert "clone" in clone_args[0][0]
            # Verify git fetch
            fetch_args = mock_run.call_args_list[1]
            assert "fetch" in fetch_args[0][0]
            assert "abc123" in fetch_args[0][0]
            # Verify git checkout
            checkout_args = mock_run.call_args_list[2]
            assert "checkout" in checkout_args[0][0]

    @patch("seclens.sandbox.manager.subprocess.run")
    def test_create_removes_git_dir(self, mock_run: MagicMock) -> None:
        mock_run.return_value = MagicMock(returncode=0)
        with tempfile.TemporaryDirectory() as tmp:
            manager = SandboxManager(base_dir=Path(tmp))
            task_dir = Path(tmp) / "task-1"
            task_dir.mkdir(parents=True)
            # Simulate .git dir created by clone
            git_dir = task_dir / ".git"
            git_dir.mkdir()
            (git_dir / "HEAD").write_text("ref: refs/heads/main")

            manager.create("task-1", "https://github.com/django/django", "abc123")
            assert not git_dir.exists()


class TestFetchTargetCode:
    @patch("seclens.sandbox.manager._fetch_file_raw")
    def test_fetches_and_extracts(self, mock_fetch: MagicMock) -> None:
        # Simulate a 10-line Python file
        lines = [f"line {i}\n" for i in range(1, 11)]
        mock_fetch.return_value = "".join(lines)

        target = Target(function="my_func", file="app.py", line_start=3, line_end=5)
        result = fetch_target_code("https://github.com/owner/repo", "abc123", target)

        assert "line 3" in result
        assert "line 5" in result
        assert "line 1" not in result
        assert "line 6" not in result
        mock_fetch.assert_called_once_with("owner", "repo", "abc123", "app.py")

    @pytest.mark.integration
    def test_real_fetch_from_bootstrap(self) -> None:
        """Integration test: fetch real code from GitHub using bootstrap dataset."""
        if not BOOTSTRAP_PATH.exists():
            pytest.skip("bootstrap.jsonl not found")

        with open(BOOTSTRAP_PATH) as f:
            task_data = json.loads(f.readline())

        target = Target.model_validate(task_data["target"])
        code = fetch_target_code(
            task_data["repository"]["url"],
            task_data["repository"]["commit"],
            target,
        )

        assert len(code) > 0
        assert len(code.splitlines()) == target.line_end - target.line_start + 1
