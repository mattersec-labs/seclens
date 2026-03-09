"""Sandbox management for evaluation environments."""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from engine_harness.tools.read_file import ReadFileTool

from seclens.schemas.task import Target


class SandboxManager:
    """Manages sandboxed repositories for Layer 2 tool-use evaluation.

    Each task gets its own directory under ``base_dir``. Directories are
    created via git clone and cleaned up after evaluation.
    """

    def __init__(self, base_dir: Path | None = None) -> None:
        self._base_dir = base_dir or Path(tempfile.mkdtemp(prefix="sandboxed_"))

    @property
    def base_dir(self) -> Path:
        return self._base_dir

    def create(self, task_id: str, repo_url: str, commit: str) -> Path:
        """Clone a repository at a specific commit and return the sandbox path.

        Steps:
            1. ``git clone --depth=1`` the repo
            2. ``git fetch --depth=1 origin <commit>``
            3. ``git checkout <commit>``
            4. Remove ``.git/`` directory (anti-gaming)

        Returns:
            Path to the cloned repository root.
        """
        task_dir = self._base_dir / task_id
        task_dir.mkdir(parents=True, exist_ok=True)

        self._git_clone(repo_url, commit, task_dir)
        self._sanitize_repo(task_dir)

        return task_dir

    def cleanup(self, task_id: str) -> None:
        """Remove a task's sandbox directory."""
        task_dir = self._base_dir / task_id
        if task_dir.exists():
            shutil.rmtree(task_dir)

    def cleanup_all(self) -> None:
        """Remove the entire sandbox base directory and all task sandboxes."""
        if self._base_dir.exists():
            shutil.rmtree(self._base_dir, ignore_errors=True)

    def _git_clone(self, repo_url: str, commit: str, dest: Path) -> None:
        """Clone repo and checkout specific commit."""
        subprocess.run(
            ["git", "clone", "--depth=1", repo_url, str(dest)],
            capture_output=True,
            text=True,
            check=True,
            timeout=120,
        )
        subprocess.run(
            ["git", "fetch", "--depth=1", "origin", commit],
            cwd=dest,
            capture_output=True,
            text=True,
            check=True,
            timeout=120,
        )
        subprocess.run(
            ["git", "checkout", commit],
            cwd=dest,
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        )

    @staticmethod
    def _sanitize_repo(repo_dir: Path) -> None:
        """Remove files that could leak answers or add noise.

        Tier 1: Git internals and CI/build noise — no value for security analysis.
        Tier 2: Tests and docs — could contain CVE regression tests or
                 changelog entries that directly reveal the vulnerability.
        """
        # Directories to remove
        remove_dirs = [
            # Tier 1 — git & CI noise
            ".git", ".github", ".gitlab", ".circleci",
            ".tx", "js_tests", "scripts", "extras",
            # Tier 2 — answer leakage
            "tests", "test", "docs", "doc",
        ]
        # Files to remove (glob patterns matched against name only)
        remove_files = [
            # Git-specific (useless without .git)
            ".gitattributes", ".git-blame-ignore-revs", ".gitignore", ".gitmodules",
            # CI / build / editor noise
            ".editorconfig", ".flake8", ".pre-commit-config.yaml",
            ".readthedocs.yml", ".readthedocs.yaml",
            "tox.ini", "MANIFEST.in", "Gruntfile.js",
            "eslint.config.mjs", "package.json", "package-lock.json",
            "yarn.lock", ".eslintrc.js", ".eslintrc.json",
            # Docs / meta
            "CONTRIBUTING.rst", "CONTRIBUTING.md",
            "AUTHORS", "CHANGELOG.md", "CHANGELOG.rst",
            "CHANGES.md", "CHANGES.rst", "HISTORY.md", "HISTORY.rst",
        ]

        for name in remove_dirs:
            path = repo_dir / name
            if path.is_dir():
                shutil.rmtree(path, ignore_errors=True)

        for name in remove_files:
            path = repo_dir / name
            if path.is_file():
                path.unlink(missing_ok=True)


def fetch_target_code(repo_url: str, commit: str, target: Target) -> str:
    """Fetch a single file from GitHub and extract target function lines.

    Used for Layer 1 evaluation where no full clone is needed.
    Fetches via ``raw.githubusercontent.com`` and uses ``ReadFileTool``
    for precise line extraction.

    Args:
        repo_url: GitHub repository URL.
        commit: Commit hash.
        target: Target with file path and line range.

    Returns:
        Extracted function source code as a string.
    """
    owner, repo = _parse_github_url(repo_url)
    content = _fetch_file_raw(owner, repo, commit, target.file)

    with tempfile.TemporaryDirectory(prefix="sandboxed_") as tmp_dir:
        tmp_path = Path(tmp_dir)
        file_dest = tmp_path / target.file
        file_dest.parent.mkdir(parents=True, exist_ok=True)
        file_dest.write_text(content)

        read_tool = ReadFileTool(sandbox_root=tmp_path)
        return read_tool.execute(
            path=target.file,
            start_line=target.line_start,
            end_line=target.line_end,
        )


def _parse_github_url(repo_url: str) -> tuple[str, str]:
    """Extract owner and repo name from a GitHub URL."""
    parsed = urlparse(repo_url)
    parts = parsed.path.strip("/").split("/")
    if len(parts) < 2:
        raise ValueError(f"Cannot parse GitHub URL: {repo_url}")
    return parts[0], parts[1]


def _fetch_file_raw(owner: str, repo: str, commit: str, file_path: str) -> str:
    """Fetch a single file from GitHub via raw.githubusercontent.com."""
    url = f"https://raw.githubusercontent.com/{owner}/{repo}/{commit}/{file_path}"
    req = Request(url, headers={"User-Agent": "seclens/0.1"})
    with urlopen(req, timeout=30) as resp:
        return resp.read().decode("utf-8")
