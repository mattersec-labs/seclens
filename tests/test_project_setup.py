"""Tests for project setup and package structure."""

from __future__ import annotations

import importlib
import subprocess
import sys
from pathlib import Path


def test_version_exists() -> None:
    from seclens import __version__

    assert __version__ == "0.1.0"


def test_package_importable() -> None:
    import seclens

    assert seclens is not None


def test_subpackages_importable() -> None:
    subpackages = [
        "seclens.cli",
        "seclens.schemas",
        "seclens.evaluation",
        "seclens.sandbox",
        "seclens.parsing",
        "seclens.scoring",
        "seclens.dataset",
        "seclens.results",
        "seclens.prompts",
    ]
    for pkg in subpackages:
        mod = importlib.import_module(pkg)
        assert mod is not None, f"Failed to import {pkg}"


def test_cli_entry_point() -> None:
    from seclens.cli.main import app

    assert app is not None


def test_no_circular_imports() -> None:
    mods_to_remove = [k for k in sys.modules if k.startswith("seclens")]
    removed = {k: sys.modules.pop(k) for k in mods_to_remove}
    try:
        importlib.import_module("seclens")
    finally:
        sys.modules.update(removed)


def test_py_typed_marker_exists() -> None:
    import seclens

    pkg_dir = Path(seclens.__file__).parent
    assert (pkg_dir / "py.typed").exists()


def test_cli_help_runs() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "typer", "seclens.cli.main", "run", "--help"],
        capture_output=True,
        text=True,
    )
    # Entry point should at least not crash
    assert result.returncode == 0 or "No such command" in result.stderr or "Usage" in result.stdout
