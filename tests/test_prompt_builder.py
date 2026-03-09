"""Tests for prompt builder."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest
from engine_harness import Role

from seclens.prompts.builder import (
    _load_preset,
    build_prompt,
    generate_output_format,
)
from seclens.schemas.task import (
    GroundTruth,
    Repository,
    Target,
    Task,
    TaskType,
)


@pytest.fixture()
def sample_task() -> Task:
    return Task(
        id="test-001",
        version="1.0",
        type=TaskType.TRUE_POSITIVE,
        max_task_points=3,
        repository=Repository(url="https://github.com/django/django", commit="abc123", language="python"),
        target=Target(function="set_values", file="django/db/models/sql/query.py", line_start=100, line_end=120),
        ground_truth=GroundTruth(vulnerable=True, cwe="CWE-89", category="sql_injection"),
    )


class TestGenerateOutputFormat:
    def test_contains_schema(self) -> None:
        fmt = generate_output_format()
        assert "vulnerable" in fmt
        assert "cwe" in fmt
        assert "location" in fmt

    def test_contains_examples(self) -> None:
        fmt = generate_output_format()
        assert "true" in fmt
        assert "false" in fmt

    def test_contains_json_keyword(self) -> None:
        fmt = generate_output_format()
        assert "JSON" in fmt


class TestLoadPreset:
    def test_load_base(self) -> None:
        preset = _load_preset("base")
        assert "system" in preset
        assert "user" in preset

    def test_load_minimal(self) -> None:
        preset = _load_preset("minimal")
        assert "system" in preset
        assert "user" in preset

    def test_load_security_expert(self) -> None:
        preset = _load_preset("security_expert")
        assert "system" in preset
        assert "methodology" in preset["system"].lower()

    def test_load_nonexistent_raises(self) -> None:
        with pytest.raises(FileNotFoundError, match="not found"):
            _load_preset("nonexistent_preset_xyz")

    def test_load_custom_file(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write("system: Custom system\nuser: Custom user\n")
            f.flush()
            preset = _load_preset(f.name)
            assert preset["system"] == "Custom system"
            assert preset["user"] == "Custom user"
            Path(f.name).unlink()


class TestBuildPrompt:
    def test_returns_two_messages(self, sample_task: Task) -> None:
        messages = build_prompt(sample_task, preset_name="base", mode="guided", layer=1, code_block="def foo(): pass")
        assert len(messages) == 2
        assert messages[0].role is Role.SYSTEM
        assert messages[1].role is Role.USER

    def test_layer1_code_in_prompt(self, sample_task: Task) -> None:
        code = "def set_values(): pass"
        messages = build_prompt(sample_task, preset_name="base", layer=1, code_block=code)
        user_content = messages[1].content
        assert "def set_values(): pass" in user_content

    def test_layer2_tool_instruction(self, sample_task: Task) -> None:
        messages = build_prompt(sample_task, preset_name="base", layer=2)
        user_content = messages[1].content
        assert "tools" in user_content.lower() or "read" in user_content.lower()

    def test_guided_mode_has_category_hint(self, sample_task: Task) -> None:
        messages = build_prompt(sample_task, preset_name="base", mode="guided", layer=1, code_block="code")
        system_content = messages[0].content
        assert "sql_injection" in system_content

    def test_open_mode_no_category_hint(self, sample_task: Task) -> None:
        messages = build_prompt(sample_task, preset_name="base", mode="open", layer=1, code_block="code")
        system_content = messages[0].content
        assert "sql_injection" not in system_content

    def test_template_vars_filled(self, sample_task: Task) -> None:
        messages = build_prompt(sample_task, preset_name="base", layer=1, code_block="code")
        user_content = messages[1].content
        assert "set_values" in user_content
        assert "django/db/models/sql/query.py" in user_content
        assert "100" in user_content
        assert "120" in user_content

    def test_output_format_injected(self, sample_task: Task) -> None:
        messages = build_prompt(sample_task, preset_name="base", layer=1, code_block="code")
        system_content = messages[0].content
        assert "vulnerable" in system_content
        assert "JSON" in system_content

    def test_all_presets_render_without_error(self, sample_task: Task) -> None:
        for preset in ("base", "minimal", "security_expert"):
            messages = build_prompt(sample_task, preset_name=preset, layer=1, code_block="code")
            assert len(messages) == 2
            assert messages[0].content  # not empty
            assert messages[1].content  # not empty
