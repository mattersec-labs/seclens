"""Prompt builder — loads YAML presets and fills template variables."""

from __future__ import annotations

import importlib.resources
import json
from pathlib import Path

import yaml
from engine_harness import Message, Role

from seclens.schemas.output import ParsedOutput
from seclens.schemas.task import Task


def build_prompt(
    task: Task,
    preset_name: str = "base",
    mode: str = "guided",
    layer: int = 2,
    code_block: str | None = None,
) -> list[Message]:
    """Build prompt messages from a YAML preset and task data.

    Args:
        task: The evaluation task.
        preset_name: Name of built-in preset or path to custom YAML.
        mode: ``"guided"`` (with category hint) or ``"open"`` (no hint).
        layer: 1 (code in prompt) or 2 (tool-use instruction).
        code_block: Function source code (Layer 1) or None (Layer 2 uses default instruction).

    Returns:
        List of Messages with system and user prompts.
    """
    preset = _load_preset(preset_name)

    if code_block is None and layer == 2:
        code_block = (
            "Use the provided tools (read_file, search, list_dir) to read and analyze "
            "the source code. Start by reading the target file and examining the function."
        )

    template_vars = _build_template_vars(task, mode, code_block or "")

    system_content = preset["system"].format(**template_vars)
    user_content = preset["user"].format(**template_vars)

    return [
        Message(role=Role.SYSTEM, content=system_content),
        Message(role=Role.USER, content=user_content),
    ]


def generate_output_format() -> str:
    """Generate output format instructions from ParsedOutput JSON schema.

    Uses the LangChain PydanticOutputParser pattern: derive the expected
    JSON structure from the Pydantic model schema so the prompt stays
    in sync with the model automatically.
    """
    schema = ParsedOutput.model_json_schema(mode="serialization")

    # Strip internal class names and implementation details from schema
    schema.pop("title", None)
    schema.pop("type", None)
    for def_obj in schema.get("$defs", {}).values():
        def_obj.pop("title", None)
    for prop in schema.get("properties", {}).values():
        prop.pop("title", None)

    # Rename programmatic $defs keys to neutral names
    _rename_schema_def(schema, "EvidenceOutput", "Evidence")

    schema_str = json.dumps(schema, indent=2)

    return (
        "You MUST respond with a JSON object matching this schema:\n"
        f"```json\n{schema_str}\n```\n\n"
        "Example for a vulnerable function:\n"
        '```json\n{"vulnerable": true, "cwe": "CWE-89", '
        '"location": {"file": "app/views.py", "line_start": 42, "line_end": 55}, '
        '"evidence": {"source": "request.GET[\'q\']", "sink": "cursor.execute(query)", '
        '"flow": ["views.py:42", "views.py:50"]}, '
        '"reasoning": "User input is concatenated directly into SQL query"}\n```\n\n'
        "Example for a non-vulnerable function:\n"
        '```json\n{"vulnerable": false, "cwe": null, "location": null, '
        '"evidence": null, "reasoning": "Input is properly parameterized"}\n```'
    )


def _build_template_vars(task: Task, mode: str, code_block: str) -> dict[str, str]:
    """Build the template variable dictionary for prompt formatting."""
    category_hint = ""
    if mode == "guided" and task.ground_truth.category:
        category_hint = f"Focus your analysis on potential {task.ground_truth.category} vulnerabilities."

    return {
        "function_name": task.target.function,
        "file_path": task.target.file,
        "line_start": str(task.target.line_start),
        "line_end": str(task.target.line_end),
        "category_hint": category_hint,
        "code_block": code_block,
        "output_format": generate_output_format(),
    }


def _rename_schema_def(schema: dict, old: str, new: str) -> None:
    """Rename a key in $defs and update all $ref pointers."""
    defs = schema.get("$defs", {})
    if old in defs:
        defs[new] = defs.pop(old)
    old_ref = f"#/$defs/{old}"
    new_ref = f"#/$defs/{new}"
    _replace_refs(schema, old_ref, new_ref)


def _replace_refs(obj: dict | list, old_ref: str, new_ref: str) -> None:
    """Recursively replace $ref values in a JSON schema."""
    if isinstance(obj, dict):
        if obj.get("$ref") == old_ref:
            obj["$ref"] = new_ref
        for v in obj.values():
            if isinstance(v, (dict, list)):
                _replace_refs(v, old_ref, new_ref)
    elif isinstance(obj, list):
        for item in obj:
            if isinstance(item, (dict, list)):
                _replace_refs(item, old_ref, new_ref)


def _load_preset(preset_name: str) -> dict[str, str]:
    """Load a prompt preset from built-in package data or custom file path.

    Resolution order:
        1. Check built-in presets (``seclens/prompts/<name>.yaml``)
        2. Treat as file path
    """
    # Try built-in preset
    try:
        files = importlib.resources.files("seclens.prompts")
        resource = files.joinpath(f"{preset_name}.yaml")
        content = resource.read_text(encoding="utf-8")
        return _parse_preset_yaml(content, preset_name)
    except (FileNotFoundError, TypeError):
        pass

    # Try as file path
    path = Path(preset_name)
    if path.is_file():
        content = path.read_text(encoding="utf-8")
        return _parse_preset_yaml(content, preset_name)

    # List available built-in presets for the error message
    available = []
    try:
        files = importlib.resources.files("seclens.prompts")
        for item in files.iterdir():
            name = item.name
            if name.endswith(".yaml"):
                available.append(name.removesuffix(".yaml"))
    except Exception:  # noqa: BLE001
        pass
    hint = f" Available presets: {', '.join(sorted(available))}" if available else ""
    raise FileNotFoundError(f"Prompt preset not found: {preset_name!r}.{hint}")


def _parse_preset_yaml(content: str, name: str) -> dict[str, str]:
    """Parse and validate a preset YAML file."""
    data = yaml.safe_load(content)
    if not isinstance(data, dict):
        raise ValueError(f"Invalid preset format in {name!r}: expected a YAML mapping")
    for key in ("system", "user"):
        if key not in data:
            raise ValueError(f"Preset {name!r} missing required key: {key!r}")
    return data
