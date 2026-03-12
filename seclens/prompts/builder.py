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
        layer: 1 (code in prompt) or 2 (tool-use).
        code_block: Function source code (Layer 1) or ``None`` (Layer 2).

    Returns:
        List of Messages with system and user prompts.
    """
    preset = _load_preset(preset_name)
    template_vars = _build_template_vars(task, mode, code_block or "")

    user_key = f"user_l{layer}" if f"user_l{layer}" in preset else "user"

    system_content = preset["system"].format(**template_vars)
    user_content = preset[user_key].format(**template_vars)

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
        for prop in def_obj.get("properties", {}).values():
            prop.pop("title", None)
    for prop in schema.get("properties", {}).values():
        prop.pop("title", None)

    # Rename internal class name to neutral name in $defs and $ref pointers
    defs = schema.get("$defs", {})
    if "EvidenceOutput" in defs:
        defs["Evidence"] = defs.pop("EvidenceOutput")

    schema_str = json.dumps(schema, indent=2)
    schema_str = schema_str.replace("#/$defs/EvidenceOutput", "#/$defs/Evidence")

    return (
        "You MUST respond with a JSON object matching this schema:\n"
        f"```json\n{schema_str}\n```\n\n"
        "Example for a vulnerable function:\n"
        '```json\n{"vulnerable": true, "cwe": "<CWE-ID>", '
        '"location": {"file": "<file_path>", "line_start": 0, "line_end": 0}, '
        '"evidence": {"source": "<source>", "sink": "<sink>", '
        '"flow": ["<step1>", "<step2>"]}, '
        '"reasoning": "<explanation>"}\n```\n\n'
        "Example for a non-vulnerable function:\n"
        '```json\n{"vulnerable": false, "cwe": null, "location": null, '
        '"evidence": null, "reasoning": "<explanation>"}\n```'
    )


def _build_template_vars(
    task: Task, mode: str, code_block: str,
) -> dict[str, str]:
    """Build the template variable dictionary for prompt formatting."""
    category_hint = ""
    if mode == "guided" and task.ground_truth.category:
        category_hint = f"Focus your analysis on potential {task.ground_truth.category} vulnerabilities."

    return {
        "function_name": task.target.function,
        "file_path": task.target.file,
        "line_start": str(task.target.line_start),
        "line_end": str(task.target.line_end),
        "language": task.repository.language,
        "category_hint": category_hint,
        "code_block": code_block,
        "output_format": generate_output_format(),
    }


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
    """Parse and validate a preset YAML file.

    Required: ``system`` key.  For user prompts, either a shared ``user`` key
    or both ``user_l1`` and ``user_l2`` must be present.  Layer-specific user
    keys take precedence when the matching layer is requested.
    """
    data = yaml.safe_load(content)
    if not isinstance(data, dict):
        raise ValueError(f"Invalid preset format in {name!r}: expected a YAML mapping")
    if "system" not in data:
        raise ValueError(f"Preset {name!r} missing required key: 'system'")
    has_shared_user = "user" in data
    has_layer_users = "user_l1" in data and "user_l2" in data
    if not has_shared_user and not has_layer_users:
        raise ValueError(
            f"Preset {name!r} must have 'user' or both 'user_l1' and 'user_l2'"
        )
    return data
