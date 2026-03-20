"""Migrate results JSONL files from numeric layers to EvalLayer enum values.

Also renames files from old convention (L1/L2) to new (cip/tu) with prompt preset.

Usage:
    python scripts/migrate_results.py <results_dir_or_file> [--dry-run]
"""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

LAYER_MAP = {1: "code-in-prompt", 2: "tool-use"}
LAYER_SHORT = {"code-in-prompt": "cip", "tool-use": "tu"}


def migrate_jsonl(path: Path, dry_run: bool = False) -> tuple[int, int]:
    """Migrate a single JSONL file. Returns (total_lines, migrated_lines)."""
    lines = path.read_text().strip().splitlines()
    total = len(lines)
    migrated = 0
    new_lines = []

    # First pass: build category lookup from positive tasks
    category_lookup: dict[str, str] = {}
    for line in lines:
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue
        if data.get("task_type") == "true_positive" and data.get("task_category"):
            category_lookup[data["task_id"]] = data["task_category"]

    for line in lines:
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            new_lines.append(line)  # keep corrupt lines as-is
            continue
        meta = data.get("run_metadata", {})
        layer = meta.get("layer")

        if isinstance(layer, int) and layer in LAYER_MAP:
            meta["layer"] = LAYER_MAP[layer]
            migrated += 1

        # Rename lmsecbench_version → seclens_version
        if "lmsecbench_version" in meta and "seclens_version" not in meta:
            meta["seclens_version"] = meta.pop("lmsecbench_version")
            migrated += 1

        # Add paired_with field if missing
        if "paired_with" not in data:
            # Infer from task_id convention: CVE-XXXX-postpatch → CVE-XXXX
            task_id = data.get("task_id", "")
            if task_id.endswith("-postpatch"):
                data["paired_with"] = task_id.removesuffix("-postpatch")
            else:
                data["paired_with"] = None
            migrated += 1

        # Backfill task_category for post-patch tasks from paired positive
        if not data.get("task_category") and data.get("paired_with"):
            paired_cat = category_lookup.get(data["paired_with"])
            if paired_cat:
                data["task_category"] = paired_cat
                migrated += 1

        # CIP: positive tasks should have max_task_points=2 (no location scoring)
        layer_val = meta.get("layer")
        scores = data.get("scores", {})
        if layer_val in (1, "code-in-prompt") and scores.get("max_task_points") == 3:
            scores["max_task_points"] = 2
            scores["location"] = 0.0
            scores["earned"] = round(scores.get("verdict", 0) + scores.get("cwe", 0), 2)
            migrated += 1

        new_lines.append(json.dumps(data, separators=(",", ":")))

    if not dry_run and migrated > 0:
        path.write_text("\n".join(new_lines) + "\n")

    return total, migrated


def rename_file(path: Path, dry_run: bool = False) -> Path | None:
    """Rename file from old convention to new. Returns new path or None."""
    name = path.name

    # Replace L1/L2 with cip/tu
    new_name = name.replace("_L1_", "_cip_").replace("_L2_", "_tu_")

    if new_name == name:
        return None

    new_path = path.parent / new_name
    if not dry_run:
        shutil.move(str(path), str(new_path))

    return new_path


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: python scripts/migrate_results.py <results_dir_or_file> [--dry-run]")
        sys.exit(1)

    target = Path(sys.argv[1])
    dry_run = "--dry-run" in sys.argv

    if dry_run:
        print("[DRY RUN] No files will be modified.\n")

    files: list[Path] = []
    if target.is_file():
        files = [target]
    elif target.is_dir():
        files = sorted(target.glob("*.jsonl"))
    else:
        print(f"Not found: {target}")
        sys.exit(1)

    if not files:
        print("No JSONL files found.")
        sys.exit(0)

    print(f"Processing {len(files)} file(s)...\n")

    for path in files:
        total, migrated = migrate_jsonl(path, dry_run)
        status = f"migrated {migrated}/{total} entries" if migrated > 0 else "already current"
        print(f"  {path.name}: {status}")

        new_path = rename_file(path, dry_run)
        if new_path:
            print(f"    renamed → {new_path.name}")

        # Handle debug file if exists
        debug_path = path.parent / f"debug_{path.name}"
        if debug_path.exists():
            d_total, d_migrated = migrate_jsonl(debug_path, dry_run)
            d_status = f"migrated {d_migrated}/{d_total}" if d_migrated > 0 else "already current"
            print(f"  debug_{path.name}: {d_status}")

            debug_new = rename_file(debug_path, dry_run)
            if debug_new:
                print(f"    renamed → {debug_new.name}")

    print("\nDone." if not dry_run else "\n[DRY RUN] Done. No changes made.")


if __name__ == "__main__":
    main()
