"""Generate model report JSONs from results JSONL files.

Usage:
    python scripts/generate_reports.py <results_file_or_dir>
    python scripts/generate_reports.py out/                     # generates missing reports
    python scripts/generate_reports.py out/results_model.jsonl  # single file
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from seclens.results.io import read_results
from seclens.scoring.model_report import generate_model_report


def _report_path_for(results_path: Path) -> Path:
    return results_path.parent / results_path.name.replace("results_", "report_").replace(".jsonl", ".json")


def _generate(results_path: Path) -> None:
    report_path = _report_path_for(results_path)

    results = read_results(results_path)
    if not results:
        print(f"  {results_path.name}: empty — skipped")
        return

    run_metadata = results[0].run_metadata
    report = generate_model_report(results, run_metadata)
    report_path.write_text(report.model_dump_json(indent=2))
    print(f"  {results_path.name} → {report_path.name}")


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: python scripts/generate_reports.py <results_file_or_dir>")
        sys.exit(1)

    target = Path(sys.argv[1])

    if target.is_file():
        print(f"Generating report for {target.name}...")
        _generate(target)
    elif target.is_dir():
        results_files = sorted(target.glob("results_*.jsonl"))
        if not results_files:
            print(f"No results_*.jsonl files found in {target}")
            sys.exit(0)

        # Find missing reports
        missing = [f for f in results_files if not _report_path_for(f).exists()]

        if not missing:
            print(f"All {len(results_files)} result files already have reports.")
            sys.exit(0)

        print(f"Generating {len(missing)} missing reports (of {len(results_files)} total)...\n")
        for f in missing:
            _generate(f)
    else:
        print(f"Not found: {target}")
        sys.exit(1)

    print("\nDone.")


if __name__ == "__main__":
    main()
