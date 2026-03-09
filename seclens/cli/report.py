"""CLI command: seclens report — generate aggregate metrics from results."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console

from seclens.results.io import read_results
from seclens.scoring.aggregate import compute_aggregate

console = Console()


def report_command(
    run: Annotated[Path, typer.Option("--run", "-r", help="Path to results JSONL file")],
    output: Annotated[Optional[Path], typer.Option(
        "--out", "-o", help="Output path (.json for JSON, omit for terminal)",
    )] = None,
) -> None:
    """Generate an aggregate report from evaluation results."""
    results = read_results(run)

    if not results:
        console.print("[yellow]No results found in file.[/yellow]")
        raise typer.Exit(code=1)

    run_metadata = results[0].run_metadata
    report = compute_aggregate(results, run_metadata)

    if output is not None and output.suffix == ".json":
        output.write_text(report.model_dump_json(indent=2))
        console.print(f"[green]Report written to {output}[/green]")
    else:
        _print_terminal_report(report)


def _print_terminal_report(report) -> None:  # noqa: ANN001
    """Print the aggregate report to the terminal using Rich."""
    from rich.table import Table

    # Leaderboard score
    ls = report.leaderboard_score
    console.print()
    console.print("[bold]Leaderboard Score[/bold]")
    console.print(f"  Score: {ls.mean:.4f} (95% CI: [{ls.ci_lower:.4f}, {ls.ci_upper:.4f}])")

    # Core metrics
    core = report.core
    console.print()
    console.print("[bold]Core Metrics[/bold]")
    table = Table(show_header=True, header_style="bold")
    table.add_column("Metric")
    table.add_column("Mean", justify="right")
    table.add_column("95% CI", justify="right")
    table.add_row("Tasks", str(core.task_count), "")
    table.add_row(
        "Verdict MCC",
        f"{core.verdict_mcc.mean:.4f}",
        f"[{core.verdict_mcc.ci_lower:.4f}, {core.verdict_mcc.ci_upper:.4f}]",
    )
    table.add_row(
        "CWE Accuracy",
        f"{core.cwe_accuracy.mean:.4f}",
        f"[{core.cwe_accuracy.ci_lower:.4f}, {core.cwe_accuracy.ci_upper:.4f}]",
    )
    table.add_row(
        "Location Accuracy",
        f"{core.location_accuracy.mean:.4f}",
        f"[{core.location_accuracy.ci_lower:.4f}, {core.location_accuracy.ci_upper:.4f}]",
    )
    console.print(table)

    # Cost
    cost = report.cost
    console.print()
    console.print("[bold]Cost Metrics[/bold]")
    cost_table = Table(show_header=True, header_style="bold")
    cost_table.add_column("Metric")
    cost_table.add_column("Value", justify="right")
    cost_table.add_row("Total Cost", f"${cost.total_cost_usd:.4f}")
    cost_table.add_row("Avg Cost/Task", f"${cost.avg_cost_per_task:.4f}")
    if cost.mcc_per_dollar is not None:
        cost_table.add_row("MCC/Dollar", f"{cost.mcc_per_dollar:.2f}")
    console.print(cost_table)

    # Summary
    console.print()
    console.print(f"[bold]Total:[/bold] {report.task_count} tasks | "
                  f"{report.errors} errors | {report.parse_failures} parse failures")
