"""CLI command: seclens compare — compare multiple evaluation runs."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from seclens.results.io import read_results
from seclens.scoring.aggregate import compute_aggregate

console = Console()


def compare_command(
    runs: Annotated[list[Path], typer.Option("--run", "-r", help="Paths to results JSONL files (pass multiple times)")],
) -> None:
    """Compare multiple evaluation runs side by side."""
    if len(runs) < 2:
        console.print("[red]At least two runs are required for comparison.[/red]")
        raise typer.Exit(code=1)

    reports = []
    for run_path in runs:
        results = read_results(run_path)
        if not results:
            console.print(f"[yellow]Skipping empty file: {run_path}[/yellow]")
            continue
        report = compute_aggregate(results, results[0].run_metadata)
        reports.append((run_path.stem, report))

    if len(reports) < 2:
        console.print("[red]Need at least two non-empty runs to compare.[/red]")
        raise typer.Exit(code=1)

    # Sort by leaderboard score descending
    reports.sort(key=lambda x: x[1].leaderboard_score.mean, reverse=True)

    # Ranking table
    console.print()
    console.print("[bold]Run Comparison[/bold]")
    table = Table(show_header=True, header_style="bold")
    table.add_column("Rank", justify="center")
    table.add_column("Run")
    table.add_column("Model")
    table.add_column("Score", justify="right")
    table.add_column("95% CI", justify="right")
    table.add_column("MCC", justify="right")
    table.add_column("CWE Acc", justify="right")
    table.add_column("Cost", justify="right")
    table.add_column("Tasks", justify="right")

    for rank, (name, report) in enumerate(reports, 1):
        ls = report.leaderboard_score
        ci_str = f"[{ls.ci_lower:.3f}, {ls.ci_upper:.3f}]"
        style = "bold green" if rank == 1 else ""
        table.add_row(
            str(rank),
            name,
            report.run_metadata.model,
            f"{ls.mean:.4f}",
            ci_str,
            f"{report.core.verdict_mcc.mean:.4f}",
            f"{report.core.cwe_accuracy.mean:.4f}",
            f"${report.cost.total_cost_usd:.4f}",
            str(report.task_count),
            style=style,
        )

    console.print(table)

    # Significance indicators
    console.print()
    best_name, best_report = reports[0]
    for name, report in reports[1:]:
        best_ci = (best_report.leaderboard_score.ci_lower, best_report.leaderboard_score.ci_upper)
        other_ci = (report.leaderboard_score.ci_lower, report.leaderboard_score.ci_upper)
        if best_ci[0] > other_ci[1]:
            console.print(f"  [green]*[/green] {best_name} significantly better than {name}")
        elif other_ci[0] > best_ci[1]:
            console.print(f"  [red]*[/red] {name} significantly better than {best_name}")
        else:
            console.print(f"  [dim]~[/dim] {best_name} vs {name}: overlapping CIs (not significant)")

    # Best efficiency
    efficiency_reports = [(n, r) for n, r in reports if r.cost.mcc_per_dollar is not None]
    if efficiency_reports:
        best_eff = max(efficiency_reports, key=lambda x: x[1].cost.mcc_per_dollar)
        console.print()
        console.print(f"[bold]Best MCC/Dollar:[/bold] {best_eff[0]} ({best_eff[1].cost.mcc_per_dollar:.2f})")
