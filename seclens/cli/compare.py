"""CLI command: seclens compare — role-based cross-model comparison."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from seclens.roles.scorer import generate_multi_role_report, generate_role_report
from seclens.roles.weights import list_roles

console = Console()

_GRADE_COLORS = {"A": "green", "B": "blue", "C": "yellow", "D": "dark_orange", "F": "red"}


def compare_command(
    runs: Annotated[
        list[Path],
        typer.Option("--run", "-r", help="Paths to results JSONL files (pass multiple times)"),
    ],
    role: Annotated[
        Optional[str],
        typer.Option("--role", help=f"Role name ({', '.join(list_roles())})"),
    ] = None,
    all_roles: Annotated[
        bool,
        typer.Option("--all-roles", help="Compare through all roles"),
    ] = False,
    output: Annotated[
        Optional[Path],
        typer.Option("--out", "-o", help="Output JSON file"),
    ] = None,
) -> None:
    """Compare multiple evaluation runs through a role lens."""
    if len(runs) < 2:
        console.print("[red]At least two runs are required for comparison.[/red]")
        raise typer.Exit(code=1)

    if not role and not all_roles:
        console.print("[red]Must specify --role or --all-roles.[/red]")
        console.print(f"[dim]Available roles: {', '.join(list_roles())}[/dim]")
        raise typer.Exit(code=1)

    if role and all_roles:
        console.print("[red]Cannot use both --role and --all-roles.[/red]")
        raise typer.Exit(code=1)

    # Load all result files
    def _load(path: Path) -> list:
        if path.suffix == ".json":
            results_name = path.name.replace("report_", "results_").replace(".json", ".jsonl")
            results_path = path.parent / results_name
            if results_path.exists():
                from seclens.results.io import read_results
                return read_results(results_path)
            return []
        from seclens.results.io import read_results
        return read_results(path)

    model_results: list[tuple[str, list]] = []
    for run_path in runs:
        results = _load(run_path)
        if not results:
            console.print(f"[yellow]Skipping empty file: {run_path}[/yellow]")
            continue
        model_name = results[0].run_metadata.model
        model_results.append((model_name, results))

    if len(model_results) < 2:
        console.print("[red]Need at least two non-empty runs to compare.[/red]")
        raise typer.Exit(code=1)

    if all_roles:
        _compare_all_roles(model_results, output)
    else:
        _compare_single_role(model_results, role, output)


def _compare_single_role(
    model_results: list[tuple[str, list]],
    role: str,
    output: Path | None,
) -> None:
    """Compare models through a single role's lens."""
    reports = []
    for model_name, results in model_results:
        report = generate_role_report(results, role)
        reports.append(report)

    # Sort by score descending
    reports.sort(key=lambda r: -r.decision_score)

    if output:
        import json
        data = [r.model_dump() for r in reports]
        output.write_text(json.dumps(data, indent=2))
        console.print(f"[green]Comparison written to {output}[/green]")
        return

    # Terminal output
    table = Table(show_header=True, header_style="bold magenta", border_style="grey35")
    table.add_column("Rank", justify="center", style="grey74")
    table.add_column("Model", style="grey74")
    table.add_column("Score", justify="right")
    table.add_column("Grade", justify="center")
    table.add_column("Top Strengths", style="dim")

    for rank, report in enumerate(reports, 1):
        grade_color = _GRADE_COLORS.get(report.grade, "white")
        strengths = sorted(report.dimensions, key=lambda d: -d.normalized)[:3]
        strength_str = ", ".join(d.name for d in strengths)
        style = "bold green" if rank == 1 else ""
        table.add_row(
            str(rank),
            report.model,
            f"{report.decision_score:.1f}",
            f"[bold {grade_color}]{report.grade}[/bold {grade_color}]",
            strength_str,
            style=style,
        )

    console.print()
    console.print(Panel(
        table,
        title=f"[bold]{reports[0].role_name} Comparison[/bold]",
        border_style="blue",
    ))
    console.print()


def _compare_all_roles(
    model_results: list[tuple[str, list]],
    output: Path | None,
) -> None:
    """Compare models across all roles (matrix view)."""
    role_names = list_roles()
    model_reports: dict[str, dict[str, object]] = {}

    for model_name, results in model_results:
        multi = generate_multi_role_report(results)
        model_reports[model_name] = multi.reports

    if output:
        import json
        data = {
            model: {role: report.model_dump() for role, report in reports.items()}
            for model, reports in model_reports.items()
        }
        output.write_text(json.dumps(data, indent=2))
        console.print(f"[green]Multi-role comparison written to {output}[/green]")
        return

    # Terminal: matrix view
    table = Table(show_header=True, header_style="bold magenta", border_style="grey35")
    table.add_column("Role", style="cyan")
    for model_name, _ in model_results:
        # Shorten model name for display
        short = model_name.split("/")[-1] if "/" in model_name else model_name
        table.add_column(short, justify="center")

    for role_name in role_names:
        row = []
        for model_name, _ in model_results:
            report = model_reports[model_name].get(role_name)
            if report:
                grade_color = _GRADE_COLORS.get(report.grade, "white")
                row.append(f"{report.decision_score:.1f} ([bold {grade_color}]{report.grade}[/bold {grade_color}])")
            else:
                row.append("—")

        # Use the full role name from the first model's report
        first_report = next(
            (model_reports[m].get(role_name) for m, _ in model_results if model_reports[m].get(role_name)),
            None,
        )
        display_name = first_report.role_name if first_report else role_name
        table.add_row(display_name, *row)

    console.print()
    console.print(Panel(
        table,
        title="[bold]Multi-Role Comparison[/bold]",
        border_style="blue",
    ))
    console.print()
