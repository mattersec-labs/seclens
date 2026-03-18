"""CLI command: seclens report — role-based analysis of evaluation results."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from seclens.results.io import read_results
from seclens.roles.scorer import generate_multi_role_report, generate_role_report
from seclens.roles.weights import list_roles
from seclens.schemas.role_report import MultiRoleReport, RoleReport

console = Console()

_GRADE_COLORS = {"A": "green", "B": "blue", "C": "yellow", "D": "dark_orange", "F": "red"}


def report_command(
    run: Annotated[Path, typer.Option("--run", "-r", help="Path to results JSONL file")],
    role: Annotated[
        Optional[str],
        typer.Option("--role", help=f"Role name ({', '.join(list_roles())})"),
    ] = None,
    all_roles: Annotated[
        bool,
        typer.Option("--all-roles", help="Generate reports for all roles"),
    ] = False,
    output: Annotated[
        Optional[Path],
        typer.Option("--out", "-o", help="Output JSON file"),
    ] = None,
) -> None:
    """Generate a role-based report from evaluation results."""
    if not role and not all_roles:
        console.print("[red]Must specify --role or --all-roles.[/red]")
        console.print(f"[dim]Available roles: {', '.join(list_roles())}[/dim]")
        raise typer.Exit(code=1)

    if role and all_roles:
        console.print("[red]Cannot use both --role and --all-roles.[/red]")
        raise typer.Exit(code=1)

    results = read_results(run)
    if not results:
        console.print("[yellow]No results found in file.[/yellow]")
        raise typer.Exit(code=1)

    if all_roles:
        multi = generate_multi_role_report(results)
        if output:
            output.write_text(multi.model_dump_json(indent=2))
            console.print(f"[green]Multi-role report written to {output}[/green]")
        else:
            _print_multi_role(multi)
    else:
        report = generate_role_report(results, role)
        if output:
            output.write_text(report.model_dump_json(indent=2))
            console.print(f"[green]Role report written to {output}[/green]")
        else:
            _print_single_role(report)


def _print_single_role(report: RoleReport) -> None:
    """Print a single role report to the terminal."""
    grade_color = _GRADE_COLORS.get(report.grade, "white")

    # Header panel
    header = Table.grid(padding=(0, 2))
    header.add_column(style="bold magenta")
    header.add_column()
    header.add_row("Decision Score", f"[bold]{report.decision_score}[/bold] / 100")
    header.add_row("Grade", f"[bold {grade_color}]{report.grade}[/bold {grade_color}]")
    header.add_row("Tasks", str(report.total_tasks))
    header.add_row("Layer", str(report.layer))

    console.print()
    console.print(Panel(
        header,
        title=f"[bold]{report.role_name} Report: {report.model}[/bold]",
        border_style=grade_color,
    ))

    # Category breakdown
    console.print()
    cat_table = Table(show_header=True, header_style="bold magenta", border_style="grey35")
    cat_table.add_column("Category", style="cyan")
    cat_table.add_column("Weight", justify="right", style="grey74")
    cat_table.add_column("Score", justify="right", style="grey74")
    cat_table.add_column("Pct", justify="right", style="grey74")

    for cat in report.categories:
        pct = cat.weighted_score / cat.total_weight * 100 if cat.total_weight > 0 else 0
        cat_table.add_row(
            cat.name,
            f"{cat.total_weight:.1f}",
            f"{cat.weighted_score:.1f}",
            f"{pct:.1f}%",
        )

    console.print(cat_table)

    # Excluded dimensions
    if report.excluded_dimensions:
        console.print()
        console.print(f"[dim]Excluded dimensions (no data): {', '.join(report.excluded_dimensions)}[/dim]")

    # Recommendation
    console.print()
    console.print(f"[bold]Recommendation:[/bold] {report.recommendation}")
    console.print()


def _print_multi_role(multi: MultiRoleReport) -> None:
    """Print all-roles summary to the terminal."""
    table = Table(show_header=True, header_style="bold magenta", border_style="grey35")
    table.add_column("Role", style="cyan")
    table.add_column("Score", justify="right")
    table.add_column("Grade", justify="center")

    for role_name in multi.ranking:
        report = multi.reports[role_name]
        grade_color = _GRADE_COLORS.get(report.grade, "white")
        table.add_row(
            report.role_name,
            f"{report.decision_score:.1f}",
            f"[bold {grade_color}]{report.grade}[/bold {grade_color}]",
        )

    console.print()
    console.print(Panel(
        table,
        title=f"[bold]Role Scores: {multi.model}[/bold]",
        border_style="blue",
    ))
    console.print()
