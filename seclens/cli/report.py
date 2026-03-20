"""CLI command: seclens report — role-based analysis of evaluation results."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from seclens.roles.scorer import generate_multi_role_report, generate_role_report
from seclens.roles.weights import list_roles
from seclens.schemas.role_report import MultiRoleReport, RoleReport

console = Console()


def _load_results(path: Path) -> list:
    """Load TaskResults from a report JSON (via JSONL fallback) or results JSONL."""
    if path.suffix == ".json":
        # Model report JSON — need to load the original results JSONL
        # Look for the corresponding results file
        results_name = path.name.replace("report_", "results_").replace(".json", ".jsonl")
        results_path = path.parent / results_name
        if results_path.exists():
            from seclens.results.io import read_results
            return read_results(results_path)
        # Fallback: can't find results file
        console.print(f"[yellow]Cannot find results JSONL for {path.name}. Looking for {results_name}[/yellow]")
        raise typer.Exit(code=1)
    else:
        from seclens.results.io import read_results
        return read_results(path)

_GRADE_COLORS = {"A": "green", "B": "blue", "C": "yellow", "D": "dark_orange", "F": "red"}


def report_command(
    run: Annotated[Path, typer.Option("--run", "-r", help="Path to report JSON or results JSONL")],
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

    results = _load_results(run)
    if not results:
        console.print("[yellow]No results found.[/yellow]")
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
            _print_single_role(report, results)


def _print_single_role(report: RoleReport, results: list | None = None) -> None:
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

    # Dimension category breakdown
    console.print()
    cat_table = Table(show_header=True, header_style="bold magenta", border_style="grey35")
    cat_table.add_column("Category", style="cyan")
    cat_table.add_column("Weight", justify="right", style="grey74")
    cat_table.add_column("Score", justify="right", style="grey74")
    cat_table.add_column("Percentage", justify="right", style="grey74")

    for cat in report.categories:
        pct = cat.weighted_score / cat.total_weight * 100 if cat.total_weight > 0 else 0
        cat_table.add_row(
            cat.name,
            f"{cat.total_weight:.1f}",
            f"{cat.weighted_score:.1f}",
            f"{pct:.1f}%",
        )

    console.print(cat_table)

    # Per vulnerability category and per language breakdowns
    if results:
        from seclens.scoring.model_report import _compute_group_breakdowns
        from seclens.schemas.task import TaskType

        # Resolve categories via paired_with for tasks missing them
        category_lookup = {r.task_id: r.task_category for r in results if r.task_category}

        def _resolve_category(r):
            if r.task_category:
                return r.task_category
            if r.paired_with and r.paired_with in category_lookup:
                return category_lookup[r.paired_with]
            return "uncategorized"

        negative_results = [r for r in results if r.task_type != TaskType.TRUE_POSITIVE]

        by_category = _compute_group_breakdowns(results, _resolve_category)
        if by_category:
            console.print()
            console.print("[bold]Per Vulnerability Category[/bold]")
            vcat_table = Table(show_header=True, header_style="bold magenta", border_style="grey35")
            vcat_table.add_column("Category", style="cyan")
            vcat_table.add_column("Tasks", justify="right", style="grey74")
            vcat_table.add_column("Detection Rate", justify="right", style="grey74")
            vcat_table.add_column("Precision", justify="right", style="grey74")
            vcat_table.add_column("F1", justify="right", style="grey74")
            vcat_table.add_column("CWE Acc", justify="right", style="grey74")
            vcat_table.add_column("IoU", justify="right", style="grey74")
            vcat_table.add_column("Actionable", justify="right", style="grey74")
            for name, bd in sorted(by_category.items()):
                vcat_table.add_row(
                    name, str(bd.task_count),
                    f"{bd.recall*100:.1f}%", f"{bd.precision*100:.1f}%", f"{bd.f1*100:.1f}%",
                    f"{bd.cwe_accuracy*100:.1f}%", f"{bd.mean_location_iou*100:.1f}%", f"{bd.actionable_rate*100:.1f}%",
                )
            console.print(vcat_table)

        by_language = _compute_group_breakdowns(results, lambda r: r.task_language)
        if by_language:
            console.print()
            console.print("[bold]Per Language[/bold]")
            lang_table = Table(show_header=True, header_style="bold magenta", border_style="grey35")
            lang_table.add_column("Language", style="cyan")
            lang_table.add_column("Tasks", justify="right", style="grey74")
            lang_table.add_column("Detection Rate", justify="right", style="grey74")
            lang_table.add_column("Precision", justify="right", style="grey74")
            lang_table.add_column("F1", justify="right", style="grey74")
            lang_table.add_column("CWE Acc", justify="right", style="grey74")
            lang_table.add_column("IoU", justify="right", style="grey74")
            for name, bd in sorted(by_language.items()):
                lang_table.add_row(
                    name, str(bd.task_count),
                    f"{bd.recall*100:.1f}%", f"{bd.precision*100:.1f}%", f"{bd.f1*100:.1f}%",
                    f"{bd.cwe_accuracy*100:.1f}%", f"{bd.mean_location_iou*100:.1f}%",
                )
            console.print(lang_table)

        by_postpatch = _compute_group_breakdowns(negative_results, _resolve_category)
        if by_postpatch:
            console.print()
            console.print("[bold]Post-Patch & Negative Tasks[/bold] [dim](verdict accuracy)[/dim]")
            pp_table = Table(show_header=True, header_style="bold magenta", border_style="grey35")
            pp_table.add_column("Category", style="cyan")
            pp_table.add_column("Tasks", justify="right", style="grey74")
            pp_table.add_column("Verdict Acc", justify="right", style="grey74")
            for name, bd in sorted(by_postpatch.items()):
                pp_table.add_row(name, str(bd.task_count), f"{bd.verdict_accuracy*100:.1f}%")
            console.print(pp_table)

        # Legend
        console.print()
        console.print("[dim][bold]Detection Rate:[/bold] % of real vulnerabilities detected | "
                      "[bold]Precision:[/bold] % of flagged findings that are real | "
                      "[bold]F1:[/bold] balanced precision/recall[/dim]")
        console.print("[dim][bold]CWE Acc:[/bold] correct vulnerability type identification | "
                      "[bold]IoU:[/bold] location precision | "
                      "[bold]Actionable:[/bold] complete findings (verdict + CWE + location)[/dim]")

    # Excluded dimensions — show human-readable names
    if report.excluded_dimensions:
        from seclens.roles.dimensions import DIMENSION_NAMES
        excluded_names = [DIMENSION_NAMES.get(d, d) for d in report.excluded_dimensions]
        console.print()
        console.print(f"[dim]Excluded dimensions (no data): {', '.join(excluded_names)}[/dim]")

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
