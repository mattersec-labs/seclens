"""CLI command: seclens summary — aggregate metrics from a single run."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console

from seclens.schemas.model_report import ModelReport

console = Console()


def _load_report(path: Path) -> ModelReport:
    """Load a model report from JSON or generate from results JSONL."""
    if path.suffix == ".json":
        return ModelReport.model_validate_json(path.read_text())

    # Legacy: generate from results JSONL
    from seclens.results.io import read_results
    from seclens.scoring.model_report import generate_model_report

    results = read_results(path)
    if not results:
        console.print("[yellow]No results found in file.[/yellow]")
        raise typer.Exit(code=1)
    return generate_model_report(results, results[0].run_metadata)


def summary_command(
    run: Annotated[Path, typer.Option("--run", "-r", help="Path to report JSON or results JSONL file")],
    output: Annotated[Optional[Path], typer.Option(
        "--out", "-o", help="Output path (.json for JSON, omit for terminal)",
    )] = None,
) -> None:
    """Show aggregate metrics from a single evaluation run."""
    report = _load_report(run)

    if output is not None and output.suffix == ".json":
        output.write_text(report.model_dump_json(indent=2))
        console.print(f"[green]Report written to {output}[/green]")
    else:
        _print_terminal_report(report)


def _print_terminal_report(report: ModelReport) -> None:
    """Print the aggregate report to the terminal using Rich."""
    from rich.table import Table

    # Leaderboard score
    ls = report.leaderboard_score
    console.print()
    console.print("[bold]Leaderboard Score[/bold]")
    console.print(f"  Score: {ls.mean * 100:.2f}% (95% CI: [{ls.ci_lower * 100:.2f}%, {ls.ci_upper * 100:.2f}%])")

    # Core metrics
    core = report.core
    console.print()
    console.print("[bold]Core Metrics[/bold]")
    table = Table(show_header=True, header_style="bold magenta", border_style="grey35")
    table.add_column("Metric", style="cyan")
    table.add_column("Mean", justify="right", style="grey74")
    table.add_column("95% CI", justify="right", style="grey74")
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
    cost_table = Table(show_header=True, header_style="bold magenta", border_style="grey35")
    cost_table.add_column("Metric", style="cyan")
    cost_table.add_column("Value", justify="right", style="grey74")
    cost_table.add_row("Total Cost", f"${cost.total_cost_usd:.4f}")
    cost_table.add_row("Avg Cost/Task", f"${cost.avg_cost_per_task:.4f}")
    if cost.mcc_per_dollar is not None:
        cost_table.add_row("MCC/Dollar", f"{cost.mcc_per_dollar:.2f}")
    console.print(cost_table)

    # Per vulnerability category (true_positive tasks only)
    if report.by_category:
        console.print()
        console.print("[bold]Per Vulnerability Category[/bold] [dim](true positive tasks)[/dim]")
        cat_table = Table(show_header=True, header_style="bold magenta", border_style="grey35")
        cat_table.add_column("Category", style="cyan")
        cat_table.add_column("Tasks", justify="right", style="grey74")
        cat_table.add_column("Recall", justify="right", style="grey74")
        cat_table.add_column("Precision", justify="right", style="grey74")
        cat_table.add_column("F1", justify="right", style="grey74")
        cat_table.add_column("CWE Acc", justify="right", style="grey74")
        cat_table.add_column("IoU", justify="right", style="grey74")
        cat_table.add_column("Actionable", justify="right", style="grey74")
        for name, bd in sorted(report.by_category.items()):
            cat_table.add_row(
                name, str(bd.task_count),
                f"{bd.recall:.2f}", f"{bd.precision:.2f}", f"{bd.f1:.2f}",
                f"{bd.cwe_accuracy:.2f}", f"{bd.mean_location_iou:.2f}", f"{bd.actionable_rate:.2f}",
            )
        console.print(cat_table)

    # Per language (true_positive tasks only)
    if report.by_language:
        console.print()
        console.print("[bold]Per Language[/bold] [dim](true positive tasks)[/dim]")
        lang_table = Table(show_header=True, header_style="bold magenta", border_style="grey35")
        lang_table.add_column("Language", style="cyan")
        lang_table.add_column("Tasks", justify="right", style="grey74")
        lang_table.add_column("Recall", justify="right", style="grey74")
        lang_table.add_column("Precision", justify="right", style="grey74")
        lang_table.add_column("F1", justify="right", style="grey74")
        lang_table.add_column("CWE Acc", justify="right", style="grey74")
        lang_table.add_column("IoU", justify="right", style="grey74")
        for name, bd in sorted(report.by_language.items()):
            lang_table.add_row(
                name, str(bd.task_count),
                f"{bd.recall:.2f}", f"{bd.precision:.2f}", f"{bd.f1:.2f}",
                f"{bd.cwe_accuracy:.2f}", f"{bd.mean_location_iou:.2f}",
            )
        console.print(lang_table)

    # Post-patch / negative tasks
    if report.by_postpatch:
        console.print()
        console.print("[bold]Post-Patch & Negative Tasks[/bold] [dim](verdict accuracy)[/dim]")
        pp_table = Table(show_header=True, header_style="bold magenta", border_style="grey35")
        pp_table.add_column("Category", style="cyan")
        pp_table.add_column("Tasks", justify="right", style="grey74")
        pp_table.add_column("Verdict Acc", justify="right", style="grey74")
        for name, bd in sorted(report.by_postpatch.items()):
            verdict_acc = bd.recall  # for negative tasks, recall = correct dismissal rate
            pp_table.add_row(name, str(bd.task_count), f"{verdict_acc:.2f}")
        console.print(pp_table)

    # Legend
    _print_legend()

    # Summary
    console.print()
    console.print(f"[bold]Total:[/bold] {report.total_tasks} tasks | "
                  f"{report.errors} errors | {report.parse_failures} parse failures")


def _print_legend() -> None:
    """Print metric legend."""
    console.print()
    console.print("[dim]Recall: % of real vulnerabilities detected | "
                  "Precision: % of flagged findings that are real | "
                  "F1: balanced precision/recall[/dim]")
    console.print("[dim]CWE Acc: correct vulnerability type identification | "
                  "IoU: location precision (0-1) | "
                  "Actionable: complete findings (verdict + CWE + location)[/dim]")
