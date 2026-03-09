"""CLI command: seclens run — execute an evaluation run."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Optional

import typer
from engine_harness import create_adapter
from rich.console import Console

from seclens.dataset.loader import load_dataset
from seclens.evaluation.config import RunConfig
from seclens.evaluation.runner import evaluate_task
from seclens.results.io import get_completed_ids, write_result
from seclens.sandbox.manager import SandboxManager
from seclens.worker import WorkerPool

console = Console()


def run_command(
    model: Annotated[str, typer.Option(
        "--model", "-m", help="Model identifier (e.g. anthropic/claude-sonnet-4-20250514)",
    )],
    dataset: Annotated[str, typer.Option("--dataset", "-d", help="Dataset string (HF repo:split) or local JSONL path")],
    prompt: Annotated[str, typer.Option("--prompt", "-p", help="Prompt preset name or custom YAML path")] = "base",
    layer: Annotated[int, typer.Option("--layer", "-l", help="Evaluation layer (1=code-in-prompt, 2=tool-use)")] = 2,
    mode: Annotated[str, typer.Option("--mode", help="Evaluation mode (guided or open)")] = "guided",
    workers: Annotated[int, typer.Option("--workers", "-w", help="Number of parallel workers")] = 5,
    out: Annotated[Optional[Path], typer.Option("--out", "-o", help="Output JSONL path")] = None,
    max_cost: Annotated[Optional[float], typer.Option("--max-cost", help="Maximum budget in USD")] = None,
    max_turns: Annotated[int, typer.Option("--max-turns", help="Maximum LLM turns per task")] = 20,
    resume: Annotated[bool, typer.Option("--resume", help="Resume from existing output file")] = False,
    seed: Annotated[int, typer.Option("--seed", help="Random seed for reproducibility")] = 42,
    dry_run: Annotated[bool, typer.Option(
        "--dry-run", help="Validate config and show task count without running",
    )] = False,
) -> None:
    """Run an evaluation benchmark against a model."""
    if layer not in (1, 2):
        console.print(f"[red]Invalid layer: {layer}. Must be 1 or 2.[/red]")
        raise typer.Exit(code=1)
    if mode not in ("guided", "open"):
        console.print(f"[red]Invalid mode: {mode!r}. Must be 'guided' or 'open'.[/red]")
        raise typer.Exit(code=1)

    config = RunConfig(
        model=model,
        dataset=dataset,
        prompt=prompt,
        layer=layer,
        mode=mode,
        max_turns=max_turns,
        max_cost=max_cost,
        workers=workers,
        seed=seed,
        output=out,
        resume=resume,
        dry_run=dry_run,
    )

    output_path = config.output or _default_output_path(config)

    console.print(f"[bold]Model:[/bold] {config.model}")
    console.print(f"[bold]Dataset:[/bold] {config.dataset}")
    console.print(f"[bold]Layer:[/bold] {config.layer} | [bold]Mode:[/bold] {config.mode}")
    console.print(f"[bold]Output:[/bold] {output_path}")

    # Load tasks
    tasks = load_dataset(config.dataset)
    console.print(f"[bold]Tasks loaded:[/bold] {len(tasks)}")

    # Resumability
    completed_ids: set[str] = set()
    if config.resume and output_path.exists():
        completed_ids = get_completed_ids(output_path)
        console.print(f"[bold]Resuming:[/bold] {len(completed_ids)} tasks already completed")

    pending_tasks = [t for t in tasks if t.id not in completed_ids]
    console.print(f"[bold]Tasks to run:[/bold] {len(pending_tasks)}")

    if config.dry_run:
        console.print("[yellow]Dry run — exiting without evaluation.[/yellow]")
        raise typer.Exit()

    if not pending_tasks:
        console.print("[green]All tasks already completed.[/green]")
        raise typer.Exit()

    # Create adapter and sandbox manager
    adapter = create_adapter(config.model)
    sandbox_manager = SandboxManager() if config.layer == 2 else None

    # Evaluate tasks
    def _evaluate(task):  # noqa: ANN001, ANN202
        result = evaluate_task(task, adapter, config, sandbox_manager=sandbox_manager)
        write_result(output_path, result)
        return result

    if config.workers == 1:
        results = []
        for task in pending_tasks:
            result = _evaluate(task)
            results.append(result)
            _print_task_status(result)
    else:
        pool = WorkerPool(num_workers=config.workers)
        results = pool.run(
            items=pending_tasks,
            evaluate_fn=_evaluate,
            on_complete=_print_task_status,
        )

    # Summary
    errors = sum(1 for r in results if r.error)
    total_cost = sum(r.metrics.cost_usd for r in results)
    console.print()
    console.print("[bold green]Evaluation complete![/bold green]")
    console.print(f"  Tasks: {len(results)} | Errors: {errors} | Cost: ${total_cost:.4f}")
    console.print(f"  Results: {output_path}")


def _default_output_path(config: RunConfig) -> Path:
    """Generate a default output filename from config."""
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    model_slug = config.model.replace("/", "_")
    return Path(f"results_{model_slug}_L{config.layer}_{config.mode}_{timestamp}.jsonl")


def _print_task_status(result) -> None:  # noqa: ANN001
    """Print a single-line status for a completed task."""
    if result.error:
        console.print(f"  [red]✗[/red] {result.task_id}: {result.error}")
    else:
        earned = result.scores.earned
        max_pts = result.scores.max_task_points
        console.print(f"  [green]✓[/green] {result.task_id}: {earned}/{max_pts}")
