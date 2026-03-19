"""CLI command: seclens run — execute an evaluation run."""

from __future__ import annotations

import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Optional

import typer
from engine_harness import create_adapter
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    TextColumn,
    TimeElapsedColumn,
)
from rich.spinner import Spinner
from rich.table import Table
from rich.text import Text

from seclens.dataset.loader import load_dataset
from seclens.evaluation.config import RunConfig
from seclens.evaluation.runner import EvalOutput, evaluate_task
from seclens.results.io import get_completed_ids, read_results, write_result
from seclens.sandbox.manager import SandboxManager
from seclens.schemas.task import Task
from seclens.worker import WorkerPool

console = Console()

OUT_DIR = Path("out")


def run_command(
    model: Annotated[
        str,
        typer.Option(
            "--model",
            "-m",
            help="Model identifier (e.g. anthropic/claude-sonnet-4-20250514)",
        ),
    ],
    dataset: Annotated[
        str,
        typer.Option(
            "--dataset",
            "-d",
            help="Dataset string (HF repo:split) or local JSONL path",
        ),
    ],
    prompt: Annotated[
        str,
        typer.Option(
            "--prompt",
            "-p",
            help="Prompt preset name or custom YAML path",
        ),
    ] = "base",
    layer: Annotated[
        int,
        typer.Option(
            "--layer",
            "-l",
            help="Evaluation layer (1=code-in-prompt, 2=tool-use)",
        ),
    ] = 2,
    mode: Annotated[
        str,
        typer.Option(
            "--mode",
            help="Evaluation mode (guided or open)",
        ),
    ] = "guided",
    workers: Annotated[
        int,
        typer.Option(
            "--workers",
            "-w",
            help="Number of parallel workers",
        ),
    ] = 5,
    max_cost: Annotated[
        Optional[float],
        typer.Option(
            "--max-cost",
            help="Maximum budget in USD",
        ),
    ] = None,
    max_turns: Annotated[
        int,
        typer.Option(
            "--max-turns",
            help="Maximum LLM turns per task",
        ),
    ] = 200,
    resume: Annotated[
        bool,
        typer.Option(
            "--resume",
            help="Resume from existing output file",
        ),
    ] = False,
    seed: Annotated[
        int,
        typer.Option(
            "--seed",
            help="Random seed for reproducibility",
        ),
    ] = 42,
    dry_run: Annotated[
        bool,
        typer.Option(
            "--dry-run",
            help="Validate config and show task count without running",
        ),
    ] = False,
    location_recall_threshold: Annotated[
        float,
        typer.Option(
            "--location-recall-threshold",
            help="Minimum GT recall for location credit (0.0–1.0)",
        ),
    ] = 1.0,
    debug: Annotated[
        bool,
        typer.Option(
            "--debug",
            help="Save full message chains to a debug JSONL file",
        ),
    ] = False,
) -> None:
    """Run an evaluation benchmark against a model."""
    if layer not in (1, 2):
        console.print(f"[red]Invalid layer: {layer}. Must be 1 or 2.[/red]")
        raise typer.Exit(code=1)
    if mode not in ("guided", "open"):
        console.print(
            f"[red]Invalid mode: {mode!r}. Must be 'guided' or 'open'.[/red]",
        )
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
        resume=resume,
        dry_run=dry_run,
        location_recall_threshold=location_recall_threshold,
    )

    result_filename = _result_filename(config)
    output_path = OUT_DIR / result_filename
    debug_path = OUT_DIR / f"debug_{result_filename}" if debug else None

    OUT_DIR.mkdir(exist_ok=True)

    # Load tasks
    tasks = load_dataset(config.dataset)

    # Resumability
    completed_ids: set[str] = set()
    if config.resume and output_path.exists():
        completed_ids = get_completed_ids(output_path)

    pending_tasks = [t for t in tasks if t.id not in completed_ids]

    # Run config panel (includes task count)
    _print_config(config, output_path, debug_path, len(tasks), len(completed_ids))
    console.print()

    if config.dry_run:
        console.print("[yellow]Dry run — exiting without evaluation.[/yellow]")
        raise typer.Exit()

    if not pending_tasks:
        console.print("[green]All tasks already completed.[/green]")
        raise typer.Exit()

    # Create adapter and sandbox manager
    try:
        adapter = create_adapter(config.model)
    except (ValueError, KeyError, ImportError) as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1) from None
    sandbox_manager = SandboxManager() if config.layer == 2 else None

    results: list = []
    interrupted = False

    # -----------------------------------------------------------------------
    # Live display: progress bar + task status table, updated in real-time.
    # -----------------------------------------------------------------------

    state_lock = threading.Lock()
    task_states: dict[str, dict[str, str]] = {}

    progress = Progress(
        TextColumn("[bold blue]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
    )

    _HEADER = "bold magenta"
    _TEXT = "grey74"

    def _build_task_table() -> Table:
        """Build the task status table from current state."""
        table = Table(
            expand=True,
            show_header=True,
            header_style=_HEADER,
            border_style="grey35",
        )
        table.add_column("Status", width=10, no_wrap=True, justify="center")
        table.add_column("Task ID", ratio=4, style=_TEXT)
        table.add_column("Category", ratio=1, style=_TEXT)
        table.add_column("Repository", ratio=1, style=_TEXT)
        table.add_column("Language", width=10, style=_TEXT)
        table.add_column("Score", width=15, justify="right", style=_TEXT)

        with state_lock:
            for tid, state in task_states.items():
                task_id_display = state["task_id"]
                # For RUNNING tasks in debug mode, dynamically resolve sandbox path
                if debug and state.get("running") and sandbox_manager:
                    sandbox_dir = sandbox_manager.get_task_dir(tid)
                    if sandbox_dir:
                        task_id_display += f"\n[dim]Sandbox: {sandbox_dir}[/dim]"
                table.add_row(
                    state["status"],
                    task_id_display,
                    state["category"],
                    state["repo"],
                    state["language"],
                    state["score"],
                )
        return table

    def _build_display() -> Table:
        """Build combined progress bar + task table as a grid layout."""
        layout = Table.grid(expand=True)

        # Wrap progress bar in a fixed-width container matching the config panel
        if _config_panel_width > 0:
            progress_box = Table.grid(expand=False)
            progress_box.add_column(width=_config_panel_width)
            progress_box.add_row(progress)
            layout.add_row(progress_box)
        else:
            layout.add_row(progress)

        layout.add_row("")  # spacing
        task_table = _build_task_table()
        if task_table.row_count:
            layout.add_row(task_table)
        return layout

    class _DynamicDisplay:
        """Renderable that rebuilds the layout on each Live refresh."""

        def __rich__(self) -> Table:
            return _build_display()

    display = _DynamicDisplay()
    ptask = None

    def _mark_running(task: Task) -> None:
        with state_lock:
            task_states[task.id] = {
                "task_id": task.id,
                "category": task.ground_truth.category,
                "repo": _repo_name(task.repository.url),
                "language": task.repository.language,
                "status": Spinner("dots", style="cyan"),
                "score": "—",
                "running": True,
            }

    def _evaluate(task: Task):  # noqa: ANN202
        _mark_running(task)
        eval_output = evaluate_task(
            task,
            adapter,
            config,
            sandbox_manager=sandbox_manager,
        )
        write_result(output_path, eval_output.result)
        if debug_path:
            _write_debug(debug_path, task.id, eval_output.messages)
        return task, eval_output

    def _on_task_done(task: Task, eval_output: EvalOutput) -> None:
        result = eval_output.result
        results.append(result)

        if result.error:
            status = Text("✘", style="bold red")
            task_id_display = f"{task.id}\n[dim red]{result.error}[/dim red]"
            score = _format_score(result.scores.earned, result.scores.max_task_points)
        else:
            status = Text("✔", style="bold green")
            task_id_display = task.id
            score = _format_score(result.scores.earned, result.scores.max_task_points)

        with state_lock:
            task_states[task.id] = {
                "task_id": task_id_display,
                "category": task.ground_truth.category,
                "repo": _repo_name(task.repository.url),
                "language": task.repository.language,
                "status": status,
                "score": score,
                "running": False,
            }
        progress.advance(ptask)

    try:
        with Live(
            display,
            console=console,
            refresh_per_second=12,
        ):
            ptask = progress.add_task("Evaluating", total=len(pending_tasks))

            if config.workers == 1:
                for task_item in pending_tasks:
                    task_item, eval_output = _evaluate(task_item)
                    _on_task_done(task_item, eval_output)
            else:
                pool = WorkerPool(num_workers=config.workers)

                def _on_complete(pair):  # noqa: ANN001, ANN202
                    t, eo = pair
                    _on_task_done(t, eo)

                pool.run(
                    items=pending_tasks,
                    evaluate_fn=_evaluate,
                    on_complete=_on_complete,
                )

    except KeyboardInterrupt:
        interrupted = True
        console.print()
        console.print("[bold yellow]Interrupted![/bold yellow]")
        if sandbox_manager:
            console.print("[dim]Cleaning up sandboxes...[/dim]")
            sandbox_manager.cleanup_all()
            console.print("[dim]Done.[/dim]")

    # Summary
    _print_run_summary(results, output_path, interrupted)

    # Auto-generate report if evaluation completed successfully
    if results and not interrupted:
        _run_report(output_path)

    # Force-exit on interrupt — ThreadPoolExecutor worker threads may still be
    # blocked on LLM API calls with long timeouts.  Normal shutdown would hang
    # until every thread finishes.  os._exit bypasses that cleanly after we've
    # already flushed results and cleaned up sandboxes.
    if interrupted:
        os._exit(130)


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------


def _print_config(
    config: RunConfig,
    output_path: Path,
    debug_path: Path | None,
    total_tasks: int,
    completed_tasks: int,
) -> None:
    """Print run configuration as a compact panel."""
    info = Table.grid(padding=(0, 2))
    info.add_column(style="bold magenta")
    info.add_column()
    info.add_row("Model", config.model)
    info.add_row("Dataset", config.dataset)
    info.add_row("Layer", f"{config.layer}")
    info.add_row("Mode", f"{config.mode}")
    info.add_row("Prompt", f"{config.prompt}")
    info.add_row("Workers", str(config.workers))
    tasks_value = str(total_tasks)
    if completed_tasks:
        tasks_value += f" ({completed_tasks} already done)"
    info.add_row("Tasks", tasks_value)
    info.add_row("Output", str(output_path))
    if debug_path:
        info.add_row("Debug", str(debug_path))

    panel = Panel(
        info,
        title="[bold]SecLens Run[/bold]",
        border_style="blue",
        expand=False,
    )

    # Measure the actual rendered panel width so the progress bar can match it
    import io
    buf_console = Console(file=io.StringIO(), width=console.width, no_color=True)
    buf_console.print(panel)
    rendered = buf_console.file.getvalue()
    global _config_panel_width
    lines = rendered.splitlines()
    _config_panel_width = max((len(line) for line in lines), default=0)

    console.print(panel)


_config_panel_width: int = 0


def _print_run_summary(
    results: list,
    output_path: Path,
    interrupted: bool,
) -> None:
    """Print compact summary panel after evaluation."""
    if not results:
        if interrupted:
            console.print("  No tasks completed before interruption.")
        return

    console.print()

    errors = sum(1 for r in results if r.error)
    total_cost = sum(r.metrics.cost_usd for r in results)
    total_earned = sum(r.scores.earned for r in results)
    total_possible = sum(r.scores.max_task_points for r in results)

    label = "Partial results" if interrupted else "Evaluation complete!"
    color = "bold yellow" if interrupted else "bold green"

    stats = Table.grid(padding=(0, 2))
    stats.add_column(style="bold magenta")
    stats.add_column()
    stats.add_row("Tasks", f"{len(results)}")
    stats.add_row("Score", f"{total_earned}/{total_possible}")
    stats.add_row("Errors", f"{errors}" if errors else "[green]0[/green]")
    stats.add_row("Cost", f"${total_cost:.4f}")

    border = "yellow" if interrupted else "green"
    console.print(
        Panel(
            stats,
            title=f"[{color}]{label}[/{color}]",
            border_style=border,
            expand=False,
        )
    )


def _run_report(output_path: Path) -> None:
    """Auto-generate aggregate summary and show next-step hints."""
    from seclens.cli.summary import _print_terminal_report
    from seclens.scoring.aggregate import compute_aggregate

    console.print()
    console.print("[bold]Generating summary...[/bold]")

    results = read_results(output_path)
    if not results:
        return

    run_metadata = results[0].run_metadata
    report = compute_aggregate(results, run_metadata)
    _print_terminal_report(report)

    # Post-run hints
    console.print()
    console.print("[bold]Next steps:[/bold]")
    console.print(f"  seclens summary -r {output_path}")
    console.print(f"  seclens report -r {output_path} --role ciso")
    console.print()


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------


def _result_filename(config: RunConfig) -> str:
    """Generate the result filename from config."""
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    model_slug = config.model.replace("/", "_")
    return f"results_{model_slug}_L{config.layer}_{config.mode}_{timestamp}.jsonl"


def _format_score(earned: float, max_points: float) -> str:
    """Format score with colour based on percentage."""
    label = f"{earned}/{max_points} pts"
    if max_points == 0:
        return label
    pct = earned / max_points
    if pct <= 0:
        color = "red"
    elif pct < 0.5:
        color = "dark_orange"
    elif pct < 1.0:
        color = "yellow"
    else:
        color = "green"
    return f"[{color}]{label}[/{color}]"


def _repo_name(url: str) -> str:
    """Extract 'owner/repo' from a GitHub URL."""
    parts = url.rstrip("/").split("/")
    if len(parts) >= 2:
        return f"{parts[-2]}/{parts[-1]}"
    return url


_debug_write_lock = threading.Lock()


def _write_debug(path: Path, task_id: str, messages: list) -> None:
    """Append a debug record to the debug JSONL file."""
    from seclens.schemas.debug import DebugRecord

    record = DebugRecord(task_id=task_id, msg_chain=messages)
    line = record.model_dump_json()

    with _debug_write_lock:
        with open(path, "a") as f:
            f.write(line + "\n")
            f.flush()
