"""Per-task evaluation runner — orchestrates the full evaluation pipeline."""

from __future__ import annotations

from datetime import datetime, timezone

from engine_harness import (
    CostTracker,
    ListDirTool,
    EngineLoop,
    ModelAdapter,
    ReadFileTool,
    SearchTool,
    ToolLogger,
)

import seclens
from seclens.evaluation.config import RunConfig
from seclens.parsing.parser import parse_response
from seclens.sandbox.manager import SandboxManager, fetch_target_code
from seclens.schemas.output import ParseResult, ParseStatus
from seclens.schemas.scoring import RunMetadata, TaskMetrics, TaskResult, TaskScore
from seclens.schemas.task import Task
from seclens.scoring.grader import score_task


def evaluate_task(
    task: Task,
    adapter: ModelAdapter,
    config: RunConfig,
    *,
    sandbox_manager: SandboxManager | None = None,
) -> TaskResult:
    """Evaluate a single task end-to-end.

    Orchestrates code fetch / sandbox creation, prompt building, LLM execution,
    response parsing, and scoring. Returns a complete ``TaskResult``.

    Args:
        task: The task to evaluate.
        adapter: LLM adapter for model invocation.
        config: Run configuration.
        sandbox_manager: Optional shared sandbox manager (Layer 2). Created
            per-call if not provided.

    Returns:
        A ``TaskResult`` with scores, metrics, and any error information.
    """
    run_metadata = _build_run_metadata(config)

    try:
        if config.layer == 1:
            return _evaluate_layer1(task, adapter, config, run_metadata)
        return _evaluate_layer2(task, adapter, config, run_metadata, sandbox_manager)
    except Exception as exc:  # noqa: BLE001
        return _error_result(task, run_metadata, str(exc))


def _evaluate_layer1(
    task: Task,
    adapter: ModelAdapter,
    config: RunConfig,
    run_metadata: RunMetadata,
) -> TaskResult:
    """Layer 1: code-in-prompt, single turn, no tools."""
    from seclens.prompts.builder import build_prompt

    code_block = fetch_target_code(
        task.repository.url, task.repository.commit, task.target,
    )

    messages = build_prompt(
        task, preset_name=config.prompt, mode=config.mode,
        layer=config.layer, code_block=code_block,
    )

    cost_tracker = CostTracker(model_id=config.model, max_cost=config.max_cost)
    runner = EngineLoop(adapter=adapter, middlewares=[cost_tracker], max_turns=1)
    result = runner.run(messages)

    parse_result = parse_response(result.final_response.content or "")
    scores = score_task(parse_result, task.ground_truth, task.max_task_points)
    metrics = _build_metrics(result, cost_tracker)

    return TaskResult(
        task_id=task.id,
        task_type=task.type,
        task_category=task.ground_truth.category,
        task_language=task.repository.language,
        run_metadata=run_metadata,
        parse_result=parse_result,
        scores=scores,
        metrics=metrics,
    )


def _evaluate_layer2(
    task: Task,
    adapter: ModelAdapter,
    config: RunConfig,
    run_metadata: RunMetadata,
    sandbox_manager: SandboxManager | None,
) -> TaskResult:
    """Layer 2: tool-use with sandboxed repository."""
    from seclens.prompts.builder import build_prompt

    manager = sandbox_manager or SandboxManager()
    sandbox_path = manager.create(
        task.id, task.repository.url, task.repository.commit,
    )

    try:
        messages = build_prompt(
            task, preset_name=config.prompt, mode=config.mode, layer=config.layer,
        )

        tool_logger = ToolLogger()
        cost_tracker = CostTracker(model_id=config.model, max_cost=config.max_cost)
        runner = EngineLoop(
            adapter=adapter,
            tools=[ReadFileTool, SearchTool, ListDirTool],
            sandbox_root=sandbox_path,
            middlewares=[tool_logger, cost_tracker],
            max_turns=config.max_turns,
        )
        result = runner.run(messages)

        parse_result = parse_response(result.final_response.content or "")
        scores = score_task(parse_result, task.ground_truth, task.max_task_points)
        metrics = _build_metrics(result, cost_tracker, tool_logger)

        return TaskResult(
            task_id=task.id,
            task_type=task.type,
            task_category=task.ground_truth.category,
            task_language=task.repository.language,
            run_metadata=run_metadata,
            parse_result=parse_result,
            scores=scores,
            tool_log=tool_logger.log,
            metrics=metrics,
        )
    finally:
        manager.cleanup(task.id)


def _build_run_metadata(config: RunConfig) -> RunMetadata:
    """Build run metadata from config."""
    return RunMetadata(
        model=config.model,
        prompt=config.prompt,
        layer=config.layer,
        mode=config.mode,
        timestamp=datetime.now(timezone.utc).isoformat(),
        seclens_version=seclens.__version__,
        seed=config.seed,
    )


def _build_metrics(
    result: "EngineLoop",
    cost_tracker: CostTracker,
    tool_logger: ToolLogger | None = None,
) -> TaskMetrics:
    """Extract metrics from loop result and middleware state."""
    usage = result.total_usage
    return TaskMetrics(
        input_tokens=usage.input_tokens if usage else 0,
        output_tokens=usage.output_tokens if usage else 0,
        total_tokens=(usage.input_tokens + usage.output_tokens) if usage else 0,
        cost_usd=cost_tracker.current_cost,
        tool_calls=len(tool_logger.log) if tool_logger else 0,
        turns=result.turns,
        wall_time_s=result.wall_time_s,
    )


def _error_result(task: Task, run_metadata: RunMetadata, error: str) -> TaskResult:
    """Build a TaskResult for a failed evaluation — all scores zero."""
    return TaskResult(
        task_id=task.id,
        task_type=task.type,
        task_category=task.ground_truth.category,
        task_language=task.repository.language,
        run_metadata=run_metadata,
        parse_result=ParseResult(status=ParseStatus.FAILED, raw_response=""),
        scores=TaskScore(
            verdict=0, cwe=0, location=0, earned=0,
            max_task_points=task.max_task_points,
        ),
        error=error,
    )
