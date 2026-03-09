"""SecLens CLI entry point."""

from __future__ import annotations

import typer

from seclens.cli.compare import compare_command
from seclens.cli.report import report_command
from seclens.cli.run import run_command

app = typer.Typer(
    name="seclens",
    help="LLM security vulnerability detection benchmark.",
    no_args_is_help=True,
)


@app.callback()
def main() -> None:
    """SecLens: Evaluate LLMs on security vulnerability detection."""


app.command(name="run")(run_command)
app.command(name="report")(report_command)
app.command(name="compare")(compare_command)
