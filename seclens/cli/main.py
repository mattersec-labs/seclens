"""SecLens CLI entry point."""

from __future__ import annotations

import typer

app = typer.Typer(
    name="seclens",
    help="LLM security vulnerability detection benchmark.",
    no_args_is_help=True,
)


@app.callback()
def main() -> None:
    """SecLens: Evaluate LLMs on security vulnerability detection."""
