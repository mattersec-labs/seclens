"""SecLens CLI entry point."""

from __future__ import annotations

import logging
import os

# Suppress multiprocessing resource_tracker warnings about leaked semaphores.
# HuggingFace datasets creates semaphores internally; on forced exit (Ctrl-C)
# the tracker subprocess warns about them.  PYTHONWARNINGS is inherited by
# child processes — warnings.filterwarnings only affects the current process.
os.environ.setdefault("PYTHONWARNINGS", "ignore::UserWarning:multiprocessing.resource_tracker")

import typer

from seclens.cli.compare import compare_command
from seclens.cli.report import report_command
from seclens.cli.run import run_command
from seclens.cli.summary import summary_command

app = typer.Typer(
    name="seclens",
    help="LLM security vulnerability detection benchmark.",
    no_args_is_help=True,
)

# Third-party loggers that produce noisy warnings at runtime
_SUPPRESSED_LOGGERS = [
    "google.genai",
    "google_genai",
    "google.auth",
    "httpx",
    "httpcore",
    "openai",
    "anthropic",
]


@app.callback()
def main(
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show third-party library warnings"),
) -> None:
    """SecLens: Evaluate LLMs on security vulnerability detection."""
    from dotenv import load_dotenv

    load_dotenv()

    if not verbose:
        for name in _SUPPRESSED_LOGGERS:
            logging.getLogger(name).setLevel(logging.ERROR)


app.command(name="run")(run_command)
app.command(name="summary")(summary_command)
app.command(name="report")(report_command)
app.command(name="compare")(compare_command)
