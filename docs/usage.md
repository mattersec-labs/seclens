# Usage Guide

## Configuration

Set your LLM provider API keys as environment variables. Add them to your shell profile (`~/.zshrc` or `~/.bashrc`) for persistence:

```bash
# Add to ~/.zshrc or ~/.bashrc
export ANTHROPIC_API_KEY="sk-ant-..."
export OPENAI_API_KEY="sk-..."
export GOOGLE_API_KEY="AIza..."
export OPENROUTER_API_KEY="sk-or-..."
```

Then reload your shell:

```bash
source ~/.zshrc   # or source ~/.bashrc
```

Or set them for a single session:

```bash
export ANTHROPIC_API_KEY="sk-ant-..."
seclens run -m "anthropic/claude-sonnet-4-20250514" -d dataset.jsonl
```

### Supported Providers

| Provider | Environment Variable | Notes |
|----------|---------------------|-------|
| Anthropic | `ANTHROPIC_API_KEY` | Claude models |
| OpenAI | `OPENAI_API_KEY` | GPT models |
| Google Gemini | `GOOGLE_API_KEY` | Gemini models |
| OpenRouter | `OPENROUTER_API_KEY` | Multi-provider gateway |
| Ollama | — | Local models, no key needed |
| LiteLLM | `LITELLM_API_KEY` | Key for upstream provider |

## Running Evaluations

### Basic Run

```bash
# Layer 2 (tool-use, default)
seclens run -m "anthropic/claude-sonnet-4-20250514" -d dataset.jsonl

# Layer 1 (code-in-prompt)
seclens run -m "openai/gpt-4.1" -d dataset.jsonl --layer code-in-prompt

# With HuggingFace dataset
seclens run -m "google/gemini-2.5-flash" -d enginesec/SecLens:test
```

### Run Options

| Flag | Default | Description |
|------|---------|-------------|
| `-m, --model` | required | Model identifier (e.g., `anthropic/claude-sonnet-4-20250514`) |
| `-d, --dataset` | required | Dataset path (local JSONL or HuggingFace `repo:split`) |
| `-l, --layer` | `tool-use` | Evaluation layer (`code-in-prompt` or `tool-use`) |
| `--mode` | `guided` | Evaluation mode (`guided` with category hint, `open` without) |
| `-p, --prompt` | `base` | Prompt preset (`base`, `minimal`, `security_expert`) or custom YAML |
| `-w, --workers` | `5` | Parallel evaluation workers |
| `--max-cost` | unlimited | Budget cap in USD |
| `--max-turns` | `200` | Max LLM turns per task (Layer 2) |
| `--seed` | `42` | Random seed for reproducibility |
| `--resume` | off | Resume from existing output file |
| `--retry-failed` | — | Path to results file — re-evaluate failed/missing tasks |
| `--debug` | off | Save full message chains to debug JSONL |

### Output Files

Each run produces:
```
out/
  results_model_tu_guided_base_20260320_143022.jsonl   # Per-task results
  report_model_tu_guided_base_20260320_143022.json     # Pre-computed model report
  debug_results_model_tu_guided_base_20260320.jsonl    # Debug chains (if --debug)
```

### Retrying Failed Tasks

If tasks fail due to API errors, timeouts, or context overflow:

```bash
seclens run -m "model" -d dataset.jsonl --retry-failed out/results_model.jsonl
```

This identifies failed, corrupt, and missing tasks, re-evaluates only those, and replaces the old entries in-place.

## Viewing Results

### Summary (Aggregate Metrics)

```bash
seclens summary -r out/report_model.json
```

Shows leaderboard score, MCC, CWE accuracy, location accuracy, cost metrics, per-category and per-language breakdowns.

### Role Report

```bash
# Single role
seclens report -r out/report_model.json --role ciso

# All five roles
seclens report -r out/report_model.json --all-roles
```

Shows decision score, grade, dimension category breakdown, per-vulnerability-category performance, per-language performance, and a natural-language recommendation.

### Cross-Model Comparison

```bash
# Through one role's lens
seclens compare -r model_a.jsonl -r model_b.jsonl --role ciso

# All roles matrix
seclens compare -r model_a.jsonl -r model_b.jsonl --all-roles
```

### JSON Output

All commands support `-o output.json` for programmatic consumption:

```bash
seclens report -r results.jsonl --role ciso -o ciso_report.json
seclens report -r results.jsonl --all-roles -o all_roles.json
```

## Prompt Presets

Three built-in presets control how the model is instructed:

| Preset | Description | Use Case |
|--------|-------------|----------|
| `base` | Structured baseline with output format instructions | Default for leaderboard runs |
| `minimal` | Bare-bones prompt with minimal guidance | Testing raw capability |
| `security_expert` | Security audit methodology with anti-pattern guidance | Testing with expert framing |

In `guided` mode, the system prompt includes a category hint (e.g., "Focus on SQL injection vulnerabilities"). In `open` mode, no hint is provided.

## Helper Scripts

### Migrate Old Results

```bash
python scripts/migrate_results.py out/              # batch
python scripts/migrate_results.py out/ --dry-run     # preview
```

Converts old results files to current schema (numeric layers to named, backfills paired_with and category on post-patch tasks).

### Batch Generate Model Reports

```bash
python scripts/generate_model_reports.py out/        # generates missing reports only
```

## Tips

- **Large repos** (moodle, tensorflow): reduce workers (`-w 2`) to avoid disk space issues from concurrent clones
- **Small `/tmp`**: set `TMPDIR=/path/to/larger/disk` before running
- **Ollama**: no API key needed, runs locally. Use `ollama/model:tag` format
- **Cost control**: use `--max-cost 5.0` to cap spending per run
- **Reproducibility**: the `--seed` flag ensures bootstrap CIs are deterministic
