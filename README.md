# SecLens

Benchmark for evaluating how well LLMs detect security vulnerabilities in real-world code. Tests models against confirmed CVEs across multiple CWE categories using two evaluation layers.

## Evaluation Layers

- **Layer 1 (Code-in-prompt)** — The vulnerable function is provided directly in the prompt. Tests pure reasoning ability without tool use.
- **Layer 2 (Tool-use)** — The model is given access to a sandboxed repository clone and tools (`read_file`, `search`, `list_dir`). Tests real-world auditing ability with navigation.

## Setup

```bash
uv venv --python 3.13
uv sync --extra dev
cp .env.example .env  # fill in API keys
```

### API Keys

| Provider | Environment Variable | Notes |
|----------|---------------------|-------|
| Anthropic | `ANTHROPIC_API_KEY` | |
| OpenAI | `OPENAI_API_KEY` | |
| Google Gemini | `GOOGLE_API_KEY` | |
| Ollama | — | Local, no key needed |
| LiteLLM | `LITELLM_API_KEY` | Key for upstream provider |

## Usage

### Run an evaluation

```bash
# Layer 2 (default) with HuggingFace dataset
seclens run -m "anthropic/claude-sonnet-4-20250514" -d sidds020/SecLens:test_lite

# Layer 1 with local dataset
seclens run -m "openai/gpt-4.1" -d tasks.jsonl --layer 1

# Ollama (local models)
seclens run -m "ollama/qwen3:latest" -d sidds020/SecLens:test_lite

# Customize workers, prompt preset, and budget
seclens run -m "google/gemini-2.5-flash" -d sidds020/SecLens:test -w 10 -p security_expert --max-cost 5.0
```

### Generate a report

```bash
seclens report -r out/results_*.jsonl
```

### Compare runs

```bash
seclens compare -r out/results_model_a.jsonl -r out/results_model_b.jsonl
```

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `--model, -m` | Model identifier (e.g. `anthropic/claude-sonnet-4-20250514`) | required |
| `--dataset, -d` | HuggingFace `repo:split` or local JSONL path | required |
| `--layer, -l` | Evaluation layer (1 or 2) | 2 |
| `--prompt, -p` | Prompt preset (`base`, `minimal`, `security_expert`) or YAML path | `base` |
| `--workers, -w` | Parallel evaluation workers | 5 |
| `--max-cost` | Budget cap in USD | unlimited |
| `--max-turns` | Max LLM turns per task | 200 |
| `--resume` | Resume from existing output file | off |
| `--debug` | Save full message chains to debug JSONL | off |

## Scoring

Each task awards points based on prediction accuracy:

| Component | Points | Criteria |
|-----------|--------|----------|
| Verdict | 1 | Correct vulnerable/not-vulnerable classification |
| CWE | 1 | Correct CWE identifier (positive tasks only) |
| Location | 1 | File path + line range with IoU above threshold (positive tasks only) |

Positive tasks: max 3 points. Negative tasks: max 1 point (verdict only).

## Project Structure

```
seclens/
  cli/          CLI commands (run, report, compare)
  dataset/      HuggingFace and local JSONL loading
  evaluation/   Evaluation runner and orchestration
  parsing/      LLM response parsing
  prompts/      Prompt templates and builder
  sandbox/      Git clone sandboxing for Layer 2
  schemas/      Pydantic models (tasks, output, debug)
  scoring/      Scoring logic (verdict, CWE, location)
  results/      JSONL result I/O
  worker/       Thread pool for parallel evaluation
```

## Dependencies

SecLens uses [engine-harness](../engine-harness) for LLM adapter management, agent loops, and tool execution.
