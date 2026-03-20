# SecLens

Security vulnerability detection benchmark for LLMs. Tests models against confirmed CVEs from real-world open source projects across 8 vulnerability categories and 10 programming languages, producing role-specific scores for different organizational stakeholders.

## Key Features

- **Real CVEs**: 406 tasks from 93 open source projects — not synthetic test cases
- **Two evaluation layers**: Code-in-Prompt (reasoning) and Tool-Use (real-world auditing)
- **35 dimensions**: Detection, coverage, reasoning, efficiency, tool-use, severity, robustness
- **5 role perspectives**: CISO, CAIO, Security Researcher, Head of Engineering, AI as Actor
- **10 languages**: Python, JavaScript/TypeScript, Go, Ruby, Rust, Java, PHP, C, C++, C#
- **8 categories**: Injection, Broken Access Control, Cryptographic Failures, Authentication, Deserialization, SSRF, Memory Safety, Input Validation

## Quick Start

```bash
# Set your API key
export ANTHROPIC_API_KEY="sk-ant-..."

# Run evaluation
seclens run -m "anthropic/claude-sonnet-4-20250514" -d dataset.jsonl

# View role report
seclens report -r out/report_model.json --role ciso

# Compare models
seclens compare -r report_a.json -r report_b.json --all-roles
```

## Commands

| Command | Purpose |
|---------|---------|
| `seclens run` | Run evaluation against a model |
| `seclens summary` | View aggregate metrics from a run |
| `seclens report --role` | Generate role-specific analysis |
| `seclens compare --role` | Compare models through a role lens |

## Scoring

Each vulnerability task is scored on three dimensions:

| Dimension | Points | What It Measures |
|-----------|:------:|------------------|
| Verdict | 1 | Correctly identifies if code is vulnerable |
| CWE | +1 | Identifies the correct vulnerability type |
| Location | +1 | Pinpoints the vulnerable code (continuous IoU) |

35 aggregate dimensions are computed and weighted per role to produce a decision score (0-100) with grades A through F.

## Documentation

| Doc | Description |
|-----|-------------|
| [Overview](docs/overview.md) | What SecLens is and how it works |
| [Evaluation Layers](docs/evaluation-layers.md) | Code-in-Prompt vs Tool-Use |
| [Scoring](docs/scoring.md) | Per-task scoring, IoU, grading, confidence intervals |
| [Dimensions](docs/dimensions.md) | All 35 dimensions across 7 categories |
| [Roles](docs/roles.md) | 5 stakeholder perspectives and weight priorities |
| [Coverage](docs/coverage.md) | Vulnerability categories, languages, dataset design |
| [Usage Guide](docs/usage.md) | Configuration, CLI options, helper scripts |

## Development Setup

```bash
uv venv --python 3.13
uv sync --extra dev
cp .env.example .env  # fill in API keys
```

## Project Structure

```
seclens/
  cli/          CLI commands (run, summary, report, compare)
  dataset/      HuggingFace and local JSONL loading
  evaluation/   Evaluation runner and orchestration
  parsing/      LLM response parsing
  prompts/      Prompt templates and builder
  roles/        Role dimensions, normalization, scoring, weight profiles
  sandbox/      Git clone sandboxing for Tool-Use layer
  schemas/      Pydantic models (tasks, output, scoring, reports)
  scoring/      Scoring logic, aggregation, model report generation
  results/      JSONL result I/O with thread safety
  worker/       Thread pool for parallel evaluation
```
