# Execution Instructions — Role-Specific Benchmark

Guide for the team to run the full 250-dimension benchmark evaluation.

## Prerequisites

```bash
cd /path/to/seclens
uv venv --python 3.13
uv sync --extra dev
cp .env.example .env  # Fill in API keys
```

## Step 1: Run Base Evaluations

Each model needs at minimum one Layer 2 (tool-use) run with the `base` prompt preset in `guided` mode. For full coverage of all 250 dimensions, run the extended matrix below.

### Minimum Required Run (per model)

```bash
# Layer 2, guided mode, base preset — produces data for most dimensions
seclens run -m "anthropic/claude-sonnet-4-20250514" \
    -d sidds020/SecLens:test \
    -l 2 --mode guided -p base -w 10 --debug
```

### Full Coverage Matrix (per model)

For complete dimension coverage including placeholders (L1/L2 delta, prompt sensitivity, etc.):

```bash
# Run 1: L2 + guided + base (primary)
seclens run -m MODEL -d sidds020/SecLens:test -l 2 --mode guided -p base -w 10 --debug

# Run 2: L2 + open mode (for unsupervised decision quality — a13, a48, ai05)
seclens run -m MODEL -d sidds020/SecLens:test -l 2 --mode open -p base -w 10

# Run 3: L2 + minimal preset (for zero-guidance accuracy — a13, ai05, prompt sensitivity)
seclens run -m MODEL -d sidds020/SecLens:test -l 2 --mode guided -p minimal -w 10

# Run 4: L1 + guided + base (for L1 vs L2 delta — a08, d43)
seclens run -m MODEL -d sidds020/SecLens:test -l 1 --mode guided -p base -w 10

# Run 5: L2 + security_expert preset (for prompt sensitivity — d44)
seclens run -m MODEL -d sidds020/SecLens:test -l 2 --mode guided -p security_expert -w 10

# Run 6: Repeat Run 1 with different seed (for cross-run stability — d34, c27)
seclens run -m MODEL -d sidds020/SecLens:test -l 2 --mode guided -p base -w 10 --seed 123
```

### Models to Evaluate

| Provider | Model ID | Notes |
|----------|----------|-------|
| Anthropic | `anthropic/claude-sonnet-4-20250514` | |
| Anthropic | `anthropic/claude-opus-4-20250514` | |
| OpenAI | `openai/gpt-4.1` | |
| OpenAI | `openai/o3` | |
| Google | `google/gemini-2.5-pro` | |
| Google | `google/gemini-2.5-flash` | |
| Ollama | `ollama/qwen3:latest` | Local, free |
| Ollama | `ollama/llama3.3:latest` | Local, free |

## Step 2: Generate Standard Report

```bash
# Verify results with standard aggregate report
seclens report -r out/results_MODEL_L2_guided_TIMESTAMP.jsonl
```

## Step 3: Generate Role-Specific Reports

The role-specific scoring uses the same result JSONL files. Once the `roles/` module is integrated into the CLI:

```bash
# Single role report
seclens role-report -r out/results_MODEL.jsonl --role ciso
seclens role-report -r out/results_MODEL.jsonl --role caio
seclens role-report -r out/results_MODEL.jsonl --role security_researcher
seclens role-report -r out/results_MODEL.jsonl --role head_of_engineering
seclens role-report -r out/results_MODEL.jsonl --role ai_actor

# All roles at once
seclens role-report -r out/results_MODEL.jsonl --all-roles

# JSON output for further analysis
seclens role-report -r out/results_MODEL.jsonl --all-roles -o out/role_report_MODEL.json
```

### Programmatic Access (before CLI integration)

```python
from seclens.results.io import read_results
from seclens.roles.scorer import generate_role_report, generate_multi_role_report

results = read_results("out/results_MODEL_L2_guided_TIMESTAMP.jsonl")

# Single role
ciso_report = generate_role_report(results, "ciso")
print(f"CISO Decision Score: {ciso_report.decision_score}/100 ({ciso_report.grade})")
print(f"Recommendation: {ciso_report.recommendation}")

# All roles
multi = generate_multi_role_report(results)
for role in multi.ranking:
    r = multi.reports[role]
    print(f"{role}: {r.decision_score}/100 ({r.grade})")
```

## Step 4: Cross-Model Comparison

```bash
# Compare models through CISO lens
seclens role-compare \
    -r out/results_claude.jsonl \
    -r out/results_gpt4.jsonl \
    -r out/results_gemini.jsonl \
    --role ciso

# Compare through all roles
seclens role-compare \
    -r out/results_claude.jsonl \
    -r out/results_gpt4.jsonl \
    --all-roles
```

## Step 5: Run Tests

```bash
# Run all tests (including role dimensions)
uv run pytest tests/ -v

# Run only role-specific tests
uv run pytest tests/test_role_dimensions.py -v

# Run with coverage
uv run pytest tests/test_role_dimensions.py -v --cov=seclens.roles
```

## Step 6: Paper Data Collection

For the ArXiv paper, collect the following outputs per model:

1. **Decision Scores**: All 5 role scores from `generate_multi_role_report()`
2. **Per-Dimension Raw Values**: Full 250-dimension breakdown from each role report
3. **Cross-Role Divergence**: Cases where roles disagree on model ranking
4. **Standard Metrics**: Leaderboard score, MCC, cost from `seclens report`

### Data Collection Script

```python
import json
from pathlib import Path
from seclens.results.io import read_results
from seclens.roles.scorer import generate_multi_role_report

OUT_DIR = Path("out")
RESULT_FILES = sorted(OUT_DIR.glob("results_*_L2_guided_*.jsonl"))

all_data = {}
for result_file in RESULT_FILES:
    results = read_results(result_file)
    if not results:
        continue
    model = results[0].run_metadata.model
    multi = generate_multi_role_report(results)
    all_data[model] = {
        role: {
            "decision_score": report.decision_score,
            "grade": report.grade,
            "recommendation": report.recommendation,
            "category_scores": {
                cat.name: cat.weighted_score for cat in report.categories
            },
        }
        for role, report in multi.reports.items()
    }

with open("out/paper_data.json", "w") as f:
    json.dump(all_data, f, indent=2)
print(f"Collected data for {len(all_data)} models")
```

## Dimension Coverage Notes

| Dimension Type | Single L2 Run | Full Matrix |
|---------------|---------------|-------------|
| Detection accuracy (verdict, MCC, F1) | Full | Full |
| CWE knowledge (accuracy, breadth, rare) | Full | Full |
| Localization (IoU, file, pinpoint) | Full | Full |
| Reasoning quality (evidence, coherence) | Full | Full |
| Operational efficiency (cost, tokens, time) | Full | Full |
| Tool-use (calls, turns, efficiency) | Full (L2 only) | Full |
| Robustness (parse, error, format) | Full | Full |
| Risk profile (critical CWEs, severity) | Full | Full |
| L1 vs L2 delta | Placeholder | Needs Run 4 |
| Prompt sensitivity | Placeholder | Needs Runs 3 + 5 |
| Cross-run stability | Placeholder | Needs Run 6 |
| Zero-guidance accuracy | Proxy | Needs Run 3 |
| Open mode accuracy | Proxy | Needs Run 2 |

## Troubleshooting

- **"Unknown role profile"**: Ensure `seclens/roles/profiles/*.yaml` files exist
- **Empty results**: Check that the result JSONL file has content with `wc -l out/results_*.jsonl`
- **Import errors**: Run `uv sync` to ensure all dependencies are installed
- **Test failures**: Run `uv run pytest tests/test_role_dimensions.py -v --tb=long` for details
