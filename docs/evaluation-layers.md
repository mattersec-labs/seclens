# Evaluation Layers

SecLens evaluates models through two distinct layers, each testing a different aspect of vulnerability detection capability.

## Layer 1: Code-in-Prompt

The vulnerable function is provided directly in the prompt. The model receives the code, analyzes it, and produces a verdict — all in a single turn.

**What it tests**: Pure security reasoning. Can the model recognize vulnerability patterns when handed the code?

**How it works**:
1. The target function is fetched from GitHub at the vulnerable commit
2. The code is included directly in the prompt
3. The model analyzes it in a single turn (no tools, no navigation)
4. The model outputs a structured JSON verdict

**Best for**: Measuring baseline reasoning ability. If a model can't find a vulnerability when looking directly at the code, tools won't help.

**CLI**:
```bash
seclens run -m "model" -d dataset.jsonl --layer code-in-prompt
```

## Layer 2: Tool-Use

The model is given access to a sandboxed clone of the repository and must navigate the codebase using tools to find and analyze the vulnerability.

**What it tests**: Real-world auditing ability. Can the model form an investigation strategy, follow data flows across files, and reach a correct conclusion?

**How it works**:
1. The repository is cloned at the vulnerable commit into a sandboxed directory
2. Anti-gaming sanitization removes tests, docs, changelogs, and git history
3. The model is told which function to analyze (file path + line range)
4. The model uses tools to investigate:
   - `read_file`: Read specific files or line ranges
   - `search`: Search for patterns across the codebase
   - `list_dir`: Explore directory structure
5. The model can take multiple turns (default: up to 200)
6. The model outputs a structured JSON verdict

**Best for**: Measuring operational readiness. This is how the model would actually be used in a real security scanning workflow.

**CLI**:
```bash
seclens run -m "model" -d dataset.jsonl --layer tool-use
```

## Comparing Layers

Running the same dataset at both layers reveals important diagnostic signals:

| Pattern | What It Means |
|---------|---------------|
| L2 > L1 | Tool access helps — the model benefits from exploring context |
| L2 < L1 | Tool access hurts — the model gets confused by additional information |
| L1 low, L2 low | Fundamental reasoning gap — the model can't detect the vulnerability class |
| L1 high, L2 high | Strong model — good reasoning AND good tool use |
| L1 high, L2 same | Tools add no value — the model already has what it needs from the code |

## Sandbox Security

Layer 2 clones repositories into isolated temporary directories. Before the model sees the code:

- `.git` directory is removed (prevents commit message leakage)
- Test directories (`tests/`, `test/`) are removed (prevents regression test leakage)
- Documentation and changelogs are removed (prevents CVE description leakage)
- CI/CD configuration is removed (noise reduction)

This ensures the model must reason about the code itself, not metadata that could reveal the answer.
