# SecLens Overview

SecLens is a benchmark for evaluating how well LLMs detect security vulnerabilities in real-world code. It tests models against confirmed CVEs across multiple vulnerability categories and programming languages, producing role-specific scores that help different stakeholders make informed decisions.

## What SecLens Measures

SecLens answers a simple question: **Can this LLM find real security vulnerabilities?**

But different people need different answers:

- A **CISO** needs to know if the tool's aggregate output supports sound security decisions
- A **Head of Engineering** needs to know if it helps or hurts developer velocity
- A **Security Researcher** needs to know if it genuinely understands vulnerability mechanics
- A **Chief AI Officer** needs to know how autonomous the agent can be
- When evaluating **AI as an Actor**, the question is whether the agent knows its own limits

SecLens provides role-specific scores for each of these personas, weighted according to what matters most to that role.

## How It Works

### 1. Real CVEs, Real Code

SecLens uses confirmed CVEs from real-world open source projects — not synthetic test cases. Each task points to a specific function in a specific commit of a real repository. The model must determine if that function contains a vulnerability, identify the CWE type, and locate the vulnerable code.

### 2. Two Evaluation Layers

**Code-in-Prompt (Layer 1)**: The vulnerable function is provided directly in the prompt. Tests pure reasoning ability — can the model spot the vulnerability when given the code?

**Tool-Use (Layer 2)**: The model is given access to a sandboxed repository clone with tools (`read_file`, `search`, `list_dir`). Tests real-world auditing ability — can the model navigate a codebase, follow data flows across files, and reach a correct conclusion?

Comparing Layer 1 and Layer 2 results reveals whether tool access helps or hurts a model's performance.

### 3. Three-Dimensional Scoring

Each positive task is scored on three dimensions:

| Dimension | Points | What It Measures |
|-----------|:------:|------------------|
| **Verdict** | 1 | Did the model correctly identify if the code is vulnerable? |
| **CWE** | +1 | Did it identify the correct vulnerability type (e.g., CWE-89)? |
| **Location** | +1 | Did it pinpoint the vulnerable code location? |

Maximum: 3 points per positive task, 1 point per negative (post-patch) task.

Location scoring uses continuous IoU (Intersection over Union) — the model gets partial credit proportional to how precisely it locates the vulnerability, rather than a binary pass/fail.

### 4. 35 Dimensions, 5 Role Perspectives

Beyond the per-task score, SecLens computes 35 aggregate dimensions across 7 categories:

- **Detection**: MCC, Recall, Precision, F1, CWE Accuracy, Location IoU
- **Coverage**: CWE breadth, worst-category floor, cross-language consistency
- **Reasoning**: Evidence completeness, reasoning quality
- **Efficiency**: Cost per task, throughput, tokens
- **Tool-Use**: Navigation efficiency, tool effectiveness
- **Severity**: Severity-weighted recall, critical miss rate
- **Robustness**: Parse success, error rate, autonomous completion

Each role applies different weights to these dimensions, producing a decision score (0-100) and grade (A-F) tailored to that stakeholder's concerns.

## Dataset

SecLens tests against **confirmed CVEs from 145 real-world projects** across:

- **10 programming languages**: Python, JavaScript/TypeScript, Go, Ruby, Rust, Java, PHP, C, C++, C#
- **8 vulnerability categories**: Injection, Broken Access Control, Cryptographic Failures, Authentication Failures, Deserialization/Integrity, SSRF, Memory Safety, Improper Input Validation

Each CVE includes both the vulnerable version (true positive) and the patched version (post-patch), enabling measurement of both detection ability and false positive rate.

## Output

SecLens produces:

1. **Results JSONL** — per-task scores for detailed analysis
2. **Model Report JSON** — pre-computed dimensions, breakdowns, and aggregate scores
3. **Role Reports** — role-specific grades and recommendations via CLI
4. **Comparison Tables** — cross-model ranking through any role's lens
