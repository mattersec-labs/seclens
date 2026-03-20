# Dimensions

SecLens computes 35 dimensions from evaluation results, organized into 7 categories. These dimensions form the basis for role-specific scoring — each role weights them differently based on what matters for their decision context.

## Category A: Detection (D1–D8)

Core vulnerability detection metrics.

| ID | Dimension | What It Measures |
|----|-----------|------------------|
| D1 | **MCC** | Overall classification quality, accounting for class imbalance. The single most balanced metric — penalizes models that always say "vulnerable" or "safe." |
| D2 | **Detection Rate** | Of all real vulnerabilities, what percentage were detected? A model with 60% detection rate misses 4 in 10 vulnerabilities. |
| D3 | **Precision** | Of all code flagged as vulnerable, what percentage was actually vulnerable? Low precision = high false positive noise. |
| D4 | **F1** | Balanced combination of detection rate and precision. Punishes models that sacrifice one for the other. |
| D5 | **True Negative Rate** | Of all safe code, what percentage was correctly cleared? Measures how quiet the model stays on clean code. |
| D6 | **CWE Accuracy** | Among detected vulnerabilities, correct CWE identification rate. Finding a vulnerability isn't enough — you need to know what kind. |
| D7 | **Mean Location IoU** | Average precision of vulnerability localization. Higher IoU = model points to the right code. |
| D8 | **Actionable Finding Rate** | Percentage of vulnerabilities reported with correct verdict AND correct CWE AND correct location — complete findings that need zero human triage. |

## Category B: Coverage & Consistency (D9–D13)

How reliably the model works across different vulnerability types, languages, and tool outputs.

| ID | Dimension | What It Measures |
|----|-----------|------------------|
| D9 | **CWE Coverage Breadth** | Percentage of vulnerability categories with at least one correct detection. A specialist vs generalist indicator. |
| D10 | **Worst Category Floor** | Detection rate of the model's weakest vulnerability category. Average accuracy hides blind spots — this exposes them. |
| D11 | **Cross-Language Consistency** | How consistent performance is across programming languages. Low variance = predictable behavior. |
| D12 | **Worst Language Floor** | Detection rate of the model's weakest language. Critical for teams using that specific stack. |
| D13 | **SAST FP Filtering** | Accuracy on SAST false positive tasks. Can the model correctly dismiss findings from traditional static analysis tools? |

## Category C: Reasoning & Evidence (D14–D17)

Does the model explain its findings with supporting evidence?

| ID | Dimension | What It Measures |
|----|-----------|------------------|
| D14 | **Evidence Completeness** | Percentage of responses with a complete evidence chain — source (input entry), sink (dangerous operation), and data flow path. |
| D15 | **Reasoning Presence** | Percentage of responses that include a written explanation. Verdicts without reasoning are black boxes. |
| D16 | **Reasoning + Correct Verdict** | Among responses with reasoning, how often is the verdict correct? Low scores suggest the model confabulates. |
| D17 | **FP Reasoning Quality** | Among false positives, what percentage include reasoning? An explained wrong answer is at least reviewable. |

## Category D: Operational Efficiency (D18–D23)

What does it cost and how fast is it?

| ID | Dimension | What It Measures |
|----|-----------|------------------|
| D18 | **Cost per Task** | Average API cost per evaluation. Directly determines financial viability at scale. |
| D19 | **Cost per True Positive** | Average cost to find one real vulnerability. Combines cost efficiency with detection effectiveness. |
| D20 | **MCC per Dollar** | Detection quality per unit of cost. The ultimate efficiency metric. |
| D21 | **Wall Time per Task** | Average elapsed time. Determines whether the tool fits in real-time pipelines or batch jobs. |
| D22 | **Throughput** | Tasks per minute. Scale readiness metric. |
| D23 | **Tokens per Task** | Average token consumption. Model-agnostic cost proxy independent of pricing. |

## Category E: Tool-Use & Navigation (D24–D27)

How effectively the model uses tools to investigate code. Layer 2 only.

| ID | Dimension | What It Measures |
|----|-----------|------------------|
| D24 | **Tool Calls per Task** | Investigation intensity. Too few = not exploring enough. Too many = flailing. |
| D25 | **Turns per Task** | Conversation length. Fewer turns = faster convergence. |
| D26 | **Navigation Efficiency** | Percentage of tasks resolved with 5 or fewer tool calls. Measures focused investigation. |
| D27 | **Tool Effectiveness** | Verdict accuracy among tasks where tools were used. Do tools actually help? |

## Category F: Risk & Severity (D28–D30)

Does the model prioritize high-severity vulnerabilities?

| ID | Dimension | What It Measures |
|----|-----------|------------------|
| D28 | **Severity-Weighted Detection Rate** | Detection rate where missing a critical vulnerability costs 4x more than missing a low-severity one. Uses advisory-reported severity. |
| D29 | **Critical Miss Rate** | Detection rate specifically on critical and high severity vulnerabilities. Zero-tolerance metric. |
| D30 | **Severity Coverage** | Percentage of severity levels with at least one correct detection. Does the model work across the severity spectrum? |

## Category G: Robustness (D31–D35)

Does the model work reliably without crashing or producing unusable output?

| ID | Dimension | What It Measures |
|----|-----------|------------------|
| D31 | **Parse Success Rate** | Percentage of responses that are fully parseable structured JSON. Fundamental for pipeline integration. |
| D32 | **Format Compliance** | Among responses that produced some output, what percentage was well-formed? Isolates instruction-following from infrastructure failures. |
| D33 | **Error Rate** | Percentage of tasks completed without errors (API failures, timeouts, etc.). Higher = better. |
| D34 | **Autonomous Completion Rate** | Percentage of tasks that completed without error AND produced parseable output. The strictest reliability metric. |
| D35 | **Graceful Degradation** | Does accuracy drop proportionally with task difficulty, or does it cliff? Predictable behavior is essential for deployment trust. |
