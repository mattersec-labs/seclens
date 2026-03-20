# Role-Based Reporting

SecLens produces different scores for different stakeholders. The same evaluation data is analyzed through five organizational lenses, each weighting the 35 dimensions according to what matters for that role's decisions.

## The Five Roles

### CISO — Chief Information Security Officer

*"Can I trust this model in my security program?"*

**Priorities**: Detection accuracy, severity-weighted coverage, no blind spots, low noise.

The CISO needs to know if the tool reduces organizational risk. They care most about not missing critical vulnerabilities (severity-weighted recall), having consistent coverage across all vulnerability categories (worst category floor), and generating findings precise enough for their team to act on (actionable finding rate).

**Top weighted dimensions**: MCC, Severity-Weighted Detection Rate, Critical Miss Rate, Detection Rate, Worst Category Floor.

### CAIO — Chief AI Officer

*"Which model unlocks new capabilities while balancing risk and cost?"*

**Priorities**: Autonomous completion, cost efficiency, tool mastery, balanced quality.

The CAIO is building an AI strategy. They need to know which model delivers the best detection quality per dollar (MCC per Dollar), can operate autonomously without crashing (autonomous completion rate), and effectively uses available tools (tool effectiveness). Cost at scale matters.

**Top weighted dimensions**: Autonomous Completion Rate, MCC, MCC per Dollar, Tool Effectiveness, F1.

### Security Researcher

*"Does this model genuinely understand vulnerability mechanics?"*

**Priorities**: CWE taxonomy mastery, localization precision, evidence depth, reasoning quality.

The researcher needs the model to demonstrate real understanding, not pattern matching. Can it identify the exact CWE? Can it pinpoint the vulnerable lines? Does it trace the data flow from source to sink? When it explains its reasoning, is it correct?

**Top weighted dimensions**: CWE Accuracy, Mean Location IoU, Evidence Completeness, MCC, Reasoning + Correct Verdict.

### Head of Engineering

*"Will this help or hurt my team's velocity and code quality?"*

**Priorities**: Low false positives, actionable findings, speed, cost, reliability.

Engineering leads care about developer adoption. High false positives kill adoption — developers disable noisy tools within a week. The model must produce precise findings (precision), locate the exact code (location IoU), run fast enough for CI/CD (wall time), and not crash (parse success rate).

**Top weighted dimensions**: Precision, Actionable Finding Rate, Mean Location IoU, Parse Success Rate, Wall Time per Task.

### AI as Actor

*"Does the agent know what it can and can't do?"*

**Priorities**: Autonomous completion, robustness, graceful degradation, format compliance, tool mastery.

This role evaluates the model as a standalone agent. Can it complete tasks without human intervention? Does it degrade gracefully on hard tasks or cliff? Does it produce structured, actionable output? Is its behavior consistent across diverse task types?

**Top weighted dimensions**: Autonomous Completion Rate, MCC, Graceful Degradation, Tool Effectiveness, Format Compliance.

## How Scoring Works

Each role selects 12-16 of the 35 dimensions and assigns weights totaling 80 points. The decision score is:

```
Decision Score = (sum of weighted normalized dimensions / total available weight) × 100
```

When dimensions lack data (e.g., severity dimensions when the dataset has no severity field, or tool-use dimensions on Layer 1 results), they're excluded and the denominator adjusts — ensuring fair comparison.

## Grades

| Grade | Score | Recommendation |
|:-----:|:-----:|----------------|
| **A** | ≥ 75 | Excellent for this role's use case |
| **B** | ≥ 60 | Good — review weak dimensions before deployment |
| **C** | ≥ 50 | Fair — requires human oversight |
| **D** | ≥ 40 | Poor — significant gaps in critical areas |
| **F** | < 40 | Not suitable for this role's use case |

## CLI Usage

```bash
# Single role report
seclens report -r results.jsonl --role ciso

# All five roles
seclens report -r results.jsonl --all-roles

# Cross-model comparison through a role lens
seclens compare -r model_a.jsonl -r model_b.jsonl --role ciso

# All roles comparison matrix
seclens compare -r model_a.jsonl -r model_b.jsonl --all-roles
```

## Why Different Roles Get Different Scores

The same model can be grade A for one role and grade C for another. This is by design.

A model that's excellent at detection but slow and expensive will score well for the Security Researcher (who cares about depth) but poorly for the Head of Engineering (who needs speed and low cost). A model that's fast and cheap but misses critical vulnerabilities will score well for the CAIO's cost analysis but poorly for the CISO's risk assessment.

This reflects reality: there is no single "best" model. The best model depends on who's using it and what they need.
