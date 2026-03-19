# Role-Specific Benchmark Plan

## Overview

SecLens evaluates LLM vulnerability detection capability with a single leaderboard score. This extension adds **role-specific decision lenses** — the same benchmark data, scored through **250 distinct dimensions** (50 per role), producing a composite **Decision Score (0–100)** tailored to what each stakeholder actually cares about.

**Total dimensions**: 250 (50 × 5 roles). Each role has its own unique set of 50 dimensions.

**Key constraint**: Nothing in the existing codebase changes. All new code lives in `seclens/roles/`.

## Roles

| Role | Core Decision | Primary Focus |
|------|--------------|---------------|
| **CISO** | "Can I trust this model in my security program?" | Risk governance, compliance, audit trail, detection reliability |
| **CAIO / Head of AI** | "Which model unlocks new capabilities while balancing risk and cost?" | Capability upside, automation enablement, ROI, strategic value |
| **Security Researcher** | "How deep and reliable is this model's vulnerability reasoning?" | CWE mastery, evidence chains, per-language analysis, rare pattern detection |
| **Head of Engineering** | "Will this help or hurt my team's velocity and code quality?" | Low FP rate, speed, actionable findings, CI/CD integration |
| **AI as Actor** | "Can this model operate autonomously on security tasks?" | Tool mastery, self-correction, unsupervised quality, agent-loop efficiency |

---

## 250 Dimensions — Full Catalog

### CISO Dimensions (c01–c50)

| # | Dimension | Description |
|---|-----------|-------------|
| c01 | Overall Detection Reliability | Verdict accuracy across all tasks |
| c02 | Critical Vulnerability Detection Rate | Recall on injection, RCE, auth bypass, XSS CWEs |
| c03 | Critical Vulnerability Miss Prevention | 1 - FN rate on critical CWEs |
| c04 | False Alarm Suppression | True negative rate — organizational noise cost |
| c05 | Balanced Detection Accuracy | (TPR + TNR) / 2 |
| c06 | Overall MCC Score | Matthews Correlation Coefficient (normalized 0–1) |
| c07 | Audit Trail Completeness | % of responses with full evidence chain |
| c08 | CWE Classification Accuracy | Correct CWE among TP detections |
| c09 | Zero-Day Readiness | Performance on rare CWE categories (≤3 tasks) |
| c10 | Severity-Weighted Recall | Recall weighted by CWE severity tier |
| c11 | Worst-Category Floor | Minimum accuracy across CWE categories |
| c12 | Language Parity | 1 - accuracy gap across languages |
| c13 | Overconfident Miss Prevention | 1 - FN rate among FULL-parsed responses |
| c14 | Operational Error Rate | % of tasks without crash/error |
| c15 | Parse Reliability | % with parseable output (FULL or PARTIAL) |
| c16 | Structured Output Compliance | % FULL parse status |
| c17 | Location Accuracy for Remediation | Location IoU score among TPs |
| c18 | Finding Actionability | % of TPs with verdict + CWE + location |
| c19 | Negative Predictive Value | Among "not vulnerable" predictions, % correct |
| c20 | Positive Predictive Value (Precision) | Among "vulnerable" predictions, % that are real |
| c21 | Cost Per Task | Average USD per task |
| c22 | Cost Per True Positive | USD per real detection |
| c23 | Budget Predictability | 1 - coefficient of variation of cost |
| c24 | Annual Projected Cost | Projected cost for 10K tasks/year |
| c25 | Compliance Report Readiness | % of findings with CWE + evidence + location |
| c26 | Reasoning Transparency | % of responses with reasoning field |
| c27 | Cross-Run Consistency | Placeholder (requires multi-seed) |
| c28 | Regression Risk | Placeholder (requires version comparison) |
| c29 | Supply Chain CWE Coverage | Performance on dependency-related CWEs |
| c30 | Authentication Bypass Detection | Performance on auth/authz CWEs |
| c31 | Injection Detection Rate | Detection rate for injection class vulns |
| c32 | XSS Detection Rate | Detection rate for XSS vulns |
| c33 | Data Exposure Detection | Detection rate for information disclosure |
| c34 | Cryptographic Weakness Detection | Detection rate for crypto/hash weaknesses |
| c35 | Mean Time to Detect | Average wall time (normalized: <10s=1.0, >120s=0.0) |
| c36 | Scanning Throughput | Tasks/minute (normalized against 30 tpm cap) |
| c37 | Incident Response Utility | Composite: recall × speed × actionability |
| c38 | Vendor Risk Assessment Utility | Language consistency × CWE breadth |
| c39 | Regulatory Mapping Accuracy | CWE accuracy (maps to PCI-DSS, SOC2, HIPAA) |
| c40 | Triage Noise Ratio | PPV — % of alerts worth investigating |
| c41 | SLA Compliance Rate | % of tasks within 60-second SLA |
| c42 | Token Efficiency | Accuracy per 1K tokens consumed |
| c43 | Multi-Language Coverage | Languages with >50% accuracy / total languages |
| c44 | Patch Verification Accuracy | Accuracy on post-patch tasks |
| c45 | SAST False Positive Rejection | Accuracy on SAST FP tasks |
| c46 | Board-Reportable Score | Severity-weighted F1 |
| c47 | Risk Exposure Index | Critical detection × overconfidence penalty |
| c48 | Defense-in-Depth Contribution | Unique detection capability vs. SAST |
| c49 | Production Stability | Error rate + parse reliability combined |
| c50 | Overall CISO Confidence | Composite: balanced accuracy + risk + reliability |

### CAIO / Head of AI Dimensions (a01–a50)

| # | Dimension | Description |
|---|-----------|-------------|
| a01 | Capability Score | Overall verdict accuracy |
| a02 | Full Finding Rate | % of TP tasks with perfect 3/3 score |
| a03 | MCC (Normalized) | MCC mapped to 0–1 |
| a04 | Recall | True positive rate |
| a05 | Precision | PPV — flagged vulns that are real |
| a06 | F1 Score | Harmonic mean of precision and recall |
| a07 | Tool-Use Effectiveness | Among tool tasks, % that scored > 0 |
| a08 | Tool-Use Uplift | Accuracy delta: tool tasks vs. non-tool tasks |
| a09 | Autonomous Completion Rate | % without error or parse failure |
| a10 | Multi-Turn Success Rate | Accuracy among multi-turn tasks |
| a11 | Navigation Efficiency | % of L2 tasks with ≤5 tool calls |
| a12 | Reasoning Depth | % with evidence chain (source + sink) |
| a13 | Zero-Guidance Capability | Accuracy proxy for minimal-prompt scenarios |
| a14 | Cross-Category Breadth | % of CWE categories with >50% accuracy |
| a15 | Language Breadth | % of languages with >50% accuracy |
| a16 | Cost Per Task | Average USD per task |
| a17 | Cost Per Correct Finding | USD per true positive |
| a18 | MCC Per Dollar | Quality per dollar spent |
| a19 | Tokens Per Task | Average total tokens |
| a20 | Accuracy Per 1K Tokens | Correct verdicts per 1K tokens |
| a21 | Cost at Scale (1K tasks) | Projected cost for 1K tasks |
| a22 | Cost at Scale (10K tasks) | Projected cost for 10K tasks |
| a23 | Wall Time Per Task | Average seconds per task |
| a24 | Throughput (tasks/min) | Tasks completed per minute |
| a25 | Risk-Adjusted Return | Capability × reliability / cost |
| a26 | Parse Compliance | % FULL parse status |
| a27 | Error Rate (inverted) | 1 - error_rate |
| a28 | Graceful Degradation | 1 - |common vs rare CWE accuracy delta| |
| a29 | Self-Correction Capability | Multi-turn accuracy proxy |
| a30 | False Positive Prevention | TNR |
| a31 | Critical Miss Prevention | Detection rate on critical CWEs |
| a32 | Worst-Category Risk | Min accuracy across CWE categories |
| a33 | Language Consistency | 1 - language accuracy gap |
| a34 | Overconfident Miss Prevention | 1 - FN among FULL-parsed |
| a35 | Patch Verification | Post-patch task accuracy |
| a36 | Workflow Automation Readiness | Completion × parse × error rate |
| a37 | New Capability Index | Tool uplift × multi-turn × rare CWE |
| a38 | Competitive Differentiation | Full finding rate (3/3 tasks) |
| a39 | ROI Index | F1 / cost_per_task |
| a40 | Reasoning Quality | Reasoning + correct verdict rate |
| a41 | Confidence Calibration | FULL parse + correct verdict |
| a42 | Integration Readiness | Parse + errors + autonomous completion |
| a43 | CWE Knowledge Depth | CWE accuracy among TPs |
| a44 | Location Precision | Location accuracy among TPs |
| a45 | Strategic Value Score | Capability × efficiency × reliability × new capabilities |
| a46 | SAST Augmentation Value | SAST FP task performance |
| a47 | Deployment Risk (inverted) | 1 - (error + parse_failure) / 2 |
| a48 | Scalability Confidence | Cost distribution predictability |
| a49 | Business Case Strength | Capability × cost-efficiency × risk |
| a50 | Overall CAIO Score | Capability upside balanced by risk and cost |

### Security Researcher Dimensions (r01–r50)

| # | Dimension | Description |
|---|-----------|-------------|
| r01 | Vulnerability Detection Recall | True positive rate |
| r02 | Vulnerability Detection Precision | PPV |
| r03 | F1 Score | Balanced detection quality |
| r04 | MCC (Normalized) | MCC 0–1 |
| r05 | CWE Exact Match Rate | Exact CWE ID match among TPs |
| r06 | CWE Coverage Breadth | % of CWE categories with ≥1 correct CWE |
| r07 | Rare CWE Detection | Verdict accuracy on rare CWEs (≤3 tasks) |
| r08 | Rare CWE Identification | CWE match accuracy on rare CWEs |
| r09 | Cross-Language CWE Consistency | 1 - StdDev of CWE accuracy across languages |
| r10 | CWE Confusion Quality | 1 - wrong CWE rate |
| r11 | Location Accuracy (IoU>0.5) | Location score among correct TPs |
| r12 | File Identification Rate | % of TPs with location attempted |
| r13 | Mean IoU Estimate | Estimated average IoU |
| r14 | Pinpoint Rate | Location accuracy approximation |
| r15 | Over-Scope Prevention | 1 - over-scoped location rate |
| r16 | Evidence Completeness | % with source + sink + flow |
| r17 | Source Identification Rate | % of TPs with source identified |
| r18 | Sink Identification Rate | % of TPs with sink identified |
| r19 | Data Flow Completeness | % of TPs with non-empty flow chain |
| r20 | Reasoning Presence | % with reasoning field |
| r21 | Reasoning Length (median) | Median reasoning length in chars |
| r22 | Reasoning + Correct Verdict | Coherent analysis rate |
| r23 | FP Reasoning Quality | Among FPs, % with reasoning |
| r24 | Injection Class Mastery | CWE accuracy on injection vulns |
| r25 | XSS Class Mastery | CWE accuracy on XSS vulns |
| r26 | Auth Class Mastery | CWE accuracy on auth vulns |
| r27 | Crypto Class Mastery | CWE accuracy on crypto vulns |
| r28 | Deserialization Mastery | Detection rate on deserialization |
| r29 | Worst CWE Category | Min accuracy across categories |
| r30 | Best CWE Category | Max accuracy across categories |
| r31 | Category Variance (inverted) | 1 - StdDev across categories |
| r32 | Python Accuracy | Language-specific accuracy |
| r33 | JavaScript Accuracy | Language-specific accuracy |
| r34 | Java Accuracy | Language-specific accuracy |
| r35 | C/C++ Accuracy | Language-specific accuracy |
| r36 | Go Accuracy | Language-specific accuracy |
| r37 | Language Gap (inverted) | 1 - (best - worst) language accuracy |
| r38 | Post-Patch Discrimination | Accuracy on patched code |
| r39 | SAST FP Discrimination | SAST false positive rejection |
| r40 | Negative Task Accuracy | Overall specificity |
| r41 | Complete Finding Rate (3/3) | Perfect analysis rate |
| r42 | Tool-Use for Deep Analysis | Multi-turn accuracy |
| r43 | Novel Pattern Detection | Rare CWE performance proxy |
| r44 | Graceful Degradation | Common vs rare CWE consistency |
| r45 | Parse Success Rate | FULL parse % |
| r46 | Error Rate (inverted) | Reliability |
| r47 | Reproducibility Proxy | Placeholder (multi-seed) |
| r48 | Prompt Robustness | Placeholder (multi-preset) |
| r49 | Research Utility Index | CWE depth × evidence × rare CWE |
| r50 | Overall Researcher Score | Knowledge depth × reasoning × coverage |

### Head of Engineering Dimensions (e01–e50)

| # | Dimension | Description |
|---|-----------|-------------|
| e01 | False Positive Prevention (TNR) | Clean code correctly cleared |
| e02 | Precision (PPV) | Alert reliability |
| e03 | Recall (TPR) | Vulnerability catch rate |
| e04 | F1 Score | Balanced quality |
| e05 | MCC (Normalized) | MCC 0–1 |
| e06 | File-Level Accuracy | % of TPs with file identified |
| e07 | Location Accuracy (IoU>0.5) | Line-level accuracy |
| e08 | Location Precision | 1 - over-scope rate |
| e09 | Actionable Finding Rate | TPs with verdict + CWE + location |
| e10 | CWE Accuracy | CWE match for fix guidance |
| e11 | Wall Time Per Task (avg) | Pipeline latency |
| e12 | P95 Wall Time | Worst-case latency |
| e13 | SLA Compliance (30s) | % within 30-second gate |
| e14 | SLA Compliance (60s) | % within 60-second gate |
| e15 | Throughput (tasks/min) | CI throughput capacity |
| e16 | Cost Per Task | Average USD |
| e17 | Cost Per PR (projected) | 5 functions/PR estimate |
| e18 | Monthly Cost (projected) | 5000 tasks/month |
| e19 | Tokens Per Task | Average tokens |
| e20 | Cost Per Actionable Finding | USD per usable finding |
| e21 | Parse Success Rate | FULL parse % |
| e22 | Format Compliance | FULL among non-FAILED |
| e23 | Error Rate (inverted) | Reliability |
| e24 | Parse Failure Prevention | 1 - parse_failure_rate |
| e25 | Overall Reliability | No error AND parseable |
| e26 | Reasoning for Developers | % with reasoning for understanding |
| e27 | Evidence for Fix (source+sink) | % of TPs with fix guidance |
| e28 | Patch Verification | Post-patch accuracy |
| e29 | SAST Noise Reduction | SAST FP rejection |
| e30 | Developer Trust Score | PPV × parse success |
| e31 | Python Accuracy | Language-specific |
| e32 | JavaScript Accuracy | Language-specific |
| e33 | Java Accuracy | Language-specific |
| e34 | Go Accuracy | Language-specific |
| e35 | Language Parity | 1 - language gap |
| e36 | Tool Call Efficiency | % with ≤5 calls |
| e37 | Turn Efficiency | % completing in ≤3 turns |
| e38 | Wasted Tool Prevention | 1 - futile tool use rate |
| e39 | Cost Predictability | 1 - CV of cost distribution |
| e40 | Worst Language Accuracy | Min accuracy across languages |
| e41 | Injection Detection | OWASP top concern |
| e42 | XSS Detection | Frontend concern |
| e43 | Auth Detection | Access control concern |
| e44 | Negative Predictive Value | "Clean bill" trustworthiness |
| e45 | CI Gate Readiness | Fast + reliable + structured |
| e46 | Noise-to-Signal Ratio | PPV alias |
| e47 | Developer Productivity Index | Actionable findings per minute |
| e48 | Full Finding Rate (3/3) | Gold-standard findings |
| e49 | Team Adoption Readiness | Low FP + fast + reliable + actionable |
| e50 | Overall Engineering Score | Precision + speed + reliability + actionability |

### AI as Actor Dimensions (ai01–ai50)

| # | Dimension | Description |
|---|-----------|-------------|
| ai01 | Autonomous Completion Rate | % completed without error/parse failure |
| ai02 | Unsupervised Verdict Accuracy | Overall verdict quality |
| ai03 | MCC (Normalized) | MCC 0–1 |
| ai04 | Full Finding Rate (3/3) | Complete autonomous analysis |
| ai05 | Zero-Shot Accuracy | Minimal-prompt accuracy proxy |
| ai06 | Multi-Turn Engagement Rate | % using > 1 turn |
| ai07 | Multi-Turn Success Rate | Accuracy among multi-turn tasks |
| ai08 | Single-Turn Success Rate | Quick decisive judgment |
| ai09 | Tool Adoption Rate | % using tools |
| ai10 | Tool-Use Effectiveness | Among tool tasks, % scored > 0 |
| ai11 | Tool Efficiency (≤5 calls) | Efficient navigation |
| ai12 | Tool Call Productivity | Score per tool call |
| ai13 | Navigation Speed | 1 - (median turns / 20) |
| ai14 | Wasted Effort Prevention | 1 - futile tool use rate |
| ai15 | Structured Output Compliance | FULL parse % |
| ai16 | Format Self-Correction | FULL among non-FAILED |
| ai17 | Error Recovery | 1 - error_rate |
| ai18 | Parse Failure Prevention | 1 - parse_failure_rate |
| ai19 | Evidence Generation | % with evidence chain |
| ai20 | Reasoning Generation | % with reasoning field |
| ai21 | Confidence Calibration | FULL parse + correct verdict |
| ai22 | Overconfident Miss Prevention | 1 - FN among FULL-parsed |
| ai23 | CWE Identification | CWE accuracy among TPs |
| ai24 | Location Identification | Location accuracy among TPs |
| ai25 | Complete Analysis Rate | TPs with verdict + CWE + location |
| ai26 | Recall (TPR) | True positive rate |
| ai27 | Specificity (TNR) | True negative rate |
| ai28 | Precision (PPV) | Positive predictive value |
| ai29 | F1 Score | Balanced quality |
| ai30 | Graceful Degradation | Common vs rare CWE consistency |
| ai31 | Cross-Language Autonomy | 1 - language accuracy gap |
| ai32 | Cross-Category Autonomy | % of categories with >50% accuracy |
| ai33 | Worst Category Floor | Min accuracy across categories |
| ai34 | Critical Vuln Autonomous Detection | Detection rate on critical CWEs |
| ai35 | Post-Patch Discrimination | Patched code accuracy |
| ai36 | SAST FP Discrimination | SAST false positive rejection |
| ai37 | Cost Efficiency | Average cost per task |
| ai38 | Token Efficiency | Correct verdicts per 1K tokens |
| ai39 | Wall Time Autonomy (<60s) | % completing within 60s |
| ai40 | Self-Monitoring Proxy | FULL parse AND correct |
| ai41 | Decision Consistency | Placeholder (multi-seed) |
| ai42 | Adversarial Robustness | Placeholder (adversarial prompts) |
| ai43 | Task Type Coverage | Accuracy across TP/post-patch/SAST types |
| ai44 | Autonomous Triage Quality | Verdict × evidence × CWE composite |
| ai45 | Autonomous Remediation Guidance | Location + evidence + reasoning |
| ai46 | Pipeline Integration Readiness | Parse + errors + format compliance |
| ai47 | Human Replacement Index | F1 × complete analysis × reliability |
| ai48 | Agent Loop Efficiency | Accuracy per turn ratio |
| ai49 | Autonomous Scalability | Completion × cost efficiency |
| ai50 | Overall Autonomy Score | Composite: completion + quality + tools + analysis + reliability |

---

## Scoring Methodology

### Per-Role Composite Score

For each role, the 50 dimensions produce raw values. These are:
1. **Normalized** to 0–1 scale (ratio, lower-is-better inversion, MCC remapping, or capped)
2. **Weighted** by role-specific weights (equal weight = 2.0 per dimension, summing to 100)
3. **Summed** to produce a **Decision Score (0–100)**
4. **Graded**: A (≥90), B (≥80), C (≥70), D (≥60), F (<60)

### Weight Philosophy Per Role

| Role | Top Priority | Secondary | Balancing |
|------|-------------|-----------|-----------|
| CISO | Risk, Detection | Compliance, Reliability | Cost, Autonomy |
| CAIO | Autonomy, Capability | Tool-Use, Reasoning | Risk, Efficiency |
| Researcher | CWE Depth, Evidence | Localization, Coverage | Reliability |
| Eng Lead | FP Rate, Speed | Actionability, Integration | Cost, Coverage |
| AI Actor | Tool Mastery, Completion | Self-Correction, Quality | Coverage, Cost |

---

## Implementation

### File Structure

```
seclens/
  roles/
    __init__.py
    dimensions.py              # 50 shared/base dimension functions
    dimensions_ciso.py         # 50 CISO-specific dimensions
    dimensions_caio.py         # 50 CAIO-specific dimensions
    dimensions_researcher.py   # 50 Security Researcher dimensions
    dimensions_engineer.py     # 50 Head of Engineering dimensions
    dimensions_ai_actor.py     # 50 AI as Actor dimensions
    weights.py                 # Weight loading + normalization + composite scoring
    scorer.py                  # Role report generation
    schemas.py                 # Pydantic models for role reports
    profiles/
      ciso.yaml
      caio.yaml
      security_researcher.yaml
      head_of_engineering.yaml
      ai_actor.yaml
tests/
  test_role_dimensions.py      # Unit tests for all 250 dimensions
paper/
  role_specific_benchmark.tex  # ArXiv paper
EXECUTION_INSTRUCTIONS.md      # Team execution guide
```

### Execution Instructions

See `EXECUTION_INSTRUCTIONS.md` for the team guide on running the full benchmark suite.

### Paper

See `paper/role_specific_benchmark.tex` for the ArXiv paper.
