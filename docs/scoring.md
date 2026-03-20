# Scoring Methodology

## Per-Task Scoring

Each task is scored on up to three dimensions, producing a points-based score that reflects detection depth.

### Positive Tasks (true_positive)

Scored on verdict + CWE + location. Maximum 3 points.

| Achievement | Points | Requirement |
|------------|:------:|-------------|
| Correct verdict | 1 | Model correctly identifies code as vulnerable |
| Correct CWE | +1 | Exact CWE-ID match (e.g., CWE-89) |
| Accurate location | +1 | Continuous IoU score (0.0–1.0) based on line range overlap |

A model that says "this code is vulnerable, it's SQL injection at lines 37-42" and is correct on all three gets the full 3 points. A model that correctly says "vulnerable" but misidentifies the CWE gets only 1 point.

### Negative Tasks (post_patch)

Scored on verdict only. Maximum 1 point.

The model must correctly determine that the patched code is no longer vulnerable. This tests the false positive rate — can the model tell the difference between vulnerable and fixed code?

### Parse Failures

If the model's response cannot be parsed into the expected JSON format, all scores are 0.

## Location Scoring: Continuous IoU

Location scoring uses Intersection over Union (IoU) — a continuous metric that rewards precision without requiring perfection.

**Formula**: `IoU = intersection of line ranges / union of line ranges`

**Recall gate**: The model's reported range must fully contain the ground truth lines (recall >= threshold, default 100%) to receive any credit. This prevents credit for ranges that miss the actual vulnerability.

**Examples**:

| Ground Truth | Model Reports | IoU | Score |
|---|---|---|---|
| Lines 37-38 | Lines 37-38 | 1.00 | 1.00 (exact match) |
| Lines 37-38 | Lines 35-40 | 0.33 | 0.33 (found it, imprecise) |
| Lines 37-38 | Lines 1-100 | 0.02 | 0.02 (very broad) |
| Lines 37-38 | Lines 50-60 | 0.00 | 0.00 (missed it) |

This approach means a model that narrows down to the right region gets meaningful credit, even if it doesn't pinpoint the exact lines.

## Leaderboard Score

The overall benchmark score is a weighted ratio:

```
Score = (sum of earned points across all tasks / sum of max points) × 100
```

Reported as a percentage with 95% bootstrap confidence intervals (1000 iterations).

## Confidence Intervals

All aggregate metrics include bootstrap confidence intervals:

1. Resample N task results with replacement
2. Compute the metric on each resample
3. Repeat 1000 times
4. Report: mean, stderr, 2.5th/97.5th percentiles

This prevents "Model A beats Model B by 0.3%" claims when the difference isn't statistically significant.

## Role-Based Grading

SecLens computes 35 dimensions from the raw results. Each role applies different weights to produce a decision score:

| Grade | Score | Meaning |
|:-----:|:-----:|---------|
| A | ≥ 75 | Excellent — strong performance across critical dimensions |
| B | ≥ 60 | Good — review weak dimensions before deployment |
| C | ≥ 50 | Fair — requires human oversight |
| D | ≥ 40 | Poor — significant gaps |
| F | < 40 | Not suitable — fundamental capability gaps |

Each role report includes:
- Decision score (0-100)
- Letter grade
- Category breakdown (which dimension groups are strong/weak)
- Specific weakness callouts
- Natural-language recommendation
