"""Weight profile loading and composite score computation."""

from __future__ import annotations

from pathlib import Path

import yaml

PROFILES_DIR = Path(__file__).parent / "profiles"

# Dimensions where lower raw value = better performance.
# These get inverted during normalization: normalized = 1 - min(raw/cap, 1)
LOWER_IS_BETTER: dict[int, float] = {
    3: 1.0,    # False Positive Rate (0-1 ratio)
    4: 1.0,    # False Negative Rate (0-1 ratio)
    21: 0.50,  # Cost Per Task — cap at $0.50
    22: 2.00,  # Cost Per Correct Detection — cap at $2.00
    23: 50000, # Tokens Per Task — cap at 50k
    24: 120.0, # Wall Time Per Task — cap at 120s
    26: 30.0,  # Tool Calls Per Task — cap at 30
    27: 20.0,  # Turns Per Task — cap at 20
    29: 15.0,  # Navigation Convergence (median turns) — cap at 15
    42: 500.0, # Cost at Scale ($) — cap at $500
}

# Dimensions where higher raw = better, but need capping for normalization
HIGHER_IS_BETTER_CAPS: dict[int, float] = {
    18: 2000.0,  # Explanation Length — cap at 2000 chars
    25: 100.0,   # MCC Per Dollar — cap at 100
    41: 60.0,    # Throughput (tasks/min) — cap at 60
}

# MCC range is [-1, 1], needs special normalization
MCC_DIMENSIONS = {5}


def load_weight_profile(role: str) -> dict[int, float]:
    """Load a weight profile YAML file for a role.

    Args:
        role: Role identifier (e.g. 'ciso', 'caio').

    Returns:
        Dict mapping dimension_id -> weight.
    """
    profile_path = PROFILES_DIR / f"{role}.yaml"
    if not profile_path.exists():
        available = [p.stem for p in PROFILES_DIR.glob("*.yaml")]
        raise ValueError(
            f"Unknown role profile: {role!r}. "
            f"Available: {', '.join(sorted(available))}"
        )

    with open(profile_path) as f:
        data = yaml.safe_load(f)

    weights: dict[int, float] = {}
    for dim in data.get("dimensions", []):
        weights[dim["id"]] = dim["weight"]

    return weights


def list_available_roles() -> list[str]:
    """List available role profile names."""
    return sorted(p.stem for p in PROFILES_DIR.glob("*.yaml"))


def normalize_dimension(dim_id: int, raw_value: float) -> float:
    """Normalize a raw dimension value to 0-1 scale.

    - Ratio dimensions (already 0-1): pass through
    - Lower-is-better dimensions: 1 - min(raw/cap, 1)
    - MCC dimensions: (raw + 1) / 2
    - Higher-is-better with caps: min(raw/cap, 1)
    """
    if dim_id in MCC_DIMENSIONS:
        return (raw_value + 1.0) / 2.0

    if dim_id in LOWER_IS_BETTER:
        cap = LOWER_IS_BETTER[dim_id]
        return max(0.0, 1.0 - min(raw_value / cap, 1.0))

    if dim_id in HIGHER_IS_BETTER_CAPS:
        cap = HIGHER_IS_BETTER_CAPS[dim_id]
        return min(raw_value / cap, 1.0)

    # Default: assume already 0-1 ratio
    return max(0.0, min(raw_value, 1.0))


def compute_decision_score(
    raw_dimensions: dict[int, float],
    weights: dict[int, float],
) -> tuple[float, list[tuple[int, float, float, float]]]:
    """Compute weighted decision score (0-100).

    Args:
        raw_dimensions: dim_id -> raw computed value.
        weights: dim_id -> weight (summing to 100).

    Returns:
        Tuple of (decision_score, [(dim_id, normalized, weight, weighted_score), ...])
    """
    details = []
    total_score = 0.0

    for dim_id in sorted(raw_dimensions.keys()):
        raw = raw_dimensions[dim_id]
        norm = normalize_dimension(dim_id, raw)
        weight = weights.get(dim_id, 0.0)
        weighted = norm * weight
        total_score += weighted
        details.append((dim_id, norm, weight, weighted))

    return total_score, details


def score_to_grade(score: float) -> str:
    """Convert 0-100 decision score to letter grade."""
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


def generate_recommendation(role: str, score: float, grade: str) -> str:
    """Generate a natural-language recommendation based on role and score."""
    role_decisions = {
        "ciso": "deploying this model in your security program",
        "caio": "adopting this model for AI-driven security automation",
        "security_researcher": "relying on this model for vulnerability research",
        "head_of_engineering": "integrating this model into your development workflow",
        "ai_actor": "running this model autonomously on security tasks",
    }

    decision = role_decisions.get(role, "using this model")

    if grade == "A":
        return f"Strong recommendation for {decision}. Performance meets or exceeds requirements across key dimensions."
    if grade == "B":
        return f"Recommended for {decision} with minor caveats. Review weak dimensions before deployment."
    if grade == "C":
        return f"Conditionally suitable for {decision}. Significant gaps in some areas — requires human oversight."
    if grade == "D":
        return f"Not recommended for {decision} without substantial mitigation. Major gaps in critical dimensions."
    return f"Not suitable for {decision}. Fundamental capability gaps across multiple dimensions."
