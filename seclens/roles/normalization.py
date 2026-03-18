"""Normalization of raw dimension values to 0.0–1.0 for weighted aggregation.

Four strategies:
- ratio: clamp to [0, 1] (most dimensions)
- mcc: map [-1, 1] → [0, 1]
- lower_is_better: 1 - min(raw/cap, 1) (cost, time, tokens)
- higher_is_better: min(raw/cap, 1) (throughput, MCC/dollar)
"""

from __future__ import annotations

from enum import StrEnum


class Strategy(StrEnum):
    """Normalization strategy for a dimension."""

    RATIO = "ratio"
    MCC = "mcc"
    LOWER_IS_BETTER = "lower_is_better"
    HIGHER_IS_BETTER = "higher_is_better"


# ---------------------------------------------------------------------------
# Normalization functions
# ---------------------------------------------------------------------------

def _normalize_ratio(raw: float) -> float:
    return max(0.0, min(raw, 1.0))


def _normalize_mcc(raw: float) -> float:
    return max(0.0, min((raw + 1.0) / 2.0, 1.0))


def _normalize_lower_is_better(raw: float, cap: float) -> float:
    return max(0.0, 1.0 - min(raw / cap, 1.0))


def _normalize_higher_is_better(raw: float, cap: float) -> float:
    return min(raw / cap, 1.0)


# ---------------------------------------------------------------------------
# Registry: dimension ID → (strategy, cap)
# cap is None for ratio and mcc strategies
# ---------------------------------------------------------------------------

NORMALIZATION_CONFIG: dict[str, tuple[Strategy, float | None]] = {
    # Detection (D1-D8)
    "D1": (Strategy.MCC, None),
    "D2": (Strategy.RATIO, None),
    "D3": (Strategy.RATIO, None),
    "D4": (Strategy.RATIO, None),
    "D5": (Strategy.RATIO, None),
    "D6": (Strategy.RATIO, None),
    "D7": (Strategy.RATIO, None),
    "D8": (Strategy.RATIO, None),
    # Coverage (D9-D13)
    "D9": (Strategy.RATIO, None),
    "D10": (Strategy.RATIO, None),
    "D11": (Strategy.RATIO, None),
    "D12": (Strategy.RATIO, None),
    "D13": (Strategy.RATIO, None),
    # Reasoning (D14-D17)
    "D14": (Strategy.RATIO, None),
    "D15": (Strategy.RATIO, None),
    "D16": (Strategy.RATIO, None),
    "D17": (Strategy.RATIO, None),
    # Efficiency (D18-D23) — cost/time/tokens are lower-is-better
    "D18": (Strategy.LOWER_IS_BETTER, 0.50),       # Cost per task: cap $0.50
    "D19": (Strategy.LOWER_IS_BETTER, 2.00),       # Cost per TP: cap $2.00
    "D20": (Strategy.HIGHER_IS_BETTER, 100.0),     # MCC per dollar: cap 100
    "D21": (Strategy.LOWER_IS_BETTER, 120.0),      # Wall time: cap 120s
    "D22": (Strategy.HIGHER_IS_BETTER, 60.0),      # Throughput: cap 60 tasks/min
    "D23": (Strategy.LOWER_IS_BETTER, 50_000.0),   # Tokens per task: cap 50K
    # Tool-Use (D24-D27)
    "D24": (Strategy.LOWER_IS_BETTER, 30.0),       # Tool calls: cap 30
    "D25": (Strategy.LOWER_IS_BETTER, 20.0),       # Turns: cap 20
    "D26": (Strategy.RATIO, None),
    "D27": (Strategy.RATIO, None),
    # Severity (D28-D30)
    "D28": (Strategy.RATIO, None),
    "D29": (Strategy.RATIO, None),
    "D30": (Strategy.RATIO, None),
    # Robustness (D31-D35)
    "D31": (Strategy.RATIO, None),
    "D32": (Strategy.RATIO, None),
    "D33": (Strategy.RATIO, None),
    "D34": (Strategy.RATIO, None),
    "D35": (Strategy.RATIO, None),
}


def normalize(dim_id: str, raw_value: float) -> float:
    """Normalize a raw dimension value to 0.0–1.0.

    Args:
        dim_id: Dimension identifier (D1-D35).
        raw_value: Raw computed value from the dimension function.

    Returns:
        Normalized value in [0.0, 1.0].

    Raises:
        KeyError: If dim_id is not in the normalization config.
    """
    strategy, cap = NORMALIZATION_CONFIG[dim_id]

    if strategy == Strategy.RATIO:
        return _normalize_ratio(raw_value)
    if strategy == Strategy.MCC:
        return _normalize_mcc(raw_value)
    if strategy == Strategy.LOWER_IS_BETTER:
        return _normalize_lower_is_better(raw_value, cap)
    if strategy == Strategy.HIGHER_IS_BETTER:
        return _normalize_higher_is_better(raw_value, cap)

    return _normalize_ratio(raw_value)  # fallback


def normalize_all(raw_dimensions: dict[str, float]) -> dict[str, float]:
    """Normalize all raw dimension values."""
    return {dim_id: normalize(dim_id, raw) for dim_id, raw in raw_dimensions.items()}
