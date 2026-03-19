"""Tests for dimension normalization."""

from __future__ import annotations

import pytest

from seclens.roles.normalization import (
    NORMALIZATION_CONFIG,
    normalize,
    normalize_all,
)


class TestRatioNormalization:
    """Dimensions that are already 0-1 (most dimensions)."""

    def test_within_range(self) -> None:
        assert normalize("D2", 0.75) == 0.75

    def test_clamp_above_one(self) -> None:
        assert normalize("D2", 1.5) == 1.0

    def test_clamp_below_zero(self) -> None:
        assert normalize("D2", -0.1) == 0.0

    def test_zero(self) -> None:
        assert normalize("D2", 0.0) == 0.0

    def test_one(self) -> None:
        assert normalize("D2", 1.0) == 1.0


class TestMCCNormalization:
    """D1 (MCC): maps [-1, 1] → [0, 1]."""

    def test_perfect(self) -> None:
        assert normalize("D1", 1.0) == 1.0

    def test_worst(self) -> None:
        assert normalize("D1", -1.0) == 0.0

    def test_random(self) -> None:
        assert normalize("D1", 0.0) == 0.5

    def test_positive(self) -> None:
        assert normalize("D1", 0.5) == 0.75


class TestLowerIsBetter:
    """Cost, time, token dimensions — lower raw = better normalized."""

    def test_cost_free(self) -> None:
        assert normalize("D18", 0.0) == 1.0

    def test_cost_at_cap(self) -> None:
        assert normalize("D18", 0.50) == 0.0

    def test_cost_above_cap(self) -> None:
        assert normalize("D18", 1.00) == 0.0

    def test_cost_half_cap(self) -> None:
        assert normalize("D18", 0.25) == pytest.approx(0.5)

    def test_wall_time_fast(self) -> None:
        assert normalize("D21", 10.0) == pytest.approx(1.0 - 10.0 / 120.0)

    def test_tokens_moderate(self) -> None:
        assert normalize("D23", 25_000) == pytest.approx(0.5)

    def test_turns_low(self) -> None:
        assert normalize("D25", 2.0) == pytest.approx(1.0 - 2.0 / 20.0)


class TestHigherIsBetter:
    """Throughput, MCC/dollar — higher raw = better normalized."""

    def test_throughput_zero(self) -> None:
        assert normalize("D22", 0.0) == 0.0

    def test_throughput_at_cap(self) -> None:
        assert normalize("D22", 60.0) == 1.0

    def test_throughput_above_cap(self) -> None:
        assert normalize("D22", 120.0) == 1.0

    def test_throughput_half(self) -> None:
        assert normalize("D22", 30.0) == pytest.approx(0.5)

    def test_mcc_per_dollar(self) -> None:
        assert normalize("D20", 50.0) == pytest.approx(0.5)


class TestRegistry:
    def test_all_35_configured(self) -> None:
        for i in range(1, 36):
            assert f"D{i}" in NORMALIZATION_CONFIG

    def test_unknown_dim_raises(self) -> None:
        with pytest.raises(KeyError):
            normalize("D99", 0.5)


class TestNormalizeAll:
    def test_normalizes_all(self) -> None:
        raw = {"D1": 0.5, "D2": 0.8, "D18": 0.25}
        result = normalize_all(raw)
        assert result["D1"] == pytest.approx(0.75)  # MCC
        assert result["D2"] == pytest.approx(0.8)    # ratio
        assert result["D18"] == pytest.approx(0.5)   # lower-is-better

    def test_all_output_in_range(self) -> None:
        # All dimensions at boundary values
        raw = {f"D{i}": 0.5 for i in range(1, 36)}
        result = normalize_all(raw)
        for dim_id, val in result.items():
            assert 0.0 <= val <= 1.0, f"{dim_id} normalized to {val}"
