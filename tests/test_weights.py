"""Tests for YAML weight profiles and loader."""

from __future__ import annotations

import pytest

from seclens.roles.dimensions import DIMENSION_FUNCTIONS
from seclens.roles.weights import WeightProfile, list_roles, load_profile


EXPECTED_ROLES = ["ai_actor", "caio", "ciso", "head_of_engineering", "security_researcher"]


class TestListRoles:
    def test_all_five_roles(self) -> None:
        roles = list_roles()
        assert roles == EXPECTED_ROLES

    def test_returns_sorted(self) -> None:
        roles = list_roles()
        assert roles == sorted(roles)


class TestLoadProfile:
    @pytest.mark.parametrize("role", EXPECTED_ROLES)
    def test_loads_without_error(self, role: str) -> None:
        profile = load_profile(role)
        assert isinstance(profile, WeightProfile)

    @pytest.mark.parametrize("role", EXPECTED_ROLES)
    def test_weights_sum_to_80(self, role: str) -> None:
        profile = load_profile(role)
        assert abs(profile.total_weight - 80.0) < 0.01, (
            f"{role} weights sum to {profile.total_weight}, expected 80.0"
        )

    @pytest.mark.parametrize("role", EXPECTED_ROLES)
    def test_all_dimension_ids_valid(self, role: str) -> None:
        profile = load_profile(role)
        for dim_id in profile.dimensions:
            assert dim_id in DIMENSION_FUNCTIONS, (
                f"{role} references unknown dimension: {dim_id}"
            )

    @pytest.mark.parametrize("role", EXPECTED_ROLES)
    def test_has_required_fields(self, role: str) -> None:
        profile = load_profile(role)
        assert profile.role
        assert profile.name
        assert profile.description
        assert profile.version

    @pytest.mark.parametrize("role", EXPECTED_ROLES)
    def test_all_weights_positive(self, role: str) -> None:
        profile = load_profile(role)
        for dim_id, weight in profile.dimensions.items():
            assert weight > 0, f"{role}.{dim_id} has non-positive weight: {weight}"

    @pytest.mark.parametrize("role", EXPECTED_ROLES)
    def test_has_categories(self, role: str) -> None:
        profile = load_profile(role)
        assert profile.categories, f"{role} has no categories"
        # All dimensions should appear in at least one category
        categorized = set()
        for dims in profile.categories.values():
            categorized.update(dims)
        for dim_id in profile.dimensions:
            assert dim_id in categorized, (
                f"{role}.{dim_id} not in any category"
            )

    def test_unknown_role_raises(self) -> None:
        with pytest.raises(ValueError, match="Unknown role"):
            load_profile("cfo")


class TestWeightProfile:
    def test_validate_bad_dimension(self) -> None:
        data = {
            "role": "test", "name": "Test", "description": "Test",
            "version": "1.0",
            "dimensions": {"D99": {"weight": 80}},
        }
        profile = WeightProfile(data)
        errors = profile.validate()
        assert any("D99" in e for e in errors)

    def test_validate_bad_weight_sum(self) -> None:
        data = {
            "role": "test", "name": "Test", "description": "Test",
            "version": "1.0",
            "dimensions": {"D1": {"weight": 50}},
        }
        profile = WeightProfile(data)
        errors = profile.validate()
        assert any("80" in e for e in errors)


class TestRoleDifferentiation:
    """Verify roles actually emphasize different dimensions."""

    def test_ciso_emphasizes_severity(self) -> None:
        profile = load_profile("ciso")
        assert "D28" in profile.dimensions
        assert "D29" in profile.dimensions

    def test_researcher_emphasizes_cwe(self) -> None:
        profile = load_profile("security_researcher")
        assert profile.dimensions.get("D6", 0) >= 10  # CWE Accuracy highest

    def test_engineer_emphasizes_precision(self) -> None:
        profile = load_profile("head_of_engineering")
        assert profile.dimensions.get("D3", 0) >= 10  # Precision highest

    def test_ai_actor_emphasizes_autonomy(self) -> None:
        profile = load_profile("ai_actor")
        assert profile.dimensions.get("D34", 0) >= 10  # Autonomous Completion highest

    def test_caio_emphasizes_efficiency(self) -> None:
        profile = load_profile("caio")
        assert "D20" in profile.dimensions  # MCC per Dollar
        assert "D22" in profile.dimensions  # Throughput
