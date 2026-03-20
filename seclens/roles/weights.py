"""YAML weight profile loading for role-based scoring."""

from __future__ import annotations

from pathlib import Path

import yaml

from seclens.roles.dimensions import DIMENSION_FUNCTIONS

PROFILES_DIR = Path(__file__).parent / "profiles"


class WeightProfile:
    """A loaded role weight profile."""

    def __init__(self, data: dict) -> None:
        self.role: str = data["role"]
        self.name: str = data["name"]
        self.description: str = data["description"]
        self.version: str = data["version"]
        self.dimensions: dict[str, float] = {
            dim_id: entry["weight"]
            for dim_id, entry in data["dimensions"].items()
        }
        self.categories: dict[str, list[str]] = data.get("categories", {})

    @property
    def total_weight(self) -> float:
        return sum(self.dimensions.values())

    EXPECTED_TOTAL_WEIGHT = 80.0

    def validate(self) -> list[str]:
        """Return list of validation errors (empty if valid)."""
        errors = []
        for dim_id in self.dimensions:
            if dim_id not in DIMENSION_FUNCTIONS:
                errors.append(f"Unknown dimension ID: {dim_id}")
        total = self.total_weight
        if abs(total - self.EXPECTED_TOTAL_WEIGHT) > 0.01:
            errors.append(f"Weights sum to {total}, expected {self.EXPECTED_TOTAL_WEIGHT}")
        return errors


def load_profile(role: str) -> WeightProfile:
    """Load a role's weight profile from YAML.

    Args:
        role: Role identifier (e.g., "ciso", "ai_actor").

    Returns:
        Loaded and parsed weight profile.

    Raises:
        ValueError: If the role is unknown or the profile is invalid.
    """
    path = PROFILES_DIR / f"{role}.yaml"
    if not path.exists():
        available = ", ".join(list_roles())
        raise ValueError(f"Unknown role: {role!r}. Available: {available}")

    with open(path) as f:
        data = yaml.safe_load(f)

    profile = WeightProfile(data)
    errors = profile.validate()
    if errors:
        raise ValueError(f"Invalid profile {role!r}: {'; '.join(errors)}")

    return profile


def list_roles() -> list[str]:
    """List available role names (from YAML files in profiles dir)."""
    return sorted(p.stem for p in PROFILES_DIR.glob("*.yaml"))
