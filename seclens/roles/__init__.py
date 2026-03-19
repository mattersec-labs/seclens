"""Role-specific benchmark dimensions and scoring."""

from seclens.roles.scorer import generate_multi_role_report, generate_role_report
from seclens.roles.weights import list_roles

__all__ = ["generate_role_report", "generate_multi_role_report", "list_roles"]
