"""Role-specific scorer — generates full role reports from TaskResult data."""

from __future__ import annotations

from collections import defaultdict

from seclens.roles.dimensions import (
    DIMENSION_CATEGORIES,
    DIMENSION_NAMES,
    compute_all_dimensions,
)
from seclens.roles.normalization import normalize
from seclens.roles.weights import WeightProfile, list_roles, load_profile
from seclens.schemas.role_report import (
    CategoryScore,
    DimensionScore,
    MultiRoleReport,
    RoleReport,
)
from seclens.schemas.scoring import TaskResult
from seclens.schemas.task import EvalLayer, TaskType


# ---------------------------------------------------------------------------
# Data availability checks
# ---------------------------------------------------------------------------

_SEVERITY_DIMS = {"D28", "D29", "D30"}
_TOOL_DIMS = {"D24", "D25", "D26", "D27"}
_LOCATION_DIMS = {"D7", "D8"}
_SAST_FP_DIMS = {"D13"}


def _unavailable_dimensions(results: list[TaskResult]) -> set[str]:
    """Determine which dimensions lack data and should be excluded."""
    excluded: set[str] = set()

    if not any(r.task_severity for r in results):
        excluded |= _SEVERITY_DIMS

    if not any(r.metrics.tool_calls > 0 for r in results if r.error is None):
        excluded |= _TOOL_DIMS

    # CIP: location scoring not possible (no file path/absolute lines in prompt)
    if results and results[0].run_metadata.layer == EvalLayer.CODE_IN_PROMPT:
        excluded |= _LOCATION_DIMS

    if not any(r.task_type == TaskType.SAST_FALSE_POSITIVE for r in results):
        excluded |= _SAST_FP_DIMS

    return excluded


# ---------------------------------------------------------------------------
# Grading
# ---------------------------------------------------------------------------

def _score_to_grade(score: float) -> str:
    if score >= 75:
        return "A"
    if score >= 60:
        return "B"
    if score >= 50:
        return "C"
    if score >= 40:
        return "D"
    return "F"


# ---------------------------------------------------------------------------
# Recommendations
# ---------------------------------------------------------------------------

_ROLE_CONTEXTS = {
    "ciso": "deploying this model in your security program",
    "caio": "adopting this model for AI-driven security operations",
    "security_researcher": "relying on this model for vulnerability research",
    "head_of_engineering": "integrating this model into development pipelines",
    "ai_actor": "running this model autonomously on security tasks",
}

_GRADE_TEMPLATES = {
    "A": "Excellent for {context}. Strong performance across critical dimensions.",
    "B": "Good for {context}. Review weak dimensions ({weaknesses}) before deployment.",
    "C": "Fair for {context}. Requires human oversight. Key gaps: {weaknesses}.",
    "D": "Poor for {context}. Significant gaps in: {weaknesses}.",
    "F": "Not suitable for {context}. Fundamental capability gaps across multiple dimensions.",
}


def _generate_recommendation(
    role: str,
    grade: str,
    dimensions: list[DimensionScore],
) -> str:
    context = _ROLE_CONTEXTS.get(role, f"using this model for {role}")
    weaknesses = sorted(dimensions, key=lambda d: d.normalized)[:3]
    weakness_names = ", ".join(d.name for d in weaknesses)
    template = _GRADE_TEMPLATES[grade]
    return template.format(context=context, weaknesses=weakness_names)


# ---------------------------------------------------------------------------
# Category building
# ---------------------------------------------------------------------------

def _build_categories(
    dimensions: list[DimensionScore],
    profile: WeightProfile,
) -> list[CategoryScore]:
    """Group dimensions into categories for display."""
    cat_map: dict[str, list[DimensionScore]] = defaultdict(list)
    for dim in dimensions:
        cat_map[dim.category].append(dim)

    categories = []
    for cat_name, dims in cat_map.items():
        categories.append(CategoryScore(
            name=cat_name,
            total_weight=sum(d.weight for d in dims),
            weighted_score=round(sum(d.weighted_score for d in dims), 4),
            dimensions=dims,
        ))
    return sorted(categories, key=lambda c: -c.total_weight)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_role_report(
    results: list[TaskResult],
    role: str,
    *,
    model: str | None = None,
    layer: EvalLayer | None = None,
) -> RoleReport:
    """Generate a complete role-specific report from evaluation results.

    Args:
        results: Task results from an evaluation run.
        role: Role name (e.g., "ciso", "ai_actor").
        model: Model identifier (auto-detected from results if omitted).
        layer: Evaluation layer (auto-detected from results if omitted).

    Returns:
        Complete role report with score, grade, dimensions, and recommendation.
    """
    profile = load_profile(role)
    raw_dimensions = compute_all_dimensions(results)
    excluded = _unavailable_dimensions(results)

    # Build dimension scores for this role
    dimension_scores: list[DimensionScore] = []
    total_weighted = 0.0
    total_weight = 0.0

    for dim_id, weight in profile.dimensions.items():
        if dim_id in excluded:
            continue

        raw = raw_dimensions.get(dim_id, 0.0)
        normalized = normalize(dim_id, raw)
        weighted = round(normalized * weight, 4)

        dimension_scores.append(DimensionScore(
            id=dim_id,
            name=DIMENSION_NAMES.get(dim_id, dim_id),
            category=DIMENSION_CATEGORIES.get(dim_id, "Other"),
            raw_value=round(raw, 4),
            normalized=round(normalized, 4),
            weight=weight,
            weighted_score=weighted,
        ))

        total_weighted += weighted
        total_weight += weight

    # Decision score: 0-100
    decision_score = round(total_weighted / total_weight * 100, 1) if total_weight > 0 else 0.0

    # Grade
    grade = _score_to_grade(decision_score)

    # Categories
    categories = _build_categories(dimension_scores, profile)

    # Recommendation
    recommendation = _generate_recommendation(role, grade, dimension_scores)

    # Auto-detect model and layer from results
    detected_model = model or (results[0].run_metadata.model if results else "unknown")
    detected_layer = layer or (results[0].run_metadata.layer if results else EvalLayer.CODE_IN_PROMPT)

    # Layer note for CIP
    layer_note = None
    if detected_layer == EvalLayer.CODE_IN_PROMPT:
        available_weight = sum(d.weight for d in dimension_scores)
        layer_note = (
            f"Code-in-Prompt evaluation ({available_weight:.0f}/{profile.total_weight:.0f} weight scored). "
            "Location precision and tool-use dimensions not measured. "
            "Run with --layer tool-use for full coverage."
        )

    return RoleReport(
        role=role,
        role_name=profile.name,
        role_description=profile.description,
        decision_score=decision_score,
        grade=grade,
        categories=categories,
        dimensions=dimension_scores,
        model=detected_model,
        layer=detected_layer,
        total_tasks=len(results),
        recommendation=recommendation,
        excluded_dimensions=sorted(excluded & set(profile.dimensions)),
        layer_note=layer_note,
    )


def generate_multi_role_report(
    results: list[TaskResult],
    roles: list[str] | None = None,
    *,
    model: str | None = None,
    layer: EvalLayer | None = None,
) -> MultiRoleReport:
    """Generate reports for all roles (or a subset) from the same results.

    Args:
        results: Task results from an evaluation run.
        roles: Role names to include (defaults to all available).
        model: Model identifier (auto-detected if omitted).
        layer: Evaluation layer (auto-detected if omitted).

    Returns:
        Multi-role report with per-role reports and cross-role ranking.
    """
    role_names = roles or list_roles()
    reports: dict[str, RoleReport] = {}

    for role in role_names:
        reports[role] = generate_role_report(results, role, model=model, layer=layer)

    ranking = sorted(reports, key=lambda r: -reports[r].decision_score)
    detected_model = model or (results[0].run_metadata.model if results else "unknown")

    return MultiRoleReport(
        model=detected_model,
        reports=reports,
        ranking=ranking,
    )
