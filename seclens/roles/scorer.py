"""Role-specific scorer — generates full role reports from TaskResult data."""

from __future__ import annotations

from seclens.roles.dimensions import (
    DIMENSION_CATEGORIES,
    DIMENSION_NAMES,
    compute_all_dimensions,
)
from seclens.roles.schemas import (
    CategoryScore,
    DimensionScore,
    MultiRoleReport,
    RoleReport,
)
from seclens.roles.weights import (
    compute_decision_score,
    generate_recommendation,
    list_available_roles,
    load_weight_profile,
    normalize_dimension,
    score_to_grade,
)
from seclens.schemas.scoring import TaskResult

ROLE_DESCRIPTIONS: dict[str, str] = {
    "ciso": "Chief Information Security Officer — evaluates model trustworthiness for security programs",
    "caio": "Chief AI Officer / Head of AI — evaluates capability upside vs. risk for business enablement",
    "security_researcher": "Security Researcher — evaluates depth and reliability of vulnerability reasoning",
    "head_of_engineering": "Head of Engineering — evaluates impact on team velocity and code quality",
    "ai_actor": "AI as Actor — evaluates autonomous operation capability without human supervision",
}


def generate_role_report(
    results: list[TaskResult],
    role: str,
    model: str | None = None,
    layer: int | None = None,
) -> RoleReport:
    """Generate a complete role-specific report.

    Args:
        results: All task results from an evaluation run.
        role: Role profile name (e.g. 'ciso').
        model: Model identifier override.
        layer: Evaluation layer override.

    Returns:
        Full RoleReport with composite score and per-dimension breakdowns.
    """
    weights = load_weight_profile(role)
    raw_dims = compute_all_dimensions(results)
    decision_score, details = compute_decision_score(raw_dims, weights)
    grade = score_to_grade(decision_score)

    # Build dimension scores
    dimension_scores: list[DimensionScore] = []
    for dim_id, norm, weight, weighted in details:
        dimension_scores.append(DimensionScore(
            id=dim_id,
            name=DIMENSION_NAMES.get(dim_id, f"Dimension {dim_id}"),
            category=DIMENSION_CATEGORIES.get(dim_id, "Unknown"),
            raw_value=raw_dims[dim_id],
            normalized=norm,
            weight=weight,
            weighted_score=weighted,
        ))

    # Build category scores
    cat_groups: dict[str, list[DimensionScore]] = {}
    for ds in dimension_scores:
        cat_groups.setdefault(ds.category, []).append(ds)

    category_scores = [
        CategoryScore(
            name=cat_name,
            total_weight=sum(d.weight for d in dims),
            weighted_score=sum(d.weighted_score for d in dims),
            dimensions=dims,
        )
        for cat_name, dims in cat_groups.items()
    ]

    # Infer model and layer from results
    if model is None and results:
        model = results[0].run_metadata.model
    if layer is None and results:
        layer = results[0].run_metadata.layer

    return RoleReport(
        role=role,
        role_description=ROLE_DESCRIPTIONS.get(role, role),
        decision_score=round(decision_score, 2),
        grade=grade,
        categories=category_scores,
        dimensions=dimension_scores,
        model=model or "unknown",
        layer=layer or 2,
        total_tasks=len(results),
        recommendation=generate_recommendation(role, decision_score, grade),
    )


def generate_multi_role_report(
    results: list[TaskResult],
    roles: list[str] | None = None,
) -> MultiRoleReport:
    """Generate reports for all roles from the same result data.

    Args:
        results: All task results.
        roles: Optional list of roles. Defaults to all available.

    Returns:
        MultiRoleReport with per-role reports and ranking.
    """
    if roles is None:
        roles = list_available_roles()

    reports: dict[str, RoleReport] = {}
    for role in roles:
        reports[role] = generate_role_report(results, role)

    ranking = sorted(reports.keys(), key=lambda r: -reports[r].decision_score)

    model = results[0].run_metadata.model if results else "unknown"

    return MultiRoleReport(
        model=model,
        reports=reports,
        ranking=ranking,
    )
