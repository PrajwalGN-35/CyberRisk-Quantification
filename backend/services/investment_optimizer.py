from __future__ import annotations

from typing import Any


def optimize_investments(
    risk_assessments: dict[str, Any],
    investments: list[dict[str, Any]],
    budget: float,
) -> dict[str, Any]:
    """Select investments subject to the available budget."""
    if budget < 0:
        raise ValueError("Budget must be non-negative.")

    current_score = float(risk_assessments.get("overall_risk_score", 0.0))
    ranked = sorted(
        investments,
        key=lambda item: (
            float(item.get("expected_risk_reduction", 0.0)) / max(float(item.get("cost", 1.0)), 1.0),
            float(item.get("expected_risk_reduction", 0.0)),
        ),
        reverse=True,
    )

    selected: list[dict[str, Any]] = []
    remaining_budget = float(budget)
    total_cost = 0.0
    perceived_reduction = 0.0

    for investment in ranked:
        cost = float(investment.get("cost", 0.0))
        if cost <= 0:
            continue
        if cost <= remaining_budget:
            selected.append(investment)
            remaining_budget -= cost
            total_cost += cost
            perceived_reduction += float(investment.get("expected_risk_reduction", 0.0))

    selected_ids = [investment.get("name") for investment in selected]
    unselected = [inv for inv in investments if inv.get("name") not in selected_ids]
    after_risk_score = max(0.0, current_score - (perceived_reduction * 0.8))

    return {
        "budget": float(budget),
        "selected_investments": selected,
        "unselected_investments": unselected,
        "total_cost": round(total_cost, 2),
        "remaining_budget": round(remaining_budget, 2),
        "before_risk_score": round(current_score, 2),
        "after_risk_score": round(after_risk_score, 2),
        "risk_reduction_estimate": round(perceived_reduction, 2),
    }
