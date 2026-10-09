from __future__ import annotations

from typing import Any


def answer_question(
    question: str,
    state: dict[str, Any] | None = None,
    risk_assessment: dict[str, Any] | None = None,
    gaps: list[dict[str, Any]] | None = None,
    optimizer_result: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Return a deterministic, grounded explanation for the current state."""
    state = state or {}
    risk_assessment = risk_assessment or {}
    gaps = gaps or []
    optimizer_result = optimizer_result or {}

    overall_score = float(risk_assessment.get("overall_risk_score", 0.0))
    risk_level = risk_assessment.get("risk_level", "Low")
    highest_asset = (
        max(
            risk_assessment.get("asset_risks", []),
            key=lambda item: float(item.get("score", 0.0)),
            default={"asset": "No assets available", "score": 0.0},
        )
    )
    top_gap = gaps[0] if gaps else {"name": "No active gaps", "severity": "Low"}

    question_lower = (question or "").lower()

    if "budget" in question_lower or "allocate" in question_lower or "investment" in question_lower:
        allocation = optimizer_result.get("selected_investments", []) or state.get("investments", [])[:2]
        selected_names = ", ".join(item.get("name", "investment") for item in allocation[:3]) if allocation else "no targeted investments"
        answer = (
            f"The assessed risk is {overall_score:.2f}/100 ({risk_level}), and the most valuable budget allocation is "
            f"{selected_names}. This recommendation is supported by the current risk drivers and the optimizer's ranking "
            f"of cost-efficient controls."
        )
    elif "vulnerab" in question_lower or "first" in question_lower:
        answer = (
            f"The highest-priority issue is {top_gap.get('name', 'the top risk gap')} on {top_gap.get('affected_asset', 'the organization')} "
            f"with severity {top_gap.get('severity', 'Medium')}. This should be addressed before lower-impact issues because it "
            f"contributes {top_gap.get('risk_contribution', 0.0):.2f} to the modeled risk exposure."
        )
    elif "why" in question_lower or "high" in question_lower or "risk" in question_lower:
        key_drivers = ", ".join(
            item.get("factor", "risk driver") for item in risk_assessment.get("risk_factors", [])[:3]
        ) or "control coverage gaps"
        answer = (
            f"The score is elevated because the current model identifies {key_drivers} as significant contributors. "
            f"The highest-risk asset is {highest_asset.get('asset', 'unknown')}, at {highest_asset.get('score', 0.0):.2f}/100, "
            f"which is why the organization-wide score reaches {overall_score:.2f}/100 ({risk_level})."
        )
    elif "event" in question_lower or "critical vulnerability" in question_lower:
        answer = (
            "A critical vulnerability or exploit attempt raises the modeled risk by increasing both threat likelihood and incident severity. "
            "The system should respond by validating the vulnerable asset, accelerating patch or compensating controls, and reprioritizing "
            "budget allocation toward the affected domain."
        )
    elif "remediation" in question_lower or "value" in question_lower:
        answer = (
            f"The most valuable remediation is to address {top_gap.get('name', 'the top risk gap')} because it offers the largest "
            f"risk reduction within the current threat context. This is the best use of budget when the organization needs to reduce "
            f"{overall_score:.2f}/100 to a more resilient target state."
        )
    else:
        answer = (
            f"Based on the latest assessment, the current modeled cyber risk is {overall_score:.2f}/100 ({risk_level}). "
            f"The leading issue is {top_gap.get('name', 'the top risk gap')} and the most exposed asset is {highest_asset.get('asset', 'the organization')}. "
            "The recommended next action is to remediate the top-priority gap and validate the relevant security controls."
        )

    return {
        "question": question,
        "answer": answer,
        "grounded": True,
        "evidence": {
            "overall_risk_score": round(overall_score, 2),
            "risk_level": risk_level,
            "top_gap": top_gap,
            "highest_asset": highest_asset,
            "selected_budget_items": optimizer_result.get("selected_investments", [])[:3],
        },
    }
