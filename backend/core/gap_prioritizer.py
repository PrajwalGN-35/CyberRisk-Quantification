from __future__ import annotations

from typing import Any


def prioritize_security_gaps(risk_assessments: dict[str, Any]) -> list[dict[str, Any]]:
    """Rank actionable security gaps."""
    if not isinstance(risk_assessments, dict):
        return []

    prioritized: list[dict[str, Any]] = []
    for asset in risk_assessments.get("asset_risks", []):
        score = float(asset.get("score", 0.0))
        if score < 35:
            continue
        severity = "High" if score >= 75 else "Medium" if score >= 55 else "Low"
        priority = "P1" if score >= 75 else "P2" if score >= 55 else "P3"
        prioritized.append(
            {
                "name": f"Hardening gap on {asset['asset']}",
                "severity": severity,
                "affected_asset": asset["asset"],
                "risk_contribution": round(score, 2),
                "recommended_action": (
                    "Reduce exposure with asset hardening, patching, and control validation on "
                    f"{asset['asset']}."
                ),
                "priority": priority,
                "explanation": (
                    f"{asset['asset']} has a modeled risk score of {score:.2f} because it combines "
                    "critical exposure, vulnerability pressure, and control effectiveness gaps."
                ),
            }
        )

    for factor in risk_assessments.get("risk_factors", []):
        if not any(gap["name"].startswith(factor["factor"]) for gap in prioritized):
            prioritized.append(
                {
                    "name": factor["factor"],
                    "severity": "High" if factor["score"] >= 60 else "Medium",
                    "affected_asset": "Organization-wide",
                    "risk_contribution": round(factor["score"], 2),
                    "recommended_action": "Prioritize targeted remediation and monitoring for the dominant risk driver.",
                    "priority": "P1" if factor["score"] >= 60 else "P2",
                    "explanation": (
                        f"{factor['factor']} contributes {factor['score']:.2f} to the overall modeled risk "
                        "profile and should be addressed before lower-impact issues."
                    ),
                }
            )

    prioritized.sort(key=lambda item: self_weight(item), reverse=True)
    return prioritized[:5]


def self_weight(item: dict[str, Any]) -> float:
    severity_rank = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2}
    return float(item.get("risk_contribution", 0.0)) + severity_rank.get(item.get("severity"), 0) * 10
