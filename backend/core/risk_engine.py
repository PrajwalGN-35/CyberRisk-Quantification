from __future__ import annotations

from typing import Any


def _to_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _risk_level(score: float) -> str:
    if score >= 80:
        return "Critical"
    if score >= 65:
        return "High"
    if score >= 40:
        return "Moderate"
    return "Low"


def calculate_risk(
    assets: list[dict[str, Any]],
    vulnerabilities: list[dict[str, Any]],
    threats: list[dict[str, Any]],
    incidents: list[dict[str, Any]],
    controls: list[dict[str, Any]],
) -> dict[str, Any]:
    """Calculate explainable asset-level and organization-level risk."""
    if not assets:
        return {
            "overall_risk_score": 0.0,
            "risk_level": "Low",
            "asset_risks": [],
            "risk_factors": [],
            "synthetic": True,
            "summary": "No assets were provided to assess.",
        }

    asset_scores: list[dict[str, Any]] = []
    factor_map: dict[str, float] = {
        "Critical asset exposure": 0.0,
        "Known vulnerabilities": 0.0,
        "Threat activity": 0.0,
        "Control coverage": 0.0,
        "Incident pressure": 0.0,
    }

    control_value_by_asset: dict[str, list[float]] = {}
    for control in controls:
        asset_name = str(control.get("asset") or control.get("affected_asset") or "General").strip()
        effectiveness = _to_float(control.get("effectiveness"), 50.0)
        control_value_by_asset.setdefault(asset_name, []).append(effectiveness)

    for asset in assets:
        asset_name = str(asset.get("name") or asset.get("asset") or "Unnamed asset")
        asset_value = _to_float(asset.get("value"), 60.0)
        criticality = _to_float(asset.get("criticality"), 50.0)
        asset_control_effectiveness = sum(control_value_by_asset.get(asset_name, [])) / max(
            len(control_value_by_asset.get(asset_name, [])), 1
        )

        vulnerability_score = 0.0
        for vuln in vulnerabilities:
            vuln_asset = str(vuln.get("asset") or vuln.get("affected_asset") or "").strip()
            if vuln_asset and vuln_asset != asset_name:
                continue
            severity = _to_float(vuln.get("severity"), 5.0)
            likelihood = _to_float(vuln.get("likelihood"), 0.6)
            exploitability = max(0.0, severity * likelihood * 12.0 - asset_control_effectiveness * 0.08)
            vulnerability_score += exploitability

        threat_score = 0.0
        for threat in threats:
            threat_asset = str(threat.get("asset") or threat.get("target_asset") or "").strip()
            if threat_asset and threat_asset != asset_name:
                continue
            impact = _to_float(threat.get("impact"), 5.0)
            likelihood = _to_float(threat.get("likelihood"), 0.6)
            threat_score += impact * likelihood * 12.0

        incident_score = 0.0
        for incident in incidents:
            incident_asset = str(incident.get("asset") or incident.get("affected_asset") or "").strip()
            if incident_asset and incident_asset != asset_name:
                continue
            severity = _to_float(incident.get("severity"), 5.0)
            incident_score += severity * 10.0

        asset_score = min(
            100.0,
            (
                asset_value * 0.25
                + criticality * 0.25
                + vulnerability_score * 0.25
                + threat_score * 0.15
                + incident_score * 0.10
            )
            / 1.5,
        )

        factor_map["Critical asset exposure"] += max(0.0, criticality * 0.5)
        factor_map["Known vulnerabilities"] += vulnerability_score
        factor_map["Threat activity"] += threat_score
        factor_map["Control coverage"] += max(0.0, 100.0 - asset_control_effectiveness)
        factor_map["Incident pressure"] += incident_score

        asset_scores.append(
            {
                "asset": asset_name,
                "score": round(asset_score, 2),
                "risk_level": _risk_level(asset_score),
                "criticality": round(criticality, 2),
                "control_effectiveness": round(asset_control_effectiveness, 2),
            }
        )

    overall_risk_score = round(sum(item["score"] for item in asset_scores) / max(len(asset_scores), 1), 2)
    normalized_factor_scores = [
        {"factor": name, "score": round(min(100.0, value), 2)}
        for name, value in factor_map.items()
        if value > 0
    ]
    normalized_factor_scores.sort(key=lambda item: item["score"], reverse=True)

    return {
        "overall_risk_score": overall_risk_score,
        "risk_level": _risk_level(overall_risk_score),
        "asset_risks": asset_scores,
        "risk_factors": normalized_factor_scores,
        "synthetic": True,
        "summary": (
            f"The modeled cyber risk is {overall_risk_score:.2f}/100, classified as {_risk_level(overall_risk_score)}. "
            f"The highest-risk assets are prioritized for remediation and investment."
        ),
    }
