"""Evidence-based security-gap ranking for risk-engine assessments."""

import math
from typing import Any

from backend.core.risk_engine import (
    _asset_id,
    _canonical,
    _category,
    _first_nonempty,
    _round,
    _score_from_record,
)


_PRIORITY_WEIGHTS = {
    "residual_risk": 0.35,
    "criticality": 0.20,
    "vulnerability_severity": 0.20,
    "exposure": 0.10,
    "incident_history": 0.10,
    "control_weakness": 0.05,
}
_DOMAIN_NAMES = {
    "vulnerability": "vulnerability",
    "vulnerabilities": "vulnerability",
    "threat": "threat",
    "threats": "threat",
    "incident": "incident",
    "incidents": "incident",
    "exposure": "exposure",
}


def _domains(record: dict[str, Any]) -> set[str]:
    value = record.get("domains", record.get("domain"))
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list):
        return set()
    return {
        _DOMAIN_NAMES[item.strip().casefold()]
        for item in value
        if isinstance(item, str) and item.strip().casefold() in _DOMAIN_NAMES
    }


def _applicable_control_weakness(
    controls: list[dict[str, Any]], asset_id: str
) -> float | None:
    effectiveness_values = []
    for control in controls:
        if "vulnerability" not in _domains(control):
            continue
        control_asset_ids = control.get("asset_ids")
        if control_asset_ids is None:
            control_asset_ids = [control.get("asset_id")]
        if not isinstance(control_asset_ids, list):
            continue
        if asset_id not in {
            normalized
            for value in control_asset_ids
            if (normalized := _asset_id(value)) is not None
        }:
            continue
        effectiveness = _score_from_record(
            control, ("effectiveness", "effectiveness_score"), "percentage"
        )
        if effectiveness is not None:
            effectiveness_values.append(effectiveness)
    if not effectiveness_values:
        return None
    return 100.0 - max(effectiveness_values)


def _weighted_priority(factors: dict[str, float]) -> float | None:
    available = [
        (weight, factors[name])
        for name, weight in _PRIORITY_WEIGHTS.items()
        if name in factors
    ]
    denominator = sum(weight for weight, _ in available)
    if not denominator:
        return None
    return sum(weight * value for weight, value in available) / denominator


def _record_list(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _normalized_score(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    score = float(value)
    if not math.isfinite(score) or not 0 <= score <= 100:
        return None
    return score


def _belongs_to_asset(record: dict[str, Any], asset_id: str) -> bool:
    identifiers = record.get("asset_ids")
    if identifiers is None:
        identifiers = [record.get("asset_id")]
    if not isinstance(identifiers, list):
        return False
    return asset_id in {
        normalized
        for value in identifiers
        if (normalized := _asset_id(value)) is not None
    }


def _has_vulnerability_evidence(record: dict[str, Any]) -> bool:
    if _first_nonempty(record, ("vulnerability_id", "id", "title", "name")) is not None:
        return True
    return (
        _score_from_record(
            record,
            ("severity", "cvss_score", "severity_score"),
            "severity",
        )
        is not None
    )


def _make_gap(
    asset: dict[str, Any],
    gap_type: str,
    record: dict[str, Any],
    gap_id: str | None,
    severity: float | None,
    control_weakness: float | None,
) -> dict[str, Any]:
    factors: dict[str, float] = {}
    residual_risk = _normalized_score(asset.get("residual_risk_score"))
    if residual_risk is not None:
        factors["residual_risk"] = residual_risk

    asset_factors = asset.get("factors")
    if not isinstance(asset_factors, dict):
        asset_factors = {}
    for name, aliases, scale in (
        ("criticality", ("criticality", "criticality_score"), "percentage"),
        ("exposure", ("exposure", "exposure_score"), "percentage"),
        ("incident_history", ("incident_history", "incident_history_score"), "percentage"),
    ):
        value = asset_factors.get(name)
        normalized = _normalized_score(value)
        if normalized is None:
            normalized = _score_from_record(asset, aliases, scale)
        if normalized is not None:
            factors[name] = normalized

    if severity is not None:
        factors["vulnerability_severity"] = severity
    elif gap_type == "control":
        asset_severity = _normalized_score(
            asset_factors.get("vulnerability_severity")
        )
        if asset_severity is not None:
            factors["vulnerability_severity"] = asset_severity
    if control_weakness is not None:
        factors["control_weakness"] = control_weakness

    priority = _weighted_priority(factors)
    title = _first_nonempty(record, ("title", "name", "summary"))
    recommendation = _first_nonempty(
        record, ("remediation", "recommendation", "fix")
    )
    if recommendation is None:
        if gap_type == "vulnerability":
            recommendation = (
                "Review the recorded vulnerability and apply an approved "
                "remediation; validate closure."
            )
        else:
            recommendation = (
                "Review the recorded control and improve its effectiveness "
                "using the organization's approved procedure."
            )

    available_weight = sum(
        weight for name, weight in _PRIORITY_WEIGHTS.items() if name in factors
    )
    scored_reasons = [
        f"{name.replace('_', ' ')} ({weight / available_weight:.0%} normalized weight): "
        f"{_round(factors[name])}/100."
        for name, weight in _PRIORITY_WEIGHTS.items()
        if name in factors
    ]
    if priority is None:
        explanation = (
            f"This {gap_type} gap is supported by the supplied evidence, but no "
            "numeric ranking factors are available."
        )
    else:
        explanation = (
            f"Priority is {_round(priority)}/100, calculated from available "
            "risk and gap evidence with unavailable factors omitted and weights "
            f"renormalized. Contributing factors: {'; '.join(scored_reasons)}"
        )
    return {
        "asset_id": asset["asset_id"],
        "asset_name": asset.get("asset_name"),
        "gap_type": gap_type,
        "gap_id": gap_id,
        "title": title,
        "priority_score": _round(priority),
        "category": _category(priority),
        "evidence": dict(record),
        "explanation": explanation,
        "recommendation": recommendation,
    }


def prioritize_security_gaps(
    risk_assessments: dict[str, Any],
) -> list[dict[str, Any]]:
    """Rank explicitly evidenced vulnerability and weak-control gaps.

    The input is the output mapping returned by ``calculate_risk``. Missing
    assessment factors are omitted from the priority weighted mean.
    """
    if not isinstance(risk_assessments, dict):
        return []
    assets = risk_assessments.get("assets")
    if not isinstance(assets, list):
        return []

    candidates: dict[tuple[str, str], dict[str, Any]] = {}
    for asset in assets:
        if not isinstance(asset, dict):
            continue
        identifier = _asset_id(asset.get("asset_id"))
        if identifier is None:
            continue
        evidence = asset.get("evidence")
        if not isinstance(evidence, dict):
            continue
        vulnerabilities = _record_list(evidence.get("vulnerabilities"))
        controls = _record_list(evidence.get("controls"))

        for vulnerability in vulnerabilities:
            if not _belongs_to_asset(vulnerability, identifier) or not (
                _has_vulnerability_evidence(vulnerability)
            ):
                continue
            severity = _score_from_record(
                vulnerability,
                ("severity", "cvss_score", "severity_score"),
                "severity",
            )
            stable_id = _first_nonempty(vulnerability, ("vulnerability_id", "id"))
            gap = _make_gap(
                asset,
                "vulnerability",
                vulnerability,
                stable_id,
                severity,
                _applicable_control_weakness(controls, identifier),
            )
            key = (
                identifier,
                f"id:{stable_id}" if stable_id else f"record:{_canonical(vulnerability)}",
            )
            existing = candidates.get(key)
            if existing is None or (
                gap["priority_score"] is not None
                and (
                    existing["priority_score"] is None
                    or gap["priority_score"] > existing["priority_score"]
                )
            ):
                candidates[key] = gap

        for control in controls:
            if not _belongs_to_asset(control, identifier):
                continue
            effectiveness = _score_from_record(
                control, ("effectiveness", "effectiveness_score"), "percentage"
            )
            if effectiveness is None or effectiveness >= 100:
                continue
            stable_id = _first_nonempty(control, ("control_id", "id"))
            gap = _make_gap(
                asset,
                "control",
                control,
                stable_id,
                None,
                100.0 - effectiveness,
            )
            key = (
                identifier,
                f"id:{stable_id}" if stable_id else f"record:{_canonical(control)}",
            )
            existing = candidates.get(key)
            if existing is None or (
                gap["priority_score"] is not None
                and (
                    existing["priority_score"] is None
                    or gap["priority_score"] > existing["priority_score"]
                )
            ):
                candidates[key] = gap

    return sorted(
        candidates.values(),
        key=lambda gap: (
            gap["priority_score"] is None,
            -(gap["priority_score"] or 0.0),
            gap["asset_id"],
            gap["gap_type"],
            gap["gap_id"] or gap["title"] or _canonical(gap["evidence"]),
        ),
    )
