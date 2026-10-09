"""Explainable asset and organization cyber-risk scoring.

Scores are modeled indicators on a 0–100 scale, not calibrated breach
probabilities. See docs/architecture.md for input mappings and assumptions.
"""

import json
import math
from collections.abc import Iterable
from typing import Any


_FACTOR_WEIGHTS = {
    "criticality": 0.25,
    "vulnerability_severity": 0.30,
    "threat_likelihood": 0.20,
    "incident_history": 0.15,
    "exposure": 0.10,
}
_DOMAINS = {
    "vulnerability": "vulnerability_severity",
    "vulnerabilities": "vulnerability_severity",
    "threat": "threat_likelihood",
    "threats": "threat_likelihood",
    "incident": "incident_history",
    "incidents": "incident_history",
    "exposure": "exposure",
}
_CATEGORIES = (
    ("Low", 0.0, 25.0),
    ("Moderate", 25.0, 50.0),
    ("High", 50.0, 75.0),
    ("Critical", 75.0, 100.0),
)
_LABELS = {
    "low": 0.0,
    "moderate": 25.0,
    "high": 50.0,
    "critical": 75.0,
}


def _category(score: float | None) -> str:
    if score is None:
        return "Unknown"
    for name, lower, upper in _CATEGORIES:
        if lower <= score < upper or (name == "Critical" and score <= upper):
            return name
    return "Unknown"


def _normalize_score(value: Any, field: str) -> float | None:
    """Normalize a supported numeric score or category label to 0–100."""
    if isinstance(value, str):
        label = value.strip().casefold()
        if label in _LABELS:
            return _LABELS[label]
        try:
            value = float(label)
        except ValueError:
            return None

    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    number = float(value)
    if not math.isfinite(number) or number < 0:
        return None

    if field in {"severity"}:
        if number <= 10:
            return number * 10
        if number <= 100:
            return number
        return None
    if field == "likelihood":
        if number <= 1:
            return number * 100
        if number <= 100:
            return number
        return None
    if number <= 1:
        return number * 100
    if number <= 100:
        return number
    return None


def _score_from_record(
    record: dict[str, Any], fields: tuple[str, ...], scale: str
) -> float | None:
    for field in fields:
        if field in record and record[field] is not None:
            return _normalize_score(record[field], scale)
    return None


def _asset_id(value: Any) -> str | None:
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        return None
    normalized = str(value).strip()
    return normalized or None


def _stable_value(value: Any) -> Any:
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else str(value)
    if isinstance(value, dict):
        return {
            str(key): _stable_value(item)
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
        }
    if isinstance(value, (list, tuple)):
        return [_stable_value(item) for item in value]
    return f"<{type(value).__name__}>"


def _canonical(record: dict[str, Any]) -> str:
    return json.dumps(
        _stable_value(record),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )


def _records(value: Any, name: str, warnings: set[str]) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        warnings.add(f"{name}: expected a list; records were not processed.")
        return []
    records: list[dict[str, Any]] = []
    for record in value:
        if not isinstance(record, dict):
            warnings.add(f"{name}: a non-object record was excluded.")
            continue
        records.append(record)
    return records


def _deduplicate(
    records: list[dict[str, Any]],
    id_fields: tuple[str, ...],
    score_fields: tuple[str, ...],
    score_scale: str,
    scope_fields: tuple[str, ...] = (),
) -> list[dict[str, Any]]:
    selected: dict[str, tuple[float, str, dict[str, Any]]] = {}
    for record in records:
        stable_id = next(
            (
                str(record[field]).strip()
                for field in id_fields
                if record.get(field) is not None and str(record[field]).strip()
            ),
            None,
        )
        scope = _canonical({field: record.get(field) for field in scope_fields})
        key = (
            f"id:{stable_id}:{scope}"
            if stable_id
            else f"record:{_canonical(record)}"
        )
        score = _score_from_record(record, score_fields, score_scale)
        rank_score = score if score is not None else -1.0
        canonical = _canonical(record)
        existing = selected.get(key)
        if existing is None or (rank_score, canonical) > (existing[0], existing[1]):
            selected[key] = (rank_score, canonical, record)
    return [entry[2] for _, entry in sorted(selected.items())]


def _round(value: float | None) -> float | None:
    return round(min(100.0, max(0.0, value)), 2) if value is not None else None


def _weighted_mean(values: dict[str, float], weights: dict[str, float]) -> float | None:
    applicable = [(weights[factor], score) for factor, score in values.items()]
    denominator = sum(weight for weight, _ in applicable)
    if denominator == 0:
        return None
    return sum(weight * score for weight, score in applicable) / denominator


def _first_nonempty(record: dict[str, Any], fields: tuple[str, ...]) -> str | None:
    for field in fields:
        value = record.get(field)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _normal_domain(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    return _DOMAINS.get(value.strip().casefold())


def calculate_risk(
    assets: list[dict[str, Any]],
    vulnerabilities: list[dict[str, Any]],
    threats: list[dict[str, Any]],
    incidents: list[dict[str, Any]],
    controls: list[dict[str, Any]],
) -> dict[str, Any]:
    """Calculate deterministic inherent and residual risk assessments.

    Inputs follow the schemas and normalization rules in docs/architecture.md.
    Invalid or unassociated evidence is excluded and noted in data-quality
    warnings. Missing factor values are omitted, never assumed to be zero.
    """
    # Compatibility adapter for existing application data that references
    # assets by name instead of asset_id. Work on copies to avoid mutating state.
    assets = [dict(item) if isinstance(item, dict) else item for item in assets] if isinstance(assets, list) else assets
    vulnerabilities = [dict(item) if isinstance(item, dict) else item for item in vulnerabilities] if isinstance(vulnerabilities, list) else vulnerabilities
    threats = [dict(item) if isinstance(item, dict) else item for item in threats] if isinstance(threats, list) else threats
    incidents = [dict(item) if isinstance(item, dict) else item for item in incidents] if isinstance(incidents, list) else incidents
    controls = [dict(item) if isinstance(item, dict) else item for item in controls] if isinstance(controls, list) else controls

    asset_name_to_id: dict[str, str] = {}

    if isinstance(assets, list):
        for asset in assets:
            if not isinstance(asset, dict):
                continue
            name = _first_nonempty(asset, ("name", "asset_name"))
            identifier = _asset_id(asset.get("asset_id"))
            if identifier is None and name is not None:
                # Stable synthetic identifier for legacy name-based records.
                identifier = "legacy:" + name.strip().casefold()
                asset["asset_id"] = identifier
            if name is not None and identifier is not None:
                asset_name_to_id.setdefault(name.strip().casefold(), identifier)

    for collection in (vulnerabilities, threats, incidents, controls):
        if not isinstance(collection, list):
            continue
        for record in collection:
            if not isinstance(record, dict):
                continue
            if _asset_id(record.get("asset_id")) is not None:
                continue
            name = _first_nonempty(record, ("asset", "asset_name"))
            if name is not None:
                identifier = asset_name_to_id.get(name.strip().casefold())
                if identifier is not None:
                    record["asset_id"] = identifier

    warnings: set[str] = set()
    asset_records = _records(assets, "assets", warnings)
    asset_facts: dict[str, dict[str, Any]] = {}
    for record in asset_records:
        identifier = _asset_id(record.get("asset_id"))
        if identifier is None:
            warnings.add("assets: a record without a valid asset_id was excluded.")
            continue
        facts = asset_facts.setdefault(
            identifier, {"criticality_values": [], "exposure_values": [], "names": []}
        )
        criticality = _score_from_record(
            record, ("criticality", "criticality_score"), "percentage"
        )
        exposure = _score_from_record(record, ("exposure", "exposure_score"), "percentage")
        if criticality is not None:
            facts["criticality_values"].append(criticality)
        if exposure is not None:
            facts["exposure_values"].append(exposure)
        name = _first_nonempty(record, ("name", "asset_name"))
        if name is not None:
            facts["names"].append(name)
        for field, aliases, scale in (
            ("criticality", ("criticality", "criticality_score"), "percentage"),
            ("exposure", ("exposure", "exposure_score"), "percentage"),
        ):
            if any(key in record and record[key] is not None for key in aliases):
                if _score_from_record(record, aliases, scale) is None:
                    warnings.add(f"assets: invalid {field} value for asset {identifier}.")

    for identifier, facts in asset_facts.items():
        facts["criticality"] = max(facts.pop("criticality_values"), default=None)
        facts["exposure"] = max(facts.pop("exposure_values"), default=None)
        facts["name"] = min(facts.pop("names"), default=None)

    evidence: dict[str, dict[str, list[dict[str, Any]]]] = {
        identifier: {
            "vulnerabilities": [],
            "threats": [],
            "incidents": [],
            "controls": [],
        }
        for identifier in asset_facts
    }
    all_records: Iterable[tuple[str, Any, tuple[str, ...], tuple[str, ...], str]] = (
        (
            "vulnerabilities",
            vulnerabilities,
            ("vulnerability_id", "id"),
            ("severity", "cvss_score", "severity_score"),
            "severity",
        ),
        ("threats", threats, ("threat_id", "id"), ("likelihood", "likelihood_score"), "likelihood"),
        ("incidents", incidents, ("incident_id", "id"), ("severity", "severity_score"), "severity"),
    )
    for domain, raw_records, id_fields, score_fields, scale in all_records:
        normalized_records: dict[str, list[dict[str, Any]]] = {
            identifier: [] for identifier in asset_facts
        }
        for record in _records(raw_records, domain, warnings):
            identifier = _asset_id(record.get("asset_id"))
            if identifier is None:
                warnings.add(f"{domain}: a record without a valid asset_id was excluded.")
                continue
            if identifier not in asset_facts:
                warnings.add(f"{domain}: a record referenced unknown asset {identifier}.")
                continue
            normalized_records[identifier].append(record)
            if any(key in record and record[key] is not None for key in score_fields):
                if _score_from_record(record, score_fields, scale) is None:
                    warnings.add(f"{domain}: invalid score for asset {identifier}.")
        for identifier, records in normalized_records.items():
            evidence[identifier][domain] = _deduplicate(
                records, id_fields, score_fields, scale
            )

    for record in _records(controls, "controls", warnings):
        raw_ids = record.get("asset_ids")
        if raw_ids is None:
            raw_ids = [record.get("asset_id")]
        elif not isinstance(raw_ids, list):
            warnings.add("controls: asset_ids must be a list; the control was excluded.")
            continue
        identifiers = sorted(
            {identifier for value in raw_ids if (identifier := _asset_id(value)) is not None}
        )
        if not identifiers:
            warnings.add("controls: a record without a valid asset association was excluded.")
            continue
        effectiveness = _score_from_record(
            record, ("effectiveness", "effectiveness_score"), "percentage"
        )
        if effectiveness is None:
            if any(
                key in record and record[key] is not None
                for key in ("effectiveness", "effectiveness_score")
            ):
                warnings.add("controls: invalid effectiveness; control cannot mitigate risk.")
        raw_domains = record.get("domains", record.get("domain"))
        if isinstance(raw_domains, str):
            raw_domains = [raw_domains]
        if not isinstance(raw_domains, list):
            raw_domains = []
        domains = sorted({domain for value in raw_domains if (domain := _normal_domain(value))})
        if not domains:
            warnings.add("controls: a record without a supported domain cannot mitigate risk.")
        for identifier in identifiers:
            if identifier not in asset_facts:
                warnings.add(f"controls: a record referenced unknown asset {identifier}.")
                continue
            evidence[identifier]["controls"].append(record)

    for asset_evidence in evidence.values():
        asset_evidence["controls"] = _deduplicate(
            asset_evidence["controls"],
            ("control_id", "id"),
            ("effectiveness", "effectiveness_score"),
            "percentage",
            ("domain", "domains"),
        )

    assessments: list[dict[str, Any]] = []
    component_totals = {factor: 0.0 for factor in _FACTOR_WEIGHTS}
    for identifier, facts in sorted(asset_facts.items()):
        asset_evidence = evidence[identifier]
        vulnerabilities_for_asset = asset_evidence["vulnerabilities"]
        threats_for_asset = asset_evidence["threats"]
        incidents_for_asset = asset_evidence["incidents"]
        factors: dict[str, float | None] = {
            "criticality": facts["criticality"],
            "vulnerability_severity": max(
                (
                    score
                    for record in vulnerabilities_for_asset
                    if (score := _score_from_record(
                        record, ("severity", "cvss_score", "severity_score"), "severity"
                    ))
                    is not None
                ),
                default=None,
            ),
            "threat_likelihood": max(
                (
                    score
                    for record in threats_for_asset
                    if (score := _score_from_record(
                        record, ("likelihood", "likelihood_score"), "likelihood"
                    ))
                    is not None
                ),
                default=None,
            ),
            "incident_history": None,
            "exposure": facts["exposure"],
        }
        incident_scores = [
            score
            for record in incidents_for_asset
            if (score := _score_from_record(
                record, ("severity", "severity_score"), "severity"
            ))
            is not None
        ]
        if incidents_for_asset:
            recurrence = min(100.0, 10.0 * len(incidents_for_asset))
            if incident_scores:
                factors["incident_history"] = (
                    0.70 * (sum(incident_scores) / len(incident_scores))
                    + 0.30 * recurrence
                )
            else:
                factors["incident_history"] = recurrence

        control_effectiveness: dict[str, float] = {}
        for record in asset_evidence["controls"]:
            effectiveness = _score_from_record(
                record, ("effectiveness", "effectiveness_score"), "percentage"
            )
            raw_domains = record.get("domains", record.get("domain"))
            if isinstance(raw_domains, str):
                raw_domains = [raw_domains]
            if not isinstance(raw_domains, list):
                continue
            for raw_domain in raw_domains:
                factor = _normal_domain(raw_domain)
                if factor is None or effectiveness is None:
                    continue
                control_effectiveness[factor] = max(
                    effectiveness, control_effectiveness.get(factor, 0.0)
                )

        available = {
            factor: score for factor, score in factors.items() if score is not None
        }
        inherent = _weighted_mean(available, _FACTOR_WEIGHTS)
        residual_contributions = {
            factor: _FACTOR_WEIGHTS[factor]
            * score
            * (1 - control_effectiveness.get(factor, 0.0) / 100)
            for factor, score in available.items()
        }
        weight_total = sum(_FACTOR_WEIGHTS[factor] for factor in available)
        residual = (
            sum(residual_contributions.values()) / weight_total if weight_total else None
        )
        for factor, score in available.items():
            component_totals[factor] += _FACTOR_WEIGHTS[factor] * score

        ranked_factors = sorted(
            available,
            key=lambda factor: (
                -(residual_contributions[factor] / weight_total)
                if weight_total
                else 0.0,
                factor,
            ),
        )
        reasons = [
            f"{factor.replace('_', ' ').capitalize()} contributes "
            f"{_round(residual_contributions[factor] / weight_total)} points to "
            "residual risk."
            for factor in ranked_factors[:3]
        ] if weight_total else ["No risk factors could be scored from the supplied data."]
        if control_effectiveness:
            reasons.append(
                "Residual risk reflects the strongest explicitly associated control "
                "for each supported domain; overlapping controls were not stacked."
            )
        assessments.append(
            {
                "asset_id": identifier,
                "asset_name": facts["name"],
                "asset": facts["name"],
                "inherent_risk_score": _round(inherent),
                "residual_risk_score": _round(residual),
                "score": _round(residual),
                "category": _category(residual),
                "risk_level": _category(residual),
                "factors": {
                    factor: _round(score) for factor, score in factors.items()
                }
                | {
                    "control_effectiveness": {
                        factor: _round(score)
                        for factor, score in sorted(control_effectiveness.items())
                    }
                },
                "risk_drivers": ranked_factors[:3],
                "reasons": reasons,
                "evidence": {
                    domain: sorted(records, key=_canonical)
                    for domain, records in asset_evidence.items()
                },
            }
        )

    scored = [item for item in assessments if item["residual_risk_score"] is not None]
    organization_inherent = (
        sum(item["inherent_risk_score"] for item in scored) / len(scored)
        if scored
        else None
    )
    organization_residual = (
        sum(item["residual_risk_score"] for item in scored) / len(scored)
        if scored
        else None
    )
    top_drivers = sorted(
        (factor for factor in _FACTOR_WEIGHTS if component_totals[factor] > 0),
        key=lambda factor: (-component_totals[factor], factor),
    )[:3]
    organization = {
        "asset_count": len(asset_facts),
        "scored_asset_count": len(scored),
        "inherent_risk_score": _round(organization_inherent),
        "residual_risk_score": _round(organization_residual),
        "category": _category(organization_residual),
        "top_risk_drivers": top_drivers,
    }

    # Keep the newer structured response and expose the legacy contract too.
    return {
        "organization": organization,
        "assets": assessments,
        "data_quality": {"warnings": sorted(warnings)},
        "overall_risk_score": _round(organization_residual),
        "risk_level": _category(organization_residual),
        "risk_factors": [
            {
                "factor": factor.replace("_", " ").title(),
                "score": _round(component_totals[factor]),
            }
            for factor in sorted(
                _FACTOR_WEIGHTS,
                key=lambda name: (-component_totals[name], name),
            )
            if component_totals[factor] > 0
        ],
        "asset_risks": assessments,
    }
