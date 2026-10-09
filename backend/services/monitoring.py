"""Deterministic security-event simulation using the provisional Member 3 schema."""

from copy import deepcopy
from datetime import datetime, timedelta, timezone
from typing import Any


DOMAINS = ("assets", "vulnerabilities", "threats", "incidents", "controls")
_REQUIRED_STRING_FIELDS = {
    "assets": ("name", "type", "environment", "criticality", "owner"),
    "vulnerabilities": (
        "asset_id",
        "title",
        "description",
        "severity",
        "status",
        "discovered_at",
    ),
    "threats": ("name", "category", "likelihood", "relevance", "description"),
    "incidents": (
        "asset_id",
        "title",
        "description",
        "severity",
        "status",
        "detected_at",
    ),
    "controls": ("asset_id", "name", "type", "status"),
}
SUPPORTED_EVENT_TYPES = {
    "critical_vulnerability_discovered",
    "security_incident_detected",
    "control_degraded",
    "vulnerability_remediated",
    "control_restored",
}
_SIMULATION_EPOCH = datetime(2026, 2, 1, tzinfo=timezone.utc)


def _validate_state(state: Any) -> None:
    if not isinstance(state, dict):
        raise TypeError("state must be a dictionary")
    for domain in DOMAINS:
        if not isinstance(state.get(domain), list):
            raise ValueError(f"state[{domain!r}] must be a list")

    ids_by_domain: dict[str, set[str]] = {}
    for domain in DOMAINS:
        seen: set[str] = set()
        for index, record in enumerate(state[domain]):
            if not isinstance(record, dict):
                raise TypeError(f"{domain}[{index}] must be a dictionary")
            record_id = record.get("id")
            if not isinstance(record_id, str) or not record_id.strip():
                raise ValueError(f"{domain}[{index}].id must be a non-empty string")
            if record_id in seen:
                raise ValueError(f"{domain} contains duplicate id {record_id!r}")
            seen.add(record_id)
            for field in _REQUIRED_STRING_FIELDS[domain]:
                value = record.get(field)
                if not isinstance(value, str) or not value.strip():
                    raise ValueError(
                        f"{domain}[{index}].{field} must be a non-empty string"
                    )
        ids_by_domain[domain] = seen

    asset_ids = ids_by_domain["assets"]
    for index, asset in enumerate(state["assets"]):
        if asset["criticality"] not in ("critical", "high", "medium", "low"):
            raise ValueError(
                f"assets[{index}].criticality must be critical, high, medium, or low"
            )
    for domain in ("vulnerabilities", "incidents", "controls"):
        for index, record in enumerate(state[domain]):
            asset_id = record.get("asset_id")
            if not isinstance(asset_id, str) or asset_id not in asset_ids:
                raise ValueError(
                    f"{domain}[{index}].asset_id must reference an existing asset"
                )
    for index, vulnerability in enumerate(state["vulnerabilities"]):
        if vulnerability["severity"] not in ("critical", "high", "medium", "low"):
            raise ValueError(
                f"vulnerabilities[{index}].severity must be critical, high, medium, or low"
            )
        if vulnerability["status"] not in ("open", "remediated"):
            raise ValueError(
                f"vulnerabilities[{index}].status must be open or remediated"
            )
    for index, threat in enumerate(state["threats"]):
        if threat["likelihood"] not in ("low", "medium", "high"):
            raise ValueError(f"threats[{index}].likelihood must be low, medium, or high")
        if threat["relevance"] not in ("low", "medium", "high"):
            raise ValueError(f"threats[{index}].relevance must be low, medium, or high")
    for index, incident in enumerate(state["incidents"]):
        if incident["severity"] not in ("critical", "high", "medium", "low"):
            raise ValueError(
                f"incidents[{index}].severity must be critical, high, medium, or low"
            )
        if incident["status"] not in ("active", "resolved"):
            raise ValueError(f"incidents[{index}].status must be active or resolved")
    for index, control in enumerate(state["controls"]):
        if control["status"] not in (
            "active",
            "operational",
            "degraded",
            "maintenance",
            "unavailable",
        ):
            raise ValueError(f"controls[{index}].status is not a supported status")
        if "pre_degradation_status" in control and control[
            "pre_degradation_status"
        ] not in ("active", "operational"):
            raise ValueError(
                f"controls[{index}].pre_degradation_status must be active or operational"
            )
        if "pre_degradation_effectiveness" in control:
            previous = control["pre_degradation_effectiveness"]
            if (
                isinstance(previous, bool)
                or not isinstance(previous, (int, float))
                or not 0 <= previous <= 1
            ):
                raise ValueError(
                    f"controls[{index}].pre_degradation_effectiveness must be from 0 to 1"
                )
    for index, control in enumerate(state["controls"]):
        effectiveness = control.get("effectiveness")
        if (
            isinstance(effectiveness, bool)
            or not isinstance(effectiveness, (int, float))
            or not 0 <= effectiveness <= 1
        ):
            raise ValueError(
                f"controls[{index}].effectiveness must be a number from 0 to 1"
            )

    history = state.get("event_history", [])
    if not isinstance(history, list):
        raise ValueError("state['event_history'] must be a list")
    history_ids: set[str] = set()
    for index, record in enumerate(history):
        if not isinstance(record, dict):
            raise TypeError(f"event_history[{index}] must be a dictionary")
        event_id = record.get("event_id")
        if not isinstance(event_id, str) or not event_id.strip():
            raise ValueError(
                f"event_history[{index}].event_id must be a non-empty string"
            )
        if event_id in history_ids:
            raise ValueError(f"event_history contains duplicate event id {event_id!r}")
        history_ids.add(event_id)
        for field in ("timestamp", "event_type", "description"):
            if not isinstance(record.get(field), str) or not record[field].strip():
                raise ValueError(
                    f"event_history[{index}].{field} must be a non-empty string"
                )
        if not isinstance(record.get("affected_entities"), list) or not isinstance(
            record.get("state_changes"), list
        ):
            raise ValueError(
                f"event_history[{index}] must contain affected_entities and state_changes lists"
            )
        for entity in record["affected_entities"]:
            if not isinstance(entity, dict) or any(
                not isinstance(entity.get(field), str) or not entity[field].strip()
                for field in ("entity_type", "entity_id")
            ):
                raise ValueError(
                    f"event_history[{index}].affected_entities entries must identify entities"
                )
        for change in record["state_changes"]:
            if not isinstance(change, dict) or any(
                not isinstance(change.get(field), str) or not change[field].strip()
                for field in ("entity_type", "entity_id", "field")
            ):
                raise ValueError(
                    f"event_history[{index}].state_changes entries must identify a field change"
                )

    if "investments" in state:
        investments = state["investments"]
        if not isinstance(investments, list):
            raise ValueError("state['investments'] must be a list")
        investment_ids: set[str] = set()
        for index, investment in enumerate(investments):
            if not isinstance(investment, dict):
                raise TypeError(f"investments[{index}] must be a dictionary")
            investment_id = investment.get("id")
            if not isinstance(investment_id, str) or not investment_id.strip():
                raise ValueError(f"investments[{index}].id must be a non-empty string")
            if investment_id in investment_ids:
                raise ValueError(f"investments contains duplicate id {investment_id!r}")
            investment_ids.add(investment_id)
            if investment.get("asset_id") not in asset_ids:
                raise ValueError(
                    f"investments[{index}].asset_id must reference an existing asset"
                )
            if not isinstance(investment.get("name"), str) or not investment["name"].strip():
                raise ValueError(f"investments[{index}].name must be a non-empty string")
            cost = investment.get("cost")
            risk_reduction = investment.get("risk_reduction")
            if (
                isinstance(cost, bool)
                or not isinstance(cost, (int, float))
                or cost < 0
            ):
                raise ValueError(f"investments[{index}].cost must be non-negative")
            if (
                isinstance(risk_reduction, bool)
                or not isinstance(risk_reduction, (int, float))
                or not 0 <= risk_reduction <= 1
            ):
                raise ValueError(
                    f"investments[{index}].risk_reduction must be from 0 to 1"
                )

    event_type = state.get("event_type")
    if not isinstance(event_type, str):
        raise ValueError("state['event_type'] must be a string")
    if event_type not in SUPPORTED_EVENT_TYPES:
        raise ValueError(f"unsupported event type: {event_type!r}")


def _next_id(
    prefix: str, records: list[dict[str, Any]], id_field: str = "id"
) -> str:
    existing = {record[id_field] for record in records}
    sequence = 1
    while f"{prefix}-{sequence:04d}" in existing:
        sequence += 1
    return f"{prefix}-{sequence:04d}"


def _event_metadata(history: list[dict[str, Any]]) -> tuple[str, str]:
    event_id = _next_id("EVT", history, "event_id")
    timestamp = (_SIMULATION_EPOCH + timedelta(minutes=len(history))).isoformat()
    return event_id, timestamp


def _record_event(
    updated_state: dict[str, Any],
    event_id: str,
    timestamp: str,
    event_type: str,
    description: str,
    affected_entities: list[dict[str, str]],
    state_changes: list[dict[str, Any]],
) -> dict[str, Any]:
    event = {
        "event_id": event_id,
        "timestamp": timestamp,
        "event_type": event_type,
        "description": description,
        "affected_entities": affected_entities,
        "state_changes": state_changes,
    }
    updated_state.setdefault("event_history", []).append(deepcopy(event))
    return event


def simulate_security_event(state: dict[str, Any]) -> dict[str, Any]:
    """Return a simulated event and a deep-copied updated state.

    The event selector is ``state["event_type"]``. The returned state preserves
    that selector so callers can replace it before triggering a subsequent event.
    """
    _validate_state(state)
    updated_state = deepcopy(state)
    event_type = updated_state["event_type"]
    event_id, timestamp = _event_metadata(updated_state.get("event_history", []))
    affected_entities: list[dict[str, str]]
    state_changes: list[dict[str, Any]]

    if event_type == "critical_vulnerability_discovered":
        if not updated_state["assets"]:
            raise ValueError(
                "critical_vulnerability_discovered requires at least one asset"
            )
        asset = min(
            updated_state["assets"],
            key=lambda row: (
                -{"critical": 4, "high": 3, "medium": 2, "low": 1}[
                    row["criticality"]
                ],
                row["id"],
            ),
        )
        vulnerability = {
            "id": _next_id("VUL-SIM", updated_state["vulnerabilities"]),
            "asset_id": asset["id"],
            "title": "Critical remotely exploitable service flaw",
            "description": (
                "A simulated assessment identified a critical remotely "
                "exploitable flaw requiring urgent patching."
            ),
            "severity": "critical",
            "status": "open",
            "discovered_at": timestamp,
        }
        updated_state["vulnerabilities"].append(vulnerability)
        description = f"Critical vulnerability discovered on asset {asset['id']}."
        affected_entities = [
            {"entity_type": "asset", "entity_id": asset["id"]},
            {"entity_type": "vulnerability", "entity_id": vulnerability["id"]},
        ]
        state_changes = [
            {
                "entity_type": "vulnerability",
                "entity_id": vulnerability["id"],
                "field": "record",
                "before": None,
                "after": deepcopy(vulnerability),
            }
        ]
    elif event_type == "security_incident_detected":
        asset = next(
            (
                row
                for row in updated_state["assets"]
                if row["criticality"] in ("critical", "high")
            ),
            updated_state["assets"][0] if updated_state["assets"] else None,
        )
        if asset is None:
            raise ValueError("security_incident_detected requires at least one asset")
        incident = {
            "id": _next_id("INC-SIM", updated_state["incidents"]),
            "asset_id": asset["id"],
            "title": "Simulated suspicious credential activity",
            "description": (
                "Monitoring detected a simulated anomalous sign-in requiring "
                "analyst investigation."
            ),
            "severity": "high",
            "status": "active",
            "detected_at": timestamp,
        }
        updated_state["incidents"].append(incident)
        description = f"Active security incident detected on asset {asset['id']}."
        affected_entities = [
            {"entity_type": "asset", "entity_id": asset["id"]},
            {"entity_type": "incident", "entity_id": incident["id"]},
        ]
        state_changes = [
            {
                "entity_type": "incident",
                "entity_id": incident["id"],
                "field": "record",
                "before": None,
                "after": deepcopy(incident),
            }
        ]
    elif event_type == "control_degraded":
        control = next(
            (
                row
                for row in updated_state["controls"]
                if row["status"] in ("active", "operational")
            ),
            None,
        )
        if control is None:
            raise ValueError("control_degraded requires an active security control")
        before_status = control["status"]
        before_effectiveness = control["effectiveness"]
        after_effectiveness = round(max(0.0, before_effectiveness - 0.25), 2)
        control["status"] = "degraded"
        control["effectiveness"] = after_effectiveness
        control["pre_degradation_status"] = before_status
        control["pre_degradation_effectiveness"] = before_effectiveness
        description = f"Security control {control['id']} degraded."
        affected_entities = [
            {"entity_type": "control", "entity_id": control["id"]},
            {"entity_type": "asset", "entity_id": control["asset_id"]},
        ]
        state_changes = [
            {
                "entity_type": "control",
                "entity_id": control["id"],
                "field": "status",
                "before": before_status,
                "after": "degraded",
            },
            {
                "entity_type": "control",
                "entity_id": control["id"],
                "field": "effectiveness",
                "before": before_effectiveness,
                "after": after_effectiveness,
            },
            {
                "entity_type": "control",
                "entity_id": control["id"],
                "field": "pre_degradation_status",
                "before": None,
                "after": before_status,
            },
            {
                "entity_type": "control",
                "entity_id": control["id"],
                "field": "pre_degradation_effectiveness",
                "before": None,
                "after": before_effectiveness,
            },
        ]
    elif event_type == "vulnerability_remediated":
        vulnerability = next(
            (
                row
                for row in updated_state["vulnerabilities"]
                if row["status"] == "open"
            ),
            None,
        )
        if vulnerability is None:
            raise ValueError("vulnerability_remediated requires an open vulnerability")
        before = vulnerability["status"]
        vulnerability["status"] = "remediated"
        vulnerability["remediated_at"] = timestamp
        description = f"Vulnerability {vulnerability['id']} was remediated."
        affected_entities = [
            {"entity_type": "vulnerability", "entity_id": vulnerability["id"]},
            {"entity_type": "asset", "entity_id": vulnerability["asset_id"]},
        ]
        state_changes = [
            {
                "entity_type": "vulnerability",
                "entity_id": vulnerability["id"],
                "field": "status",
                "before": before,
                "after": "remediated",
            },
            {
                "entity_type": "vulnerability",
                "entity_id": vulnerability["id"],
                "field": "remediated_at",
                "before": None,
                "after": timestamp,
            },
        ]
    else:
        control = next(
            (
                row
                for row in updated_state["controls"]
                if row["status"] == "degraded"
            ),
            None,
        )
        if control is None:
            raise ValueError("control_restored requires a degraded security control")
        before_status = control["status"]
        before_effectiveness = control["effectiveness"]
        saved_status = control.pop("pre_degradation_status", None)
        saved_effectiveness = control.pop("pre_degradation_effectiveness", None)
        restored_status = saved_status or "active"
        restored_effectiveness = (
            saved_effectiveness
            if saved_effectiveness is not None
            else min(1.0, round(before_effectiveness + 0.25, 2))
        )
        control["status"] = restored_status
        control["effectiveness"] = restored_effectiveness
        description = f"Security control {control['id']} was restored."
        affected_entities = [
            {"entity_type": "control", "entity_id": control["id"]},
            {"entity_type": "asset", "entity_id": control["asset_id"]},
        ]
        state_changes = [
            {
                "entity_type": "control",
                "entity_id": control["id"],
                "field": "status",
                "before": before_status,
                "after": restored_status,
            },
            {
                "entity_type": "control",
                "entity_id": control["id"],
                "field": "effectiveness",
                "before": before_effectiveness,
                "after": restored_effectiveness,
            },
        ]
        if saved_status is not None:
            state_changes.append(
                {
                    "entity_type": "control",
                    "entity_id": control["id"],
                    "field": "pre_degradation_status",
                    "before": saved_status,
                    "after": None,
                }
            )
        if saved_effectiveness is not None:
            state_changes.append(
                {
                    "entity_type": "control",
                    "entity_id": control["id"],
                    "field": "pre_degradation_effectiveness",
                    "before": saved_effectiveness,
                    "after": None,
                }
            )

    event = _record_event(
        updated_state,
        event_id,
        timestamp,
        event_type,
        description,
        affected_entities,
        state_changes,
    )
    return {"state": updated_state, "event": event}
