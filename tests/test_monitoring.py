from copy import deepcopy

import pytest

from backend.data.generator import generate_security_data
from backend.services.monitoring import simulate_security_event


def _simulate(event_type: str, state: dict | None = None) -> dict:
    event_state = generate_security_data() if state is None else deepcopy(state)
    event_state["event_type"] = event_type
    return simulate_security_event(event_state)


@pytest.mark.parametrize(
    "event_type",
    [
        "critical_vulnerability_discovered",
        "security_incident_detected",
        "control_degraded",
        "vulnerability_remediated",
        "control_restored",
    ],
)
def test_events_return_structured_deterministic_history(event_type: str) -> None:
    starting_state = generate_security_data()
    if event_type == "control_restored":
        starting_state = _simulate("control_degraded")["state"]

    first = _simulate(event_type, starting_state)
    second = _simulate(event_type, starting_state)

    assert first == second
    assert set(first) == {"state", "event"}
    updated_state = first["state"]
    asset_ids = {asset["id"] for asset in updated_state["assets"]}
    for domain in ("assets", "vulnerabilities", "threats", "incidents", "controls"):
        ids = [record["id"] for record in updated_state[domain]]
        assert len(ids) == len(set(ids))
    for domain in ("vulnerabilities", "incidents", "controls"):
        assert all(
            record["asset_id"] in asset_ids for record in updated_state[domain]
        )
    expected_sequence = len(starting_state["event_history"]) + 1
    assert first["event"]["event_id"] == f"EVT-{expected_sequence:04d}"
    assert first["event"]["event_type"] == event_type
    assert first["event"]["timestamp"].endswith("+00:00")
    assert first["event"]["description"]
    assert first["event"]["affected_entities"]
    assert first["event"]["state_changes"]
    assert first["state"]["event_history"] == [
        *starting_state["event_history"],
        first["event"],
    ]


def test_critical_vulnerability_is_added_to_existing_high_criticality_asset() -> None:
    result = _simulate("critical_vulnerability_discovered")
    vulnerability = result["state"]["vulnerabilities"][-1]

    assert vulnerability["severity"] == "critical"
    assert vulnerability["status"] == "open"
    assert vulnerability["asset_id"] in {
        asset["id"] for asset in result["state"]["assets"]
    }
    assert vulnerability["id"] not in {
        item["id"] for item in generate_security_data()["vulnerabilities"]
    }


def test_new_incident_is_active_and_referenced_by_history() -> None:
    result = _simulate("security_incident_detected")
    incident = result["state"]["incidents"][-1]

    assert incident["status"] == "active"
    assert incident["severity"] == "high"
    assert incident["asset_id"] in {
        asset["id"] for asset in result["state"]["assets"]
    }
    assert incident["id"] == result["event"]["affected_entities"][-1]["entity_id"]


def test_control_degradation_and_restoration_reconcile_effectiveness() -> None:
    original = generate_security_data()
    degraded = _simulate("control_degraded", original)
    original_control = original["controls"][0]
    degraded_control = next(
        row
        for row in degraded["state"]["controls"]
        if row["id"] == original_control["id"]
    )

    assert degraded_control["status"] == "degraded"
    assert degraded_control["effectiveness"] < original_control["effectiveness"]
    assert original_control["status"] == "active"
    assert original_control["effectiveness"] == 0.90

    restored_input = deepcopy(degraded["state"])
    restored_input["event_type"] = "control_restored"
    restored = simulate_security_event(restored_input)
    restored_control = next(
        row
        for row in restored["state"]["controls"]
        if row["id"] == original_control["id"]
    )
    assert restored_control["status"] == "active"
    assert restored_control["effectiveness"] == original_control["effectiveness"]
    assert "pre_degradation_status" not in restored_control
    assert "pre_degradation_effectiveness" not in restored_control


def test_control_restoration_preserves_operational_status() -> None:
    state = generate_security_data()
    state["controls"][0]["status"] = "operational"
    degraded = _simulate("control_degraded", state)
    degraded["state"]["event_type"] = "control_restored"

    restored = simulate_security_event(degraded["state"])

    assert restored["state"]["controls"][0]["status"] == "operational"
    assert restored["state"]["controls"][0]["effectiveness"] == 0.90
    assert any(
        change["field"] == "pre_degradation_status"
        for change in degraded["event"]["state_changes"]
    )
    assert any(
        change["field"] == "pre_degradation_effectiveness"
        for change in restored["event"]["state_changes"]
    )


def test_vulnerability_remediation_changes_status_without_mutating_input() -> None:
    original = generate_security_data()
    before = deepcopy(original)
    result = _simulate("vulnerability_remediated", original)
    changed = next(
        row
        for row in result["state"]["vulnerabilities"]
        if row["id"] == "VUL-001"
    )

    assert changed["status"] == "remediated"
    assert changed["remediated_at"] == result["event"]["timestamp"]
    assert original == before


def test_input_is_not_mutated_and_result_is_deeply_independent() -> None:
    original = generate_security_data()
    original["event_type"] = "critical_vulnerability_discovered"
    before = deepcopy(original)

    result = simulate_security_event(original)
    result["state"]["assets"][0]["name"] = "changed"

    assert original == before
    assert original["assets"][0]["name"] != "changed"


def test_consecutive_events_preserve_and_extend_timeline() -> None:
    first = _simulate("critical_vulnerability_discovered")
    next_input = first["state"]
    next_input["event_type"] = "security_incident_detected"
    second = simulate_security_event(next_input)

    assert len(second["state"]["event_history"]) == 2
    assert second["state"]["event_history"][0] == first["event"]
    assert second["state"]["event_history"][1] == second["event"]
    assert second["event"]["event_id"] == "EVT-0002"
    assert second["event"]["timestamp"] > first["event"]["timestamp"]


@pytest.mark.parametrize(
    ("state", "error", "message"),
    [
        (None, TypeError, "state must be a dictionary"),
        ({}, ValueError, r"state.*assets.*must be a list"),
        (
            {**generate_security_data(), "event_type": "not_supported"},
            ValueError,
            "unsupported event type",
        ),
    ],
)
def test_invalid_states_are_rejected(
    state: object, error: type[Exception], message: str
) -> None:
    with pytest.raises(error, match=message):
        simulate_security_event(state)  # type: ignore[arg-type]


def test_invalid_relationships_duplicate_ids_and_effectiveness_are_rejected() -> None:
    invalid_reference = generate_security_data()
    invalid_reference["vulnerabilities"][0]["asset_id"] = "missing"
    invalid_reference["event_type"] = "control_degraded"
    with pytest.raises(ValueError, match="existing asset"):
        simulate_security_event(invalid_reference)

    duplicate = generate_security_data()
    duplicate["assets"].append(deepcopy(duplicate["assets"][0]))
    duplicate["event_type"] = "control_degraded"
    with pytest.raises(ValueError, match="duplicate id"):
        simulate_security_event(duplicate)

    invalid_effectiveness = generate_security_data()
    invalid_effectiveness["controls"][0]["effectiveness"] = 2
    invalid_effectiveness["event_type"] = "control_degraded"
    with pytest.raises(ValueError, match="from 0 to 1"):
        simulate_security_event(invalid_effectiveness)


@pytest.mark.parametrize(
    ("event_type", "domain", "unavailable_status", "message"),
    [
        ("control_degraded", "controls", "maintenance", "active security control"),
        (
            "vulnerability_remediated",
            "vulnerabilities",
            "remediated",
            "open vulnerability",
        ),
        ("control_restored", "controls", "maintenance", "degraded security control"),
    ],
)
def test_event_without_eligible_record_fails_explicitly(
    event_type: str, domain: str, unavailable_status: str, message: str
) -> None:
    state = generate_security_data()
    for record in state[domain]:
        record["status"] = unavailable_status
    state["event_type"] = event_type

    with pytest.raises(ValueError, match=message):
        simulate_security_event(state)
