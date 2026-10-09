from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app import (
    ASSET_COLUMNS,
    CONTROL_COLUMNS,
    INCIDENT_COLUMNS,
    THREAT_COLUMNS,
    VULNERABILITY_COLUMNS,
    _domain_table,
    _validate_asset_references,
)
from backend.core.gap_prioritizer import prioritize_security_gaps
from backend.core.risk_engine import calculate_risk
from backend.data.generator import generate_security_data
from backend.main import app
from backend.services.analyst import answer_question
from backend.services.investment_optimizer import optimize_investments
from backend.services.monitoring import apply_remediation, simulate_security_event


client = TestClient(app)


def test_backend_health_check() -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


def test_initial_security_state_generation() -> None:
    state = generate_security_data()
    assert state["synthetic"] is True
    assert set(state).issuperset({"assets", "vulnerabilities", "threats", "incidents", "controls", "investments"})
    assert len(state["assets"]) >= 3
    assert len(state["vulnerabilities"]) >= 3
    assert len(state["controls"]) >= 3


def test_risk_assessment_response_schema() -> None:
    state = generate_security_data()
    assessment = calculate_risk(
        state["assets"],
        state["vulnerabilities"],
        state["threats"],
        state["incidents"],
        state["controls"],
    )
    assert assessment["overall_risk_score"] >= 0
    assert assessment["overall_risk_score"] <= 100
    assert assessment["risk_level"] in {"Low", "Moderate", "High", "Critical"}
    assert "risk_factors" in assessment
    assert "asset_risks" in assessment


def test_all_five_security_domains_present() -> None:
    state = generate_security_data()
    assert set(state) >= {"assets", "vulnerabilities", "threats", "incidents", "controls"}
    assert all(state["assets"])
    assert all(state["vulnerabilities"])
    assert all(state["threats"])
    assert all(state["incidents"])
    assert all(state["controls"])


def test_domain_table_columns_are_in_required_order() -> None:
    state = generate_security_data()
    assert list(_domain_table(state, "assets", ASSET_COLUMNS).columns) == ASSET_COLUMNS
    assert list(_domain_table(state, "vulnerabilities", VULNERABILITY_COLUMNS).columns) == VULNERABILITY_COLUMNS
    assert list(_domain_table(state, "threats", THREAT_COLUMNS).columns) == THREAT_COLUMNS
    assert list(_domain_table(state, "incidents", INCIDENT_COLUMNS).columns) == INCIDENT_COLUMNS
    assert list(_domain_table(state, "controls", CONTROL_COLUMNS).columns) == CONTROL_COLUMNS


def test_all_domain_references_point_to_valid_assets() -> None:
    state = generate_security_data()
    assert _validate_asset_references(state) is True
    for domain_name in ("vulnerabilities", "threats", "incidents", "controls"):
        table = _domain_table(state, domain_name, {
            "vulnerabilities": VULNERABILITY_COLUMNS,
            "threats": THREAT_COLUMNS,
            "incidents": INCIDENT_COLUMNS,
            "controls": CONTROL_COLUMNS,
        }[domain_name])
        assert not table.empty
        assert set(table.columns).issubset({"id", "asset", "title", "name", "severity", "likelihood", "impact", "status", "effectiveness"})


def test_gap_prioritization() -> None:
    state = generate_security_data()
    assessment = calculate_risk(
        state["assets"],
        state["vulnerabilities"],
        state["threats"],
        state["incidents"],
        state["controls"],
    )
    gaps = prioritize_security_gaps(assessment)
    assert isinstance(gaps, list)
    assert len(gaps) >= 1
    assert "name" in gaps[0]
    assert "severity" in gaps[0]


def test_investment_optimization_budget_constraint() -> None:
    state = generate_security_data()
    assessment = calculate_risk(
        state["assets"],
        state["vulnerabilities"],
        state["threats"],
        state["incidents"],
        state["controls"],
    )
    optimization = optimize_investments(assessment, state["investments"], 120000)
    assert optimization["total_cost"] <= 120000
    assert optimization["remaining_budget"] >= 0
    assert optimization["selected_investments"]


def test_optimizer_respects_budget_without_mutating_assets() -> None:
    state = generate_security_data()
    assets_before = [dict(asset) for asset in state["assets"]]
    assessment = calculate_risk(
        state["assets"],
        state["vulnerabilities"],
        state["threats"],
        state["incidents"],
        state["controls"],
    )

    low_budget = optimize_investments(assessment, state["investments"], 25000)
    medium_budget = optimize_investments(assessment, state["investments"], 120000)
    high_budget = optimize_investments(assessment, state["investments"], 200000)

    assert low_budget["total_cost"] <= 25000
    assert medium_budget["total_cost"] <= 120000
    assert high_budget["total_cost"] <= 200000
    assert low_budget["selected_investments"] != medium_budget["selected_investments"]
    assert medium_budget["selected_investments"] != high_budget["selected_investments"]
    assert state["assets"] == assets_before
    assert all(asset["criticality"] == assets_before[idx]["criticality"] for idx, asset in enumerate(state["assets"]))
    assert all(asset["value"] == assets_before[idx]["value"] for idx, asset in enumerate(state["assets"]))


def test_invalid_budget_handling() -> None:
    state = generate_security_data()
    assessment = calculate_risk(
        state["assets"],
        state["vulnerabilities"],
        state["threats"],
        state["incidents"],
        state["controls"],
    )
    with pytest.raises(ValueError):
        optimize_investments(assessment, state["investments"], -1)


def test_security_event_simulation_updates_state() -> None:
    state = generate_security_data()
    initial_incident_count = len(state["incidents"])
    updated = simulate_security_event(state, "critical_vulnerability")
    assert len(updated["state"]["incidents"]) >= initial_incident_count
    assert updated["risk_assessment"]["overall_risk_score"] >= 0


def test_risk_reassessment_after_event() -> None:
    state = generate_security_data()
    before = calculate_risk(
        state["assets"],
        state["vulnerabilities"],
        state["threats"],
        state["incidents"],
        state["controls"],
    )
    updated = simulate_security_event(state, "critical_vulnerability")
    after = updated["risk_assessment"]
    assert after["overall_risk_score"] >= before["overall_risk_score"] * 0.9


def test_remediation_changes_state_and_residual_risk() -> None:
    state = generate_security_data()
    assessment = calculate_risk(
        state["assets"],
        state["vulnerabilities"],
        state["threats"],
        state["incidents"],
        state["controls"],
    )
    result = apply_remediation(state, "patch-vpn")
    assert result["residual_risk"]["overall_risk_score"] <= assessment["overall_risk_score"]
    assert result["state"]["controls"]


def test_ai_analyst_fallback_without_api_key() -> None:
    state = generate_security_data()
    assessment = calculate_risk(
        state["assets"],
        state["vulnerabilities"],
        state["threats"],
        state["incidents"],
        state["controls"],
    )
    response = answer_question(
        "Why is the current risk score high?",
        state=state,
        risk_assessment=assessment,
        gaps=prioritize_security_gaps(assessment),
    )
    assert response["grounded"] is True
    assert "risk" in response["answer"].lower()


def test_invalid_api_requests_are_handled() -> None:
    response = client.post("/api/assess", json={"not": "a valid request"})
    assert response.status_code in {200, 422, 400}


@pytest.mark.parametrize(
    "endpoint,payload",
    [
        ("/api/state", None),
        ("/api/gaps/prioritize", {"risk_assessment": {"overall_risk_score": 50}}),
        ("/api/investments/optimize", {"budget": 50000, "investments": [{"name": "Patch", "cost": 1000, "risk_reduction": 10}]}),
        ("/api/events/simulate", {"event_type": "critical_vulnerability"}),
    ],
)
def test_api_endpoints_return_json(endpoint: str, payload: dict | None) -> None:
    response = client.get(endpoint) if payload is None else client.post(endpoint, json=payload)
    assert response.status_code in {200, 400, 422}
    assert isinstance(response.json(), dict)


def test_full_baseline_event_and_remediation_flow() -> None:
    state = generate_security_data()
    baseline = calculate_risk(
        state["assets"],
        state["vulnerabilities"],
        state["threats"],
        state["incidents"],
        state["controls"],
    )
    event_result = simulate_security_event(state, "critical_vulnerability")
    post_event = event_result["risk_assessment"]
    remediation_result = apply_remediation(event_result["state"], "patch-vpn")
    residual = remediation_result["residual_risk"]
    assert baseline["overall_risk_score"] > 0
    assert post_event["overall_risk_score"] >= baseline["overall_risk_score"]
    assert residual["overall_risk_score"] <= post_event["overall_risk_score"]


def test_event_simulation_updates_expected_records() -> None:
    state = generate_security_data()
    original_assets = {asset["name"]: dict(asset) for asset in state["assets"]}
    event_result = simulate_security_event(state, "critical_vulnerability")

    assert event_result["event_type"] == "critical_vulnerability"
    assert any(item["asset"] == "VPN Gateway" for item in event_result["state"]["incidents"])
    assert any(item["asset"] == "VPN Gateway" for item in event_result["state"]["threats"])
    assert any(item["asset"] == "VPN Gateway" for item in event_result["state"]["vulnerabilities"])
    assert event_result["risk_assessment"]["overall_risk_score"] >= calculate_risk(
        state["assets"],
        state["vulnerabilities"],
        state["threats"],
        state["incidents"],
        state["controls"],
    )["overall_risk_score"]
    assert state["assets"] == [
        {"name": original_assets[asset["name"]]["name"], "asset_type": original_assets[asset["name"]]["asset_type"], "criticality": original_assets[asset["name"]]["criticality"], "value": original_assets[asset["name"]]["value"]}
        for asset in state["assets"]
    ]


def test_multiple_simulated_events_and_remediation_do_not_mutate_unrelated_records() -> None:
    state = generate_security_data()
    original = {
        "assets": [dict(asset) for asset in state["assets"]],
        "vulnerabilities": [dict(v) for v in state["vulnerabilities"]],
        "threats": [dict(t) for t in state["threats"]],
        "incidents": [dict(i) for i in state["incidents"]],
        "controls": [dict(c) for c in state["controls"]],
    }

    first_event = simulate_security_event(state, "critical_vulnerability")
    second_event = simulate_security_event(first_event["state"], "phishing_campaign")
    remediation = apply_remediation(second_event["state"], "patch-vpn")

    assert len(first_event["state"]["incidents"]) >= len(original["incidents"])
    assert len(second_event["state"]["incidents"]) >= len(first_event["state"]["incidents"])
    assert remediation["residual_risk"]["overall_risk_score"] <= second_event["risk_assessment"]["overall_risk_score"]
    assert state["assets"] == original["assets"]
    assert state["controls"] == original["controls"]
    assert state["vulnerabilities"] == original["vulnerabilities"]


def test_remediation_rejects_unknown_action_and_keeps_state_unchanged() -> None:
    state = generate_security_data()
    before = {
        "assets": [dict(asset) for asset in state["assets"]],
        "controls": [dict(control) for control in state["controls"]],
        "vulnerabilities": [dict(vuln) for vuln in state["vulnerabilities"]],
    }

    with pytest.raises(ValueError, match="Unsupported remediation action"):
        apply_remediation(state, "unknown-action")

    assert state["assets"] == before["assets"]
    assert state["controls"] == before["controls"]
    assert state["vulnerabilities"] == before["vulnerabilities"]


def test_api_event_and_remediation_paths_are_consistent_with_state() -> None:
    response = client.post("/api/events/simulate", json={"event_type": "critical_vulnerability"})
    assert response.status_code == 200
    event_payload = response.json()
    assert event_payload["event_type"] == "critical_vulnerability"
    assert event_payload["risk_assessment"]["overall_risk_score"] >= 0

    remediation_response = client.post("/api/remediation/apply", json={"remediation_id": "patch-vpn"})
    assert remediation_response.status_code == 200
    remediation_payload = remediation_response.json()
    assert remediation_payload["remediation_id"] == "patch-vpn"
    assert remediation_payload["residual_risk"]["overall_risk_score"] <= event_payload["risk_assessment"]["overall_risk_score"]


def test_monitoring_handles_state_without_investments_collection() -> None:
    state = {
        "synthetic": True,
        "assets": [{"name": "Customer Portal", "asset_type": "Web Application", "criticality": 90, "value": 80}],
        "vulnerabilities": [{"id": "V-1", "asset": "Customer Portal", "title": "Weak auth", "severity": 7, "likelihood": 0.8}],
        "threats": [{"id": "T-1", "asset": "Customer Portal", "name": "Botnet", "impact": 8, "likelihood": 0.7}],
        "incidents": [],
        "controls": [{"id": "C-1", "asset": "Customer Portal", "name": "WAF", "effectiveness": 70, "status": "Active"}],
    }

    event_result = simulate_security_event(state, "critical_vulnerability")
    remediation_result = apply_remediation(event_result["state"], "patch-vpn")

    assert event_result["state"]["investments"] == []
    assert remediation_result["state"]["investments"] == []
    assert event_result["risk_assessment"]["overall_risk_score"] >= 0
    assert remediation_result["residual_risk"]["overall_risk_score"] >= 0
