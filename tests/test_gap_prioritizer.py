import inspect
from typing import get_type_hints

from backend.contracts import prioritize_security_gaps as contract_prioritize_security_gaps
from backend.core.gap_prioritizer import prioritize_security_gaps
from backend.core.risk_engine import calculate_risk


def _assessment(
    asset_id,
    *,
    criticality=50,
    exposure=50,
    severity=50,
    incident_history=20,
    residual=40,
    vulnerabilities=None,
    controls=None,
):
    vulnerability_evidence = [dict(item) for item in vulnerabilities or []]
    control_evidence = [dict(item) for item in controls or []]
    for item in vulnerability_evidence:
        item.setdefault("asset_id", asset_id)
    for item in control_evidence:
        item.setdefault("asset_id", asset_id)
    return {
        "asset_id": asset_id,
        "asset_name": asset_id,
        "residual_risk_score": residual,
        "factors": {
            "criticality": criticality,
            "exposure": exposure,
            "vulnerability_severity": severity,
            "incident_history": incident_history,
        },
        "evidence": {
            "vulnerabilities": vulnerability_evidence,
            "controls": control_evidence,
        },
    }


def _from_engine(assets, vulnerabilities=None, controls=None):
    return calculate_risk(
        assets,
        vulnerabilities or [],
        [],
        [],
        controls or [],
    )


def test_public_function_matches_shared_contract():
    actual = inspect.signature(prioritize_security_gaps)
    expected = inspect.signature(contract_prioritize_security_gaps)
    assert list(actual.parameters) == list(expected.parameters)
    assert [parameter.kind for parameter in actual.parameters.values()] == [
        parameter.kind for parameter in expected.parameters.values()
    ]
    assert get_type_hints(prioritize_security_gaps) == get_type_hints(
        contract_prioritize_security_gaps
    )


def test_vulnerability_gap_contains_evidence_explanation_and_remediation():
    result = _from_engine(
        [{"asset_id": "asset-1", "name": "Payments", "criticality": 80}],
        [
            {
                "asset_id": "asset-1",
                "vulnerability_id": "V-1",
                "severity": 9,
                "title": "Recorded critical vulnerability",
                "remediation": "Upgrade the affected component.",
            }
        ],
    )

    gaps = prioritize_security_gaps(result)
    assert len(gaps) == 1
    gap = gaps[0]
    assert gap["asset_id"] == "asset-1"
    assert gap["gap_type"] == "vulnerability"
    assert gap["gap_id"] == "V-1"
    assert gap["priority_score"] is not None
    assert gap["category"] in {"Low", "Moderate", "High", "Critical"}
    assert gap["evidence"]["severity"] == 9
    assert gap["explanation"]
    assert gap["recommendation"] == "Upgrade the affected component."


def test_priority_increases_with_vulnerability_and_risk_factors():
    lower = prioritize_security_gaps(
        _from_engine(
            [{"asset_id": "asset-1", "criticality": 20, "exposure": 10}],
            [{"asset_id": "asset-1", "vulnerability_id": "V-1", "severity": 2}],
        )
    )[0]
    higher_assessment = _from_engine(
        [{"asset_id": "asset-1", "criticality": 80, "exposure": 70}],
        [{"asset_id": "asset-1", "vulnerability_id": "V-1", "severity": 9}],
    )
    higher = prioritize_security_gaps(higher_assessment)[0]
    assert higher["priority_score"] > lower["priority_score"]
    assert higher["priority_score"] != higher_assessment["assets"][0][
        "residual_risk_score"
    ]


def test_control_gap_uses_control_weakness_and_explicit_remediation():
    result = _from_engine(
        [{"asset_id": "asset-1", "criticality": 70}],
        controls=[
            {
                "asset_id": "asset-1",
                "control_id": "C-1",
                "domain": "threat",
                "effectiveness": 30,
                "name": "Threat monitoring",
                "remediation": "Tune the detection rule.",
            }
        ],
    )

    gaps = prioritize_security_gaps(result)
    assert len(gaps) == 1
    assert gaps[0]["gap_type"] == "control"
    assert gaps[0]["priority_score"] is not None
    assert gaps[0]["recommendation"] == "Tune the detection rule."
    assert "control weakness" in gaps[0]["explanation"]


def test_normalized_asset_factors_are_not_rescaled_as_raw_input_scores():
    result = {
        "assets": [
            _assessment(
                "asset-1",
                criticality=None,
                exposure=None,
                severity=10,
                incident_history=None,
                residual=10,
                controls=[
                    {
                        "control_id": "C-1",
                        "domain": "threat",
                        "effectiveness": 10,
                    }
                ],
            )
        ]
    }
    gap = prioritize_security_gaps(result)[0]
    assert gap["priority_score"] == 16.67


def test_fully_effective_controls_and_missing_evidence_do_not_create_gaps():
    result = _from_engine(
        [{"asset_id": "asset-1", "criticality": 50}],
        controls=[
            {
                "asset_id": "asset-1",
                "control_id": "C-1",
                "domain": "threat",
                "effectiveness": 100,
            }
        ],
    )
    assert prioritize_security_gaps(result) == []
    assert prioritize_security_gaps({"assets": [{"asset_id": "asset-1"}]}) == []
    assert prioritize_security_gaps({}) == []
    assert prioritize_security_gaps(None) == []


def test_asset_association_without_vulnerability_identifiers_or_details_is_not_a_gap():
    result = {
        "assets": [
            _assessment(
                "asset-1",
                vulnerabilities=[{"asset_id": "asset-1"}],
            )
        ]
    }
    assert prioritize_security_gaps(result) == []


def test_missing_score_fields_are_omitted_and_not_assumed_zero():
    result = _from_engine(
        [{"asset_id": "asset-1"}],
        [{"asset_id": "asset-1", "vulnerability_id": "V-1", "title": "Unscored"}],
    )
    gaps = prioritize_security_gaps(result)
    assert len(gaps) == 1
    assert gaps[0]["priority_score"] is None
    assert gaps[0]["category"] == "Unknown"
    assert "no numeric ranking factors" in gaps[0]["explanation"]


def test_duplicate_gaps_are_removed_by_asset_and_stable_identifier():
    result = {
        "assets": [
            _assessment(
                "asset-1",
                vulnerabilities=[
                    {"vulnerability_id": "V-1", "severity": 50, "title": "Issue"},
                    {"vulnerability_id": "V-1", "severity": 90, "title": "Issue"},
                ],
            ),
            _assessment(
                "asset-2",
                vulnerabilities=[
                    {"vulnerability_id": "V-1", "severity": 90, "title": "Issue"}
                ],
            ),
        ]
    }
    gaps = prioritize_security_gaps(result)
    assert len(gaps) == 2
    assert [gap["asset_id"] for gap in gaps] == ["asset-1", "asset-2"]
    assert gaps[0]["evidence"]["severity"] == 90


def test_exact_duplicate_evidence_without_identifier_is_collapsed():
    vulnerability = {"title": "Repeated evidence", "severity": 5}
    result = {
        "assets": [
            _assessment(
                "asset-1",
                vulnerabilities=[vulnerability, dict(vulnerability)],
            )
        ]
    }
    assert len(prioritize_security_gaps(result)) == 1


def test_rank_order_and_ties_are_deterministic():
    result = {
        "assets": [
            _assessment(
                "asset-b",
                vulnerabilities=[{"vulnerability_id": "V-2", "severity": 90}],
            ),
            _assessment(
                "asset-a",
                vulnerabilities=[
                    {"vulnerability_id": "V-3", "severity": 90},
                    {"vulnerability_id": "V-1", "severity": 90},
                ],
            ),
            _assessment(
                "asset-c",
                vulnerabilities=[{"vulnerability_id": "V-4", "severity": 1}],
            ),
        ]
    }
    gaps = prioritize_security_gaps(result)
    assert [gap["gap_id"] for gap in gaps] == ["V-1", "V-3", "V-2", "V-4"]
    assert prioritize_security_gaps(result) == gaps


def test_malformed_asset_and_evidence_records_are_ignored():
    result = {
        "assets": [
            None,
            {"asset_id": "", "evidence": {"vulnerabilities": [{"severity": 9}]}},
            {
                "asset_id": "asset-1",
                "evidence": {
                    "vulnerabilities": [None, "bad", {"severity": 9}],
                    "controls": [None, {"effectiveness": "unknown"}],
                },
            },
        ]
    }
    assert prioritize_security_gaps(result) == []
