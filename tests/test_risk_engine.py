import inspect
from typing import get_type_hints

import pytest

from backend.contracts import calculate_risk as contract_calculate_risk
from backend.core.risk_engine import calculate_risk


def _calculate(
    assets,
    vulnerabilities=None,
    threats=None,
    incidents=None,
    controls=None,
):
    return calculate_risk(
        assets,
        vulnerabilities or [],
        threats or [],
        incidents or [],
        controls or [],
    )


def _asset_result(result, asset_id="asset-1"):
    return next(item for item in result["assets"] if item["asset_id"] == asset_id)


def test_public_function_matches_shared_contract():
    actual = inspect.signature(calculate_risk)
    expected = inspect.signature(contract_calculate_risk)
    assert list(actual.parameters) == list(expected.parameters)
    assert [parameter.kind for parameter in actual.parameters.values()] == [
        parameter.kind for parameter in expected.parameters.values()
    ]
    assert get_type_hints(calculate_risk) == get_type_hints(contract_calculate_risk)


def test_normal_risk_calculates_explainable_inherent_and_residual_scores():
    result = _calculate(
        [{"asset_id": "asset-1", "name": "Billing", "criticality": 80}],
        vulnerabilities=[
            {
                "asset_id": "asset-1",
                "vulnerability_id": "CVE-A",
                "severity": 8,
                "title": "Known issue",
            }
        ],
        threats=[{"asset_id": "asset-1", "threat_id": "T-1", "likelihood": 0.6}],
        incidents=[
            {
                "asset_id": "asset-1",
                "incident_id": "I-1",
                "severity": 5,
                "summary": "Prior event",
            }
        ],
        controls=[
            {
                "asset_id": "asset-1",
                "control_id": "C-1",
                "domain": "vulnerability",
                "effectiveness": 50,
            }
        ],
    )

    assessment = _asset_result(result)
    assert assessment["factors"]["criticality"] == 80
    assert assessment["factors"]["vulnerability_severity"] == 80
    assert assessment["factors"]["threat_likelihood"] == 60
    assert assessment["inherent_risk_score"] == 68.56
    assert assessment["residual_risk_score"] < assessment["inherent_risk_score"]
    assert "vulnerability_severity" in assessment["risk_drivers"]
    assert assessment["reasons"]
    assert result["organization"]["asset_count"] == 1
    assert result["organization"]["residual_risk_score"] == assessment[
        "residual_risk_score"
    ]


def test_high_criticality_and_severe_vulnerability_increase_risk():
    low = _calculate(
        [{"asset_id": "asset-1", "criticality": 10}],
        vulnerabilities=[{"asset_id": "asset-1", "severity": 2}],
    )
    high = _calculate(
        [{"asset_id": "asset-1", "criticality": 90}],
        vulnerabilities=[{"asset_id": "asset-1", "severity": 9}],
    )
    assert _asset_result(high)["inherent_risk_score"] > _asset_result(low)[
        "inherent_risk_score"
    ]


def test_threat_likelihood_and_incident_history_change_scores():
    base = _calculate(
        [{"asset_id": "asset-1", "criticality": 40}],
        threats=[{"asset_id": "asset-1", "likelihood": 0.2}],
        incidents=[{"asset_id": "asset-1", "incident_id": "I-1", "severity": 2}],
    )
    likely = _calculate(
        [{"asset_id": "asset-1", "criticality": 40}],
        threats=[{"asset_id": "asset-1", "likelihood": 0.9}],
        incidents=[{"asset_id": "asset-1", "incident_id": "I-1", "severity": 2}],
    )
    repeated = _calculate(
        [{"asset_id": "asset-1", "criticality": 40}],
        threats=[{"asset_id": "asset-1", "likelihood": 0.2}],
        incidents=[
            {"asset_id": "asset-1", "incident_id": "I-1", "severity": 2},
            {"asset_id": "asset-1", "incident_id": "I-2", "severity": 2},
            {"asset_id": "asset-1", "incident_id": "I-3", "severity": 2},
        ],
    )
    assert _asset_result(likely)["inherent_risk_score"] > _asset_result(base)[
        "inherent_risk_score"
    ]
    assert _asset_result(repeated)["factors"]["incident_history"] > _asset_result(
        base
    )["factors"]["incident_history"]
    assert _asset_result(repeated)["inherent_risk_score"] > _asset_result(base)[
        "inherent_risk_score"
    ]


def test_controls_only_reduce_matching_asset_and_domain_and_are_not_stacked():
    inputs = {
        "assets": [{"asset_id": "asset-1", "criticality": 80}],
        "vulnerabilities": [{"asset_id": "asset-1", "severity": 8}],
    }
    baseline = _calculate(**inputs)
    mitigated = _calculate(
        **inputs,
        controls=[
            {
                "asset_id": "asset-1",
                "control_id": "C-1",
                "domain": "vulnerability",
                "effectiveness": 60,
            },
            {
                "asset_id": "asset-1",
                "control_id": "C-2",
                "domain": "vulnerability",
                "effectiveness": 40,
            },
        ],
    )
    unrelated = _calculate(
        **inputs,
        controls=[
            {
                "asset_id": "asset-2",
                "domain": "vulnerability",
                "effectiveness": 100,
            },
            {"asset_id": "asset-1", "effectiveness": 100},
        ],
    )

    baseline_asset = _asset_result(baseline)
    mitigated_asset = _asset_result(mitigated)
    assert mitigated_asset["inherent_risk_score"] == baseline_asset["inherent_risk_score"]
    assert mitigated_asset["residual_risk_score"] < baseline_asset["residual_risk_score"]
    assert unrelated["assets"][0]["residual_risk_score"] == baseline_asset[
        "residual_risk_score"
    ]


def test_same_control_identifier_can_support_multiple_explicit_domains():
    result = _calculate(
        [{"asset_id": "asset-1", "criticality": 50}],
        vulnerabilities=[{"asset_id": "asset-1", "severity": 8}],
        threats=[{"asset_id": "asset-1", "likelihood": 0.8}],
        controls=[
            {
                "asset_id": "asset-1",
                "control_id": "C-1",
                "domain": "vulnerability",
                "effectiveness": 80,
            },
            {
                "asset_id": "asset-1",
                "control_id": "C-1",
                "domain": "threat",
                "effectiveness": 60,
            },
        ],
    )
    effectiveness = _asset_result(result)["factors"]["control_effectiveness"]
    assert effectiveness["vulnerability_severity"] == 80
    assert effectiveness["threat_likelihood"] == 60


def test_empty_inputs_and_assets_without_any_risk_factors_are_unknown_not_zero():
    empty = _calculate([])
    unscored = _calculate([{"asset_id": "asset-1", "name": "No data"}])

    assert empty["organization"]["asset_count"] == 0
    assert empty["organization"]["residual_risk_score"] is None
    assert empty["organization"]["category"] == "Unknown"
    assert unscored["assets"][0]["residual_risk_score"] is None
    assert unscored["assets"][0]["category"] == "Unknown"


def test_missing_optional_factors_renormalize_available_weights():
    result = _calculate(
        [{"asset_id": "asset-1"}],
        vulnerabilities=[{"asset_id": "asset-1", "severity": 7}],
    )
    assessment = _asset_result(result)
    assert assessment["inherent_risk_score"] == 70
    assert assessment["residual_risk_score"] == 70


def test_malformed_records_and_unknown_asset_references_are_reported():
    result = calculate_risk(
        [{"asset_id": "asset-1", "criticality": "not-a-score"}, None],
        [
            {"asset_id": "asset-1", "severity": 101},
            {"asset_id": "missing", "severity": 10},
            "not a record",
        ],
        [],
        [],
        [],
    )

    assert _asset_result(result)["residual_risk_score"] is None
    assert result["data_quality"]["warnings"]
    assert any("unknown asset" in warning for warning in result["data_quality"]["warnings"])
    assert any("invalid" in warning for warning in result["data_quality"]["warnings"])


def test_duplicate_vulnerability_and_incident_evidence_does_not_inflate_score():
    base = _calculate(
        [{"asset_id": "asset-1", "criticality": 40}],
        vulnerabilities=[
            {"asset_id": "asset-1", "vulnerability_id": "V-1", "severity": 8}
        ],
        incidents=[{"asset_id": "asset-1", "incident_id": "I-1", "severity": 8}],
    )
    duplicated = _calculate(
        [{"asset_id": "asset-1", "criticality": 40}],
        vulnerabilities=[
            {"asset_id": "asset-1", "vulnerability_id": "V-1", "severity": 8},
            {"asset_id": "asset-1", "vulnerability_id": "V-1", "severity": 8},
        ],
        incidents=[
            {"asset_id": "asset-1", "incident_id": "I-1", "severity": 8},
            {"asset_id": "asset-1", "incident_id": "I-1", "severity": 8},
        ],
    )

    assert duplicated == base
    assert len(_asset_result(duplicated)["evidence"]["vulnerabilities"]) == 1
    assert len(_asset_result(duplicated)["evidence"]["incidents"]) == 1


def test_results_are_deterministic_and_order_independent():
    assets = [
        {"asset_id": "asset-b", "criticality": 70},
        {"asset_id": "asset-a", "criticality": 40},
    ]
    vulnerabilities = [
        {"asset_id": "asset-b", "vulnerability_id": "V-2", "severity": 9},
        {"asset_id": "asset-a", "vulnerability_id": "V-1", "severity": 5},
    ]
    first = _calculate(assets, vulnerabilities)
    second = _calculate(list(reversed(assets)), list(reversed(vulnerabilities)))
    assert first == second


@pytest.mark.parametrize(
    ("criticality", "expected_category"),
    [(0, "Low"), (24.9, "Low"), (25, "Moderate"), (49.9, "Moderate"),
     (50, "High"), (74.9, "High"), (75, "Critical"), (100, "Critical")],
)
def test_score_bounds_and_category_thresholds(criticality, expected_category):
    result = _calculate([{"asset_id": "asset-1", "criticality": criticality}])
    assessment = _asset_result(result)
    assert 0 <= assessment["residual_risk_score"] <= 100
    assert assessment["category"] == expected_category
