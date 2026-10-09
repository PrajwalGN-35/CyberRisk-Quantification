from copy import deepcopy

import pytest

from backend.data.generator import generate_security_data


DOMAIN_NAMES = ("assets", "vulnerabilities", "threats", "incidents", "controls")


def test_generator_returns_five_domains_and_reproducible_fresh_state() -> None:
    first = generate_security_data()
    second = generate_security_data()

    assert all(isinstance(first[name], list) for name in DOMAIN_NAMES)
    assert first == second
    assert first is not second
    # Mutable top-level values must be independent. Immutable values such
    # as True and strings may legitimately share object identity in Python.
    assert all(
        first[name] is not second[name]
        for name in first
        if isinstance(first[name], (list, dict, set))
    )


@pytest.mark.parametrize(
    ("domain", "expected_count"),
    [
        ("assets", 6),
        ("vulnerabilities", 6),
        ("threats", 4),
        ("incidents", 3),
        ("controls", 6),
    ],
)
def test_domain_counts_and_unique_identifiers(domain: str, expected_count: int) -> None:
    records = generate_security_data()[domain]

    assert len(records) == expected_count
    assert all(isinstance(record["id"], str) for record in records)
    assert len({record["id"] for record in records}) == expected_count


def test_generator_types_categories_relationships_and_control_ranges() -> None:
    state = generate_security_data()
    asset_ids = {asset["id"] for asset in state["assets"]}

    assert {asset["type"] for asset in state["assets"]} >= {
        "database_server",
        "web_server",
        "employee_workstation",
        "financial_application",
        "file_server",
    }
    assert {asset["criticality"] for asset in state["assets"]} >= {
        "critical",
        "high",
        "medium",
    }
    for domain in ("vulnerabilities", "incidents", "controls"):
        assert all(record["asset_id"] in asset_ids for record in state[domain])
    assert {row["severity"] for row in state["vulnerabilities"]} >= {
        "critical",
        "high",
        "medium",
        "low",
    }
    assert {row["status"] for row in state["vulnerabilities"]} == {
        "open",
        "remediated",
    }
    assert {row["category"] for row in state["threats"]} >= {
        "malware",
        "phishing",
        "ransomware",
        "credential_compromise",
    }
    assert {row["status"] for row in state["incidents"]} >= {"active", "resolved"}
    assert all(
        isinstance(row["effectiveness"], float)
        and 0 <= row["effectiveness"] <= 1
        for row in state["controls"]
    )
    assert {row["type"] for row in state["controls"]} >= {
        "firewall",
        "multi_factor_authentication",
        "endpoint_protection",
        "intrusion_detection",
        "backup_system",
    }
    assert state["event_history"] == []
    assert state["investments"]


def test_generated_values_are_independent_between_calls() -> None:
    original = generate_security_data()
    snapshot = deepcopy(original)

    original["assets"][0]["name"] = "changed"
    original["vulnerabilities"].clear()

    assert snapshot["assets"][0]["name"] != "changed"
    assert len(snapshot["vulnerabilities"]) == 6
    assert len(generate_security_data()["vulnerabilities"]) == 6
