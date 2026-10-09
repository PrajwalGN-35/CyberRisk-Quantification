"""Deterministic synthetic security data for demonstrations and tests."""

from typing import Any


def _generate_security_data_impl() -> dict[str, Any]:
    """Return a fresh, reproducible state using the provisional Member 3 schema."""
    assets: list[dict[str, Any]] = [
        {
            "id": "AST-001",
            "name": "Production Customer Database",
            "type": "database_server",
            "environment": "production",
            "criticality": "critical",
            "owner": "Data Operations",
        },
        {
            "id": "AST-002",
            "name": "Public Web Portal",
            "type": "web_server",
            "environment": "production",
            "criticality": "high",
            "owner": "Web Platform",
        },
        {
            "id": "AST-003",
            "name": "Finance Workstation Pool",
            "type": "employee_workstation",
            "environment": "corporate",
            "criticality": "medium",
            "owner": "Corporate IT",
        },
        {
            "id": "AST-004",
            "name": "Payment Reconciliation",
            "type": "financial_application",
            "environment": "production",
            "criticality": "critical",
            "owner": "Finance Technology",
        },
        {
            "id": "AST-005",
            "name": "Corporate File Repository",
            "type": "file_server",
            "environment": "corporate",
            "criticality": "high",
            "owner": "Infrastructure",
        },
        {
            "id": "AST-006",
            "name": "Internal Reporting Database",
            "type": "database_server",
            "environment": "internal",
            "criticality": "medium",
            "owner": "Data Operations",
        },
    ]
    vulnerabilities: list[dict[str, Any]] = [
        {
            "id": "VUL-001",
            "asset_id": "AST-001",
            "title": "Unpatched database service",
            "description": "Database service is missing a security update for a remotely exploitable flaw.",
            "severity": "high",
            "status": "open",
            "discovered_at": "2026-01-12T09:00:00+00:00",
        },
        {
            "id": "VUL-002",
            "asset_id": "AST-002",
            "title": "Outdated web framework",
            "description": "The portal framework version is outside its supported security maintenance window.",
            "severity": "critical",
            "status": "open",
            "discovered_at": "2026-01-15T11:30:00+00:00",
        },
        {
            "id": "VUL-003",
            "asset_id": "AST-003",
            "title": "Unencrypted local cache",
            "description": "A workstation application stores cached business data without encryption at rest.",
            "severity": "medium",
            "status": "open",
            "discovered_at": "2026-01-18T14:10:00+00:00",
        },
        {
            "id": "VUL-004",
            "asset_id": "AST-004",
            "title": "Weak service-account policy",
            "description": "The application service account does not meet the current credential rotation policy.",
            "severity": "high",
            "status": "open",
            "discovered_at": "2026-01-20T08:45:00+00:00",
        },
        {
            "id": "VUL-005",
            "asset_id": "AST-005",
            "title": "Legacy file-sharing protocol",
            "description": "A legacy sharing protocol remains enabled on the corporate file server.",
            "severity": "medium",
            "status": "remediated",
            "discovered_at": "2025-12-02T10:00:00+00:00",
            "remediated_at": "2025-12-10T16:00:00+00:00",
        },
        {
            "id": "VUL-006",
            "asset_id": "AST-006",
            "title": "Excessive database permissions",
            "description": "A reporting role retains write permissions that are not needed for its duties.",
            "severity": "low",
            "status": "open",
            "discovered_at": "2026-01-22T12:15:00+00:00",
        },
    ]
    threats: list[dict[str, Any]] = [
        {
            "id": "THR-001",
            "name": "Credential phishing",
            "category": "phishing",
            "likelihood": "high",
            "relevance": "high",
            "description": "Targeted messages attempt to capture employee credentials.",
        },
        {
            "id": "THR-002",
            "name": "Commodity malware",
            "category": "malware",
            "likelihood": "medium",
            "relevance": "medium",
            "description": "Common malware may arrive through untrusted downloads or attachments.",
        },
        {
            "id": "THR-003",
            "name": "Double-extortion ransomware",
            "category": "ransomware",
            "likelihood": "medium",
            "relevance": "high",
            "description": "A criminal group may encrypt systems and threaten data disclosure.",
        },
        {
            "id": "THR-004",
            "name": "Stolen privileged credentials",
            "category": "credential_compromise",
            "likelihood": "low",
            "relevance": "high",
            "description": "An attacker may reuse exposed privileged credentials to access internal services.",
        },
    ]
    incidents: list[dict[str, Any]] = [
        {
            "id": "INC-001",
            "asset_id": "AST-003",
            "title": "Suspicious attachment quarantined",
            "description": "Endpoint protection quarantined a simulated malware attachment.",
            "severity": "medium",
            "status": "resolved",
            "detected_at": "2025-11-04T13:20:00+00:00",
            "resolved_at": "2025-11-04T14:05:00+00:00",
        },
        {
            "id": "INC-002",
            "asset_id": "AST-002",
            "title": "Repeated authentication failures",
            "description": "A short burst of failed portal logins was investigated and contained.",
            "severity": "low",
            "status": "resolved",
            "detected_at": "2025-12-19T06:40:00+00:00",
            "resolved_at": "2025-12-19T07:25:00+00:00",
        },
        {
            "id": "INC-003",
            "asset_id": "AST-004",
            "title": "Unusual payment service activity",
            "description": "An analyst is reviewing an unusual service-account access pattern.",
            "severity": "high",
            "status": "active",
            "detected_at": "2026-01-24T17:05:00+00:00",
        },
    ]
    controls: list[dict[str, Any]] = [
        {
            "id": "CTL-001",
            "asset_id": "AST-002",
            "name": "Perimeter Web Firewall",
            "type": "firewall",
            "status": "active",
            "effectiveness": 0.90,
        },
        {
            "id": "CTL-002",
            "asset_id": "AST-004",
            "name": "Workforce and Finance MFA",
            "type": "multi_factor_authentication",
            "status": "active",
            "effectiveness": 0.82,
        },
        {
            "id": "CTL-003",
            "asset_id": "AST-003",
            "name": "Managed Endpoint Protection",
            "type": "endpoint_protection",
            "status": "active",
            "effectiveness": 0.88,
        },
        {
            "id": "CTL-004",
            "asset_id": "AST-001",
            "name": "Database Network Intrusion Detection",
            "type": "intrusion_detection",
            "status": "active",
            "effectiveness": 0.76,
        },
        {
            "id": "CTL-005",
            "asset_id": "AST-005",
            "name": "Offline Backup System",
            "type": "backup_system",
            "status": "maintenance",
            "effectiveness": 0.62,
        },
        {
            "id": "CTL-006",
            "asset_id": "AST-006",
            "name": "Internal Segment Firewall",
            "type": "firewall",
            "status": "active",
            "effectiveness": 0.71,
        },
    ]
    investments: list[dict[str, Any]] = [
        {
            "id": "INV-001",
            "name": "Database patch automation",
            "asset_id": "AST-001",
            "cost": 24000.0,
            "risk_reduction": 0.22,
        },
        {
            "id": "INV-002",
            "name": "Phishing-resistant MFA rollout",
            "asset_id": "AST-004",
            "cost": 18000.0,
            "risk_reduction": 0.18,
        },
        {
            "id": "INV-003",
            "name": "Immutable backup expansion",
            "asset_id": "AST-005",
            "cost": 32000.0,
            "risk_reduction": 0.16,
        },
    ]

    # Compatibility aliases keep the existing dashboard functional while
    # preserving the ID-based security schema used by structured monitoring.
    asset_by_id = {asset["id"]: asset for asset in assets}
    legacy_values = {"critical": 95, "high": 80, "medium": 60, "low": 35}

    for asset in assets:
        asset["asset_type"] = asset["type"].replace("_", " ").title()
        asset["value"] = legacy_values[asset["criticality"]]

    for index, vulnerability in enumerate(vulnerabilities):
        asset = asset_by_id[vulnerability["asset_id"]]
        vulnerability["asset"] = asset["name"]
        vulnerability["likelihood"] = {
            "critical": 0.95, "high": 0.80, "medium": 0.60, "low": 0.35
        }[vulnerability["severity"]]

    threat_asset_ids = ("AST-002", "AST-003", "AST-004", "AST-001")
    for index, threat in enumerate(threats):
        asset = asset_by_id[threat_asset_ids[index % len(threat_asset_ids)]]
        threat["asset_id"] = asset["id"]
        threat["asset"] = asset["name"]
        threat["impact"] = {"high": 9, "medium": 6, "low": 3}[
            threat["relevance"]
        ]

    for incident in incidents:
        incident["asset"] = asset_by_id[incident["asset_id"]]["name"]

    for control in controls:
        control["asset"] = asset_by_id[control["asset_id"]]["name"]

    return {
        "synthetic": True,
        "generated_at": "2026-02-01T00:00:00+00:00",
        "assets": assets,
        "vulnerabilities": vulnerabilities,
        "threats": threats,
        "incidents": incidents,
        "controls": controls,
        "investments": investments,
        "event_history": [],
    }


# CYBERRISK_INTEGRATION_COMPATIBILITY_WRAPPER
def generate_security_data():
    """Return independent demo data with canonical and legacy field aliases."""
    from copy import deepcopy

    state = deepcopy(_generate_security_data_impl())

    assets = state.get("assets", [])
    asset_names = {
        str(a.get("id", a.get("asset_id", ""))): a.get("name", "")
        for a in assets
    }

    # Older consumers use `asset`; the structured schema uses `asset_id`.
    for domain in ("vulnerabilities", "threats", "incidents", "controls"):
        for record in state.get(domain, []):
            if record.get("asset_id") is not None:
                asset_id = str(record["asset_id"])
                if not record.get("asset"):
                    record["asset"] = asset_names.get(asset_id, asset_id)

    # Normalize investment field names without discarding original fields.
    investments = state.get("investments", [])
    for index, investment in enumerate(investments, start=1):
        if not investment.get("name"):
            investment["name"] = (
                investment.get("title")
                or investment.get("investment_name")
                or investment.get("label")
                or investment.get("id")
                or f"Security Investment {index}"
            )

        if "cost" not in investment:
            for key in ("investment_cost", "estimated_cost", "cost_usd", "budget"):
                if investment.get(key) is not None:
                    investment["cost"] = investment[key]
                    break

        if "expected_risk_reduction" not in investment:
            for key in (
                "risk_reduction",
                "expected_risk_reduction_percent",
                "risk_reduction_percent",
                "expected_reduction",
                "reduction",
            ):
                value = investment.get(key)
                if isinstance(value, (int, float)):
                    investment["expected_risk_reduction"] = value
                    break

        # Preserve a stable asset association where the source provides one.
        if investment.get("asset_id") is not None and not investment.get("asset"):
            investment["asset"] = asset_names.get(
                str(investment["asset_id"]), str(investment["asset_id"])
            )

    state["synthetic"] = True
    return state
