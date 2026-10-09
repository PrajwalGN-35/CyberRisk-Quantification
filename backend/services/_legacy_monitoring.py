from __future__ import annotations

import copy
from typing import Any

from backend.core.gap_prioritizer import prioritize_security_gaps
from backend.core.risk_engine import calculate_risk
from backend.data.generator import generate_security_data
from backend.services.investment_optimizer import optimize_investments


def _default_state() -> dict[str, Any]:
    return generate_security_data()


def simulate_security_event(
    state: dict[str, Any] | None,
    event_type: str = "critical_vulnerability",
) -> dict[str, Any]:
    """Simulate a security event and update the state."""
    active_state = copy.deepcopy(state or _default_state())
    for key in ("assets", "vulnerabilities", "threats", "incidents", "controls", "investments"):
        active_state.setdefault(key, [])
    event_type = (event_type or "critical_vulnerability").strip().lower()

    if event_type.startswith("critical"):
        active_state["incidents"].append(
            {
                "id": "INC-NEW-001",
                "asset": "VPN Gateway",
                "title": "Critical VPN exploit is observed in production",
                "severity": 9,
                "status": "Open",
            }
        )
        active_state["threats"].append(
            {
                "id": "THREAT-NEW-001",
                "asset": "VPN Gateway",
                "name": "Active exploitation of VPN appliance",
                "impact": 9,
                "likelihood": 0.9,
            }
        )
        active_state["vulnerabilities"].append(
            {
                "id": "VULN-NEW-001",
                "asset": "VPN Gateway",
                "title": "Zero-day VPN bypass chain detected",
                "severity": 9,
                "likelihood": 0.9,
            }
        )
        for control in active_state["controls"]:
            if control.get("asset") == "VPN Gateway":
                control["effectiveness"] = max(10, int(control.get("effectiveness", 50)) - 18)
    elif event_type.startswith("phish"):
        active_state["incidents"].append(
            {
                "id": "INC-NEW-002",
                "asset": "Identity Platform",
                "title": "Phishing campaign bypasses MFA controls",
                "severity": 8,
                "status": "Containment",
            }
        )
    else:
        active_state["incidents"].append(
            {
                "id": "INC-NEW-003",
                "asset": "Endpoint Fleet",
                "title": "Suspicious privilege escalation observed",
                "severity": 7,
                "status": "Investigating",
            }
        )

    assessment = calculate_risk(
        active_state["assets"],
        active_state["vulnerabilities"],
        active_state["threats"],
        active_state["incidents"],
        active_state["controls"],
    )
    gaps = prioritize_security_gaps(assessment)
    optimizer = optimize_investments(assessment, active_state["investments"], 180000)

    return {
        "event_type": event_type,
        "message": "The simulated security event increased modeled exposure and triggered a reassessment.",
        "state": active_state,
        "risk_assessment": assessment,
        "gap_prioritization": gaps,
        "investment_optimization": optimizer,
    }


def apply_remediation(state: dict[str, Any] | None, remediation_id: str) -> dict[str, Any]:
    """Apply a remediation action and return residual risk."""
    active_state = copy.deepcopy(state or _default_state())
    for key in ("assets", "vulnerabilities", "threats", "incidents", "controls", "investments"):
        active_state.setdefault(key, [])
    remediation_id = (remediation_id or "patch-vpn").strip().lower()

    if remediation_id == "patch-vpn":
        for control in active_state["controls"]:
            if control.get("asset") == "VPN Gateway":
                control["effectiveness"] = min(100, int(control.get("effectiveness", 50)) + 22)
        for vuln in active_state["vulnerabilities"]:
            if vuln.get("asset") == "VPN Gateway":
                vuln["severity"] = min(10, int(vuln.get("severity", 5)) - 2)
        message = "VPN appliance hardening was applied and the exposure pressure on the gateway was reduced."
    elif remediation_id == "mfa-strengthening":
        for control in active_state["controls"]:
            if control.get("asset") == "Identity Platform":
                control["effectiveness"] = min(100, int(control.get("effectiveness", 50)) + 18)
        message = "Identity protection controls were strengthened and phishing exposure was reduced."
    else:
        raise ValueError(f"Unsupported remediation action: {remediation_id}")

    assessment = calculate_risk(
        active_state["assets"],
        active_state["vulnerabilities"],
        active_state["threats"],
        active_state["incidents"],
        active_state["controls"],
    )
    gaps = prioritize_security_gaps(assessment)
    optimizer = optimize_investments(assessment, active_state["investments"], 180000)

    return {
        "remediation_id": remediation_id,
        "message": message,
        "state": active_state,
        "residual_risk": assessment,
        "gap_prioritization": gaps,
        "investment_optimization": optimizer,
    }
