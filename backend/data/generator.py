from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


def generate_security_data() -> dict[str, Any]:
    """Generate reproducible synthetic security data for demo use."""
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    assets = [
        {
            "name": "Customer Portal",
            "asset_type": "Web Application",
            "criticality": 92,
            "value": 90,
        },
        {
            "name": "VPN Gateway",
            "asset_type": "Network Security",
            "criticality": 88,
            "value": 85,
        },
        {
            "name": "Endpoint Fleet",
            "asset_type": "Endpoint",
            "criticality": 74,
            "value": 70,
        },
        {
            "name": "Identity Platform",
            "asset_type": "Identity",
            "criticality": 90,
            "value": 95,
        },
    ]

    vulnerabilities = [
        {
            "id": "VULN-101",
            "asset": "VPN Gateway",
            "title": "OpenVPN remote code execution",
            "severity": 9,
            "likelihood": 0.8,
        },
        {
            "id": "VULN-102",
            "asset": "Customer Portal",
            "title": "Outdated web application framework",
            "severity": 7,
            "likelihood": 0.7,
        },
        {
            "id": "VULN-103",
            "asset": "Endpoint Fleet",
            "title": "Unpatched endpoint privilege escalation",
            "severity": 8,
            "likelihood": 0.75,
        },
        {
            "id": "VULN-104",
            "asset": "Identity Platform",
            "title": "Weak multifactor enforcement",
            "severity": 6,
            "likelihood": 0.8,
        },
    ]

    threats = [
        {
            "id": "THREAT-211",
            "asset": "Customer Portal",
            "name": "Credential stuffing botnet",
            "impact": 8,
            "likelihood": 0.75,
        },
        {
            "id": "THREAT-212",
            "asset": "VPN Gateway",
            "name": "Exploit chain for remote access gateway",
            "impact": 9,
            "likelihood": 0.7,
        },
        {
            "id": "THREAT-213",
            "asset": "Identity Platform",
            "name": "Phishing campaign targeting admin accounts",
            "impact": 8,
            "likelihood": 0.8,
        },
    ]

    incidents = [
        {
            "id": "INC-301",
            "asset": "Customer Portal",
            "title": "Repeated failed login spikes",
            "severity": 6,
            "status": "Monitoring",
        },
        {
            "id": "INC-302",
            "asset": "Endpoint Fleet",
            "title": "Suspicious lateral movement alert",
            "severity": 7,
            "status": "Investigating",
        },
    ]

    controls = [
        {
            "id": "CTRL-401",
            "asset": "Customer Portal",
            "name": "WAF and input validation",
            "effectiveness": 72,
            "status": "Active",
        },
        {
            "id": "CTRL-402",
            "asset": "VPN Gateway",
            "name": "Zero-trust segmentation",
            "effectiveness": 68,
            "status": "Active",
        },
        {
            "id": "CTRL-403",
            "asset": "Endpoint Fleet",
            "name": "EDR and patch orchestration",
            "effectiveness": 74,
            "status": "Active",
        },
        {
            "id": "CTRL-404",
            "asset": "Identity Platform",
            "name": "MFA with conditional access",
            "effectiveness": 81,
            "status": "Active",
        },
    ]

    investments = [
        {
            "name": "Patch exposed VPN appliances",
            "category": "Vulnerability remediation",
            "cost": 75000,
            "expected_risk_reduction": 18,
            "asset": "VPN Gateway",
        },
        {
            "name": "Deploy endpoint hardening automation",
            "category": "Endpoint security",
            "cost": 65000,
            "expected_risk_reduction": 16,
            "asset": "Endpoint Fleet",
        },
        {
            "name": "Increase identity anti-phishing controls",
            "category": "Identity protection",
            "cost": 55000,
            "expected_risk_reduction": 15,
            "asset": "Identity Platform",
        },
        {
            "name": "Application security review",
            "category": "Application security",
            "cost": 45000,
            "expected_risk_reduction": 12,
            "asset": "Customer Portal",
        },
    ]

    return {
        "synthetic": True,
        "generated_at": timestamp,
        "assets": assets,
        "vulnerabilities": vulnerabilities,
        "threats": threats,
        "incidents": incidents,
        "controls": controls,
        "investments": investments,
    }
