from __future__ import annotations

from typing import Any

from fastapi import FastAPI, HTTPException

from backend.core.gap_prioritizer import prioritize_security_gaps
from backend.core.risk_engine import calculate_risk
from backend.data.generator import generate_security_data
from backend.services.analyst import answer_question
from backend.services.investment_optimizer import optimize_investments
from backend.services.monitoring import apply_remediation, simulate_security_event

app = FastAPI(
    title="CyberRisk Quantification API",
    description="Continuous cyber risk quantification and investment optimization",
    version="0.1.0",
)

app.state.current_state = generate_security_data()


def _assess_state(state: dict[str, Any] | None) -> dict[str, Any]:
    state = state or app.state.current_state
    return calculate_risk(
        state.get("assets", []),
        state.get("vulnerabilities", []),
        state.get("threats", []),
        state.get("incidents", []),
        state.get("controls", []),
    )


@app.get("/health")
def health_check() -> dict[str, str]:
    return {
        "status": "healthy",
        "service": "cyberrisk-api",
    }


@app.get("/api/state")
def get_state() -> dict[str, Any]:
    state = app.state.current_state
    return {
        "synthetic": bool(state.get("synthetic", True)),
        "state": state,
        "assessment": _assess_state(state),
    }


@app.post("/api/assess")
def assess(payload: dict[str, Any] | None = None) -> dict[str, Any]:
    if payload is not None and isinstance(payload, dict) and payload.get("state") is not None:
        state = payload["state"]
    else:
        state = app.state.current_state
    app.state.current_state = state
    assessment = _assess_state(state)
    return {
        "synthetic": bool(state.get("synthetic", True)),
        "assessment": assessment,
        "state": state,
    }


@app.post("/api/gaps/prioritize")
def prioritize(payload: dict[str, Any] | None = None) -> dict[str, Any]:
    payload = payload or {}
    risk_assessment = payload.get("risk_assessment") or _assess_state(app.state.current_state)
    return {
        "risk_assessment": risk_assessment,
        "gaps": prioritize_security_gaps(risk_assessment),
    }


@app.post("/api/investments/optimize")
def optimize(payload: dict[str, Any] | None = None) -> dict[str, Any]:
    payload = payload or {}
    state = app.state.current_state
    risk_assessment = payload.get("risk_assessment") or _assess_state(state)
    budget = float(payload.get("budget", 180000))
    investments = payload.get("investments") or state.get("investments", [])
    if budget < 0:
        raise HTTPException(status_code=400, detail="Budget must be non-negative.")
    return {
        "budget": budget,
        "risk_assessment": risk_assessment,
        "optimization": optimize_investments(risk_assessment, investments, budget),
    }


@app.post("/api/events/simulate")
def simulate(payload: dict[str, Any] | None = None) -> dict[str, Any]:
    payload = payload or {}
    event_type = str(payload.get("event_type") or "critical_vulnerability")
    result = simulate_security_event(app.state.current_state, event_type)
    app.state.current_state = result["state"]
    return result


@app.post("/api/remediation/apply")
def apply(payload: dict[str, Any] | None = None) -> dict[str, Any]:
    payload = payload or {}
    remediation_id = str(payload.get("remediation_id") or "patch-vpn")
    try:
        result = apply_remediation(app.state.current_state, remediation_id)
        app.state.current_state = result["state"]
        return result
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/analyst/ask")
def ask_analyst(payload: dict[str, Any] | None = None) -> dict[str, Any]:
    payload = payload or {}
    question = str(payload.get("question") or "Why is the current risk score high?")
    state = app.state.current_state
    assessment = _assess_state(state)
    gaps = prioritize_security_gaps(assessment)
    optimizer = optimize_investments(assessment, state.get("investments", []), 180000)
    response = answer_question(question, state=state, risk_assessment=assessment, gaps=gaps, optimizer_result=optimizer)
    return {
        "question": question,
        "answer": response["answer"],
        "grounded": response["grounded"],
        "evidence": response["evidence"],
    }
