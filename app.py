from __future__ import annotations
import os

import copy

import httpx
import pandas as pd
import streamlit as st

from backend.core.gap_prioritizer import prioritize_security_gaps
from backend.core.risk_engine import calculate_risk
from backend.data.generator import generate_security_data
from backend.services.analyst import answer_question
from backend.services.investment_optimizer import optimize_investments
from backend.services.monitoring import apply_remediation, simulate_security_event

st.set_page_config(page_title="CyberRisk Intelligence", page_icon="🛡️", layout="wide")

ASSET_COLUMNS = ["name", "asset_type", "criticality", "value"]
VULNERABILITY_COLUMNS = ["id", "asset", "title", "severity", "likelihood"]
THREAT_COLUMNS = ["id", "asset", "name", "impact", "likelihood"]
INCIDENT_COLUMNS = ["id", "asset", "title", "severity", "status"]
CONTROL_COLUMNS = ["id", "asset", "name", "effectiveness", "status"]

CUSTOM_CSS = """
<style>
    :root {
        --bg: #071423;
        --panel: #0d1d2d;
        --panel-soft: #122738;
        --panel-alt: #0c1f31;
        --line: rgba(148, 163, 184, 0.22);
        --text: #edf6ff;
        --muted: #97a9c3;
        --accent: #6ee7ff;
        --accent-strong: #3b82f6;
        --violet: #8b5cf6;
        --green: #34d399;
        --amber: #fbbf24;
        --red: #f87171;
        --shadow: rgba(15, 23, 42, 0.45);
    }

    .stApp {
        background: linear-gradient(180deg, #040d18 0%, #071423 100%);
        color: var(--text);
    }

    .stSidebar {
        background: rgba(9, 18, 30, 0.92);
        border-right: 1px solid var(--line);
    }

    .main .block-container {
        padding-top: 1.5rem;
        padding-bottom: 3rem;
        max-width: 1600px;
    }

    .topbar {
        display: flex;
        justify-content: space-between;
        align-items: center;
        gap: 1rem;
        padding: 1.1rem 1.3rem;
        margin-bottom: 1.25rem;
        border: 1px solid var(--line);
        border-radius: 18px;
        background: linear-gradient(135deg, rgba(13, 29, 45, 0.96), rgba(15, 28, 42, 0.82));
        box-shadow: 0 8px 30px var(--shadow);
    }

    .eyebrow {
        font-size: 0.7rem;
        letter-spacing: 0.2rem;
        color: var(--accent);
        font-weight: 700;
        margin-bottom: 0.25rem;
    }

    .topbar h1 {
        margin: 0;
        font-size: clamp(1.7rem, 2.3vw, 2.7rem);
        line-height: 1.15;
        color: var(--text);
    }

    .header-subtitle {
        color: var(--muted);
        margin-top: 0.35rem;
        font-size: 0.95rem;
    }

    .status-pill {
        display: inline-flex;
        align-items: center;
        gap: 0.5rem;
        padding: 0.5rem 0.8rem;
        border-radius: 999px;
        border: 1px solid var(--line);
        font-size: 0.72rem;
        font-weight: 700;
        letter-spacing: 0.08rem;
        text-transform: uppercase;
    }

    .status-live {
        background: rgba(52, 211, 153, 0.12);
        border-color: rgba(52, 211, 153, 0.38);
        color: #9bf3ce;
    }

    .status-demo {
        background: rgba(59, 130, 246, 0.12);
        border-color: rgba(110, 231, 255, 0.36);
        color: #c4f3ff;
    }

    .status-live::before, .status-demo::before {
        content: "";
        width: 0.6rem;
        height: 0.6rem;
        border-radius: 50%;
        display: inline-block;
        background: currentColor;
        box-shadow: 0 0 12px currentColor;
    }

    .metric-card {
        position: relative;
        background: linear-gradient(180deg, rgba(17, 32, 46, 0.98), rgba(13, 28, 40, 0.96));
        border: 1px solid var(--line);
        border-radius: 16px;
        padding: 1rem 1.1rem 0.95rem;
        min-height: 120px;
        box-shadow: 0 8px 20px rgba(2, 6, 23, 0.22);
    }

    .metric-card::after {
        content: "";
        position: absolute;
        top: 0;
        left: 0;
        right: 0;
        height: 2px;
        border-radius: 16px 16px 0 0;
        background: linear-gradient(90deg, var(--accent), var(--violet));
        opacity: 0.9;
    }

    .metric-label {
        font-size: 0.7rem;
        color: var(--muted);
        letter-spacing: 0.12rem;
        text-transform: uppercase;
        font-weight: 600;
    }

    .metric-value {
        margin-top: 0.75rem;
        font-size: clamp(1.5rem, 2vw, 2.2rem);
        font-weight: 700;
        color: var(--text);
        letter-spacing: -0.04em;
    }

    .metric-context {
        margin-top: 0.35rem;
        color: var(--muted);
        font-size: 0.8rem;
    }

    .section-panel {
        border: 1px solid var(--line);
        border-radius: 18px;
        background: linear-gradient(180deg, rgba(11, 22, 35, 0.96), rgba(8, 18, 28, 0.9));
        padding: 1.1rem 1rem 0.9rem;
        box-shadow: 0 10px 24px rgba(2, 6, 23, 0.18);
        margin-top: 1.2rem;
    }

    .section-title {
        margin: 0 0 0.65rem 0;
        color: var(--text);
        font-size: 1.08rem;
        font-weight: 700;
        letter-spacing: 0.03em;
    }

    .muted-note {
        color: var(--muted);
        font-size: 0.8rem;
    }

    .insight-pill {
        display: inline-block;
        padding: 0.38rem 0.6rem;
        border-radius: 999px;
        font-size: 0.68rem;
        font-weight: 700;
        letter-spacing: 0.08rem;
        text-transform: uppercase;
        border: 1px solid var(--line);
    }

    .pill-low { background: rgba(52, 211, 153, 0.12); color: #b8f6d9; }
    .pill-moderate { background: rgba(251, 191, 36, 0.12); color: #fbe7a4; }
    .pill-high { background: rgba(248, 113, 113, 0.12); color: #fecaca; }
    .pill-critical { background: rgba(139, 92, 246, 0.12); color: #e9d5ff; }

    .stDataFrame {
        border-radius: 14px;
    }

    .stProgress > div > div {
        background: linear-gradient(90deg, var(--accent), var(--violet));
    }

    .stTabs [data-baseweb="tab-list"] {
        gap: 0.5rem;
        border-bottom: 1px solid var(--line);
    }

    .stTabs [data-baseweb="tab"] {
        background: rgba(17, 29, 42, 0.9);
        border: 1px solid var(--line);
        border-bottom: none;
        border-radius: 10px 10px 0 0;
        color: var(--muted);
        padding: 0.5rem 0.8rem;
    }

    .stTabs [aria-selected="true"] {
        color: var(--text);
        background: rgba(14, 25, 38, 0.98);
    }

    .limited-height {
        max-height: 280px;
    }
</style>
"""


def _initial_state() -> dict:
    return generate_security_data()


def _normalize_domain_rows(rows: list[dict], expected_columns: list[str], asset_name_lookup: set[str] | None = None) -> list[dict]:
    normalized: list[dict] = []
    asset_names = asset_name_lookup or set()
    for row in rows or []:
        if not isinstance(row, dict):
            continue
        record: dict[str, object] = {}
        for column in expected_columns:
            value = row.get(column)
            if value is None:
                aliases = {
                    "asset": ["asset", "affected_asset", "target_asset"],
                    "name": ["name", "asset_name"],
                    "title": ["title", "name"],
                    "status": ["status", "state"],
                    "effectiveness": ["effectiveness", "control_effectiveness"],
                    "criticality": ["criticality", "value_score"],
                    "value": ["value", "asset_value"],
                    "severity": ["severity", "risk_severity"],
                    "likelihood": ["likelihood", "probability"],
                    "impact": ["impact", "threat_impact"],
                }
                for alias in aliases.get(column, []):
                    if alias in row:
                        value = row[alias]
                        break
            if column == "asset" and asset_names and value is not None and str(value) not in asset_names:
                continue
            record[column] = value
        if record:
            normalized.append(record)
    return normalized


def _validate_asset_references(state: dict) -> bool:
    asset_names = {str(asset.get("name")) for asset in state.get("assets", []) if isinstance(asset, dict) and asset.get("name")}
    for domain_name in ("vulnerabilities", "threats", "incidents", "controls"):
        for row in state.get(domain_name, []):
            if not isinstance(row, dict):
                continue
            asset_value = row.get("asset")
            if asset_value is None and domain_name in {"vulnerabilities", "threats", "incidents", "controls"}:
                continue
            if asset_value is not None and str(asset_value) not in asset_names:
                return False
    return True


def _domain_table(state: dict, domain_name: str, expected_columns: list[str]) -> pd.DataFrame:
    rows = state.get(domain_name, [])
    asset_names = {str(asset.get("name")) for asset in state.get("assets", []) if isinstance(asset, dict) and asset.get("name")}
    normalized = _normalize_domain_rows(rows, expected_columns, asset_names)
    return pd.DataFrame(normalized, columns=expected_columns)


def _risk_assessment_for_state(state: dict) -> dict:
    return calculate_risk(
        state.get("assets", []),
        state.get("vulnerabilities", []),
        state.get("threats", []),
        state.get("incidents", []),
        state.get("controls", []),
    )


def _build_orchestration_trace(
    state: dict,
    assessment: dict,
    event_type: str | None = None,
    remediation_id: str | None = None,
) -> list[dict]:
    steps: list[dict] = [
        {
            "stage": "OBSERVE",
            "action": "Generate current security state",
            "input": {"asset_count": len(state.get("assets", [])), "synthetic": state.get("synthetic", True)},
            "outcome": "Fresh state loaded",
            "success": True,
        },
        {
            "stage": "ASSESS",
            "action": "Calculate modeled risk",
            "input": {"score": assessment.get("overall_risk_score", 0.0)},
            "outcome": assessment.get("summary", "Risk assessment completed"),
            "success": True,
        },
    ]

    gaps = prioritize_security_gaps(assessment)
    steps.append(
        {
            "stage": "GAP PRIORITIZATION",
            "action": "Rank security gaps",
            "input": {"gap_count": len(gaps)},
            "outcome": gaps[0]["name"] if gaps else "No gap identified",
            "success": True,
        }
    )

    optimizer = optimize_investments(assessment, state.get("investments", []), 180000)
    steps.append(
        {
            "stage": "OPTIMIZE",
            "action": "Select investments within budget",
            "input": {"budget": 180000, "selected_count": len(optimizer.get("selected_investments", []))},
            "outcome": f"Allocated ${optimizer.get('total_cost', 0):,.0f}",
            "success": True,
        }
    )

    if event_type:
        event_result = simulate_security_event(state, event_type)
        steps.append(
            {
                "stage": "SIMULATE EVENT",
                "action": f"Execute {event_type}",
                "input": {"event_type": event_type},
                "outcome": event_result["message"],
                "success": True,
            }
        )

    if remediation_id:
        rem_result = apply_remediation(state, remediation_id)
        steps.append(
            {
                "stage": "REMEDIATE",
                "action": f"Apply {remediation_id}",
                "input": {"remediation_id": remediation_id},
                "outcome": rem_result["message"],
                "success": True,
            }
        )

    return steps


def _backend_health() -> dict:
    try:
        response = httpx.get(f"{os.getenv('CYBERRISK_API_URL', 'http://localhost:8000').rstrip('/')}/health", timeout=1.5)
        if response.status_code == 200:
            payload = response.json()
            return {"status": payload.get("status", "healthy"), "service": payload.get("service", "cyberrisk-api")}
    except Exception:
        return {"status": "demo-mode", "service": "local-demo"}
    return {"status": "demo-mode", "service": "local-demo"}


def _risk_pill(level: str) -> str:
    level_key = str(level or "Low").lower()
    if level_key in {"critical"}:
        return "pill-critical"
    if level_key in {"high"}:
        return "pill-high"
    if level_key in {"moderate"}:
        return "pill-moderate"
    return "pill-low"


def _render_kpi_card(label: str, value: str, context: str, tone: str = "neutral") -> None:
    st.markdown(
        f"""
        <div class="metric-card">
          <div class="metric-label">{label}</div>
          <div class="metric-value">{value}</div>
          <div class="metric-context">{context}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


if "state" not in st.session_state:
    st.session_state.state = _initial_state()
if "baseline_assessment" not in st.session_state:
    st.session_state.baseline_assessment = _risk_assessment_for_state(st.session_state.state)
if "current_assessment" not in st.session_state:
    st.session_state.current_assessment = copy.deepcopy(st.session_state.baseline_assessment)
if "orchestration_trace" not in st.session_state:
    st.session_state.orchestration_trace = _build_orchestration_trace(st.session_state.state, st.session_state.current_assessment)

st.markdown(CUSTOM_CSS, unsafe_allow_html=True)

health = _backend_health()
status_label = "LIVE" if health.get("status") == "healthy" else "DEMO"
status_class = "status-live" if health.get("status") == "healthy" else "status-demo"

st.markdown(
    f"""
    <div class="topbar">
      <div>
        <div class="eyebrow">CYBERRISK INTELLIGENCE</div>
        <h1>Continuous Cyber Risk Quantification and Investment Optimization</h1>
        <div class="header-subtitle">Executive view of the current modeled security posture and budget strategy.</div>
      </div>
      <div>
        <div class="status-pill {status_class}">{status_label}</div>
      </div>
    </div>
    """,
    unsafe_allow_html=True,
)

with st.sidebar:
    st.header("Controls")
    budget = st.number_input("Available security budget", min_value=0.0, value=180000.0, step=5000.0)
    event_type = st.selectbox(
        "Simulate security event",
        ["critical_vulnerability", "phishing_campaign", "control_failure"],
    )
    remediation_id = st.selectbox(
        "Apply remediation",
        ["patch-vpn", "mfa-strengthening"],
    )

    col_a, col_b = st.columns(2)
    with col_a:
        if st.button("Refresh state"):
            st.session_state.state = _initial_state()
            st.session_state.current_assessment = _risk_assessment_for_state(st.session_state.state)
            st.session_state.baseline_assessment = copy.deepcopy(st.session_state.current_assessment)
            st.session_state.orchestration_trace = _build_orchestration_trace(st.session_state.state, st.session_state.current_assessment)
    with col_b:
        if st.button("Reset baseline"):
            st.session_state.state = _initial_state()
            st.session_state.current_assessment = _risk_assessment_for_state(st.session_state.state)
            st.session_state.baseline_assessment = copy.deepcopy(st.session_state.current_assessment)
            st.session_state.orchestration_trace = _build_orchestration_trace(st.session_state.state, st.session_state.current_assessment)

    if st.button("Simulate event"):
        result = simulate_security_event(st.session_state.state, event_type)
        st.session_state.state = result["state"]
        st.session_state.current_assessment = result["risk_assessment"]
        st.session_state.orchestration_trace = _build_orchestration_trace(
            st.session_state.state,
            st.session_state.current_assessment,
            event_type=event_type,
        )

    if st.button("Apply remediation"):
        result = apply_remediation(st.session_state.state, remediation_id)
        st.session_state.state = result["state"]
        st.session_state.current_assessment = result["residual_risk"]
        st.session_state.orchestration_trace = _build_orchestration_trace(
            st.session_state.state,
            st.session_state.current_assessment,
            remediation_id=remediation_id,
        )

    st.markdown("---")
    st.caption("Demonstration environment")
    st.write("Synthetic telemetry is clearly labeled and should not be treated as live production data.")

state = st.session_state.state
assessment = st.session_state.current_assessment
gaps = prioritize_security_gaps(assessment)
opt = optimize_investments(assessment, state.get("investments", []), budget)

risk_score = float(assessment.get("overall_risk_score", 0.0))
risk_level = assessment.get("risk_level", "Low")
critical_gap_count = sum(1 for gap in gaps if str(gap.get("severity", "Low")).lower() in {"high", "critical"})
selected_cost = float(opt.get("total_cost", 0.0))
remaining_budget = float(opt.get("remaining_budget", 0.0))

st.markdown('<div class="section-panel">', unsafe_allow_html=True)
metric_cols = st.columns(4)
with metric_cols[0]:
    _render_kpi_card("Modeled risk", f"{risk_score:.1f}", f"{risk_level} posture")
with metric_cols[1]:
    _render_kpi_card("Assets assessed", str(len(state.get("assets", []))), "Current security estate")
with metric_cols[2]:
    _render_kpi_card("Priority findings", str(critical_gap_count), "High and critical gaps")
with metric_cols[3]:
    _render_kpi_card("Budget allocation", f"${selected_cost:,.0f}", f"${remaining_budget:,.0f} remaining")
st.markdown('</div>', unsafe_allow_html=True)

overview = st.tabs(["Overview", "Risk intelligence", "Prioritization", "Budget", "Monitoring", "Remediation", "Analyst"])

with overview[0]:
    st.markdown('<div class="section-panel">', unsafe_allow_html=True)
    st.markdown('<p class="section-title">Executive security summary</p>', unsafe_allow_html=True)
    summary_cols = st.columns(3)
    with summary_cols[0]:
        st.metric("Overall risk score", f"{risk_score:.2f}/100")
    with summary_cols[1]:
        baseline_score = float(st.session_state.baseline_assessment.get("overall_risk_score", risk_score))
        st.metric("Change vs baseline", f"{risk_score - baseline_score:+.2f}")
    with summary_cols[2]:
        st.metric("Budget utilization", f"{min(100.0, (selected_cost / max(budget, 1.0)) * 100):.0f}%")
    st.write(assessment.get("summary", "No summary available."))
    st.markdown('</div>', unsafe_allow_html=True)

    if assessment.get("risk_factors"):
        factors_df = pd.DataFrame(assessment["risk_factors"])
        st.markdown('<div class="section-panel">', unsafe_allow_html=True)
        st.markdown('<p class="section-title">Top risk drivers</p>', unsafe_allow_html=True)
        st.bar_chart(factors_df.set_index("factor")["score"], width="stretch")
        st.markdown('</div>', unsafe_allow_html=True)

with overview[1]:
    asset_risks = pd.DataFrame(assessment.get("asset_risks", []))
    st.markdown('<div class="section-panel">', unsafe_allow_html=True)
    st.markdown('<p class="section-title">Asset risk profile</p>', unsafe_allow_html=True)
    if asset_risks.empty:
        st.info("No asset risk data is available for the current state.")
    else:
        bar_df = asset_risks[["asset", "score"]].rename(columns={"asset": "Asset", "score": "Risk score"}).set_index("Asset")
        st.bar_chart(bar_df, width="stretch")

        severity_summary = asset_risks["risk_level"].value_counts().rename_axis("Risk class").reset_index(name="count")
        left_col, right_col = st.columns([1.3, 1.7])
        with left_col:
            for _, row in severity_summary.iterrows():
                level = str(row["Risk class"])
                count = int(row["count"])
                st.markdown(
                    f"<div class='insight-pill { _risk_pill(level) }'>{level}: {count}</div>",
                    unsafe_allow_html=True,
                )
        with right_col:
            st.dataframe(asset_risks[["asset", "score", "risk_level"]], width="stretch")
    st.markdown('</div>', unsafe_allow_html=True)

with overview[2]:
    st.markdown('<div class="section-panel">', unsafe_allow_html=True)
    st.markdown('<p class="section-title">Security gap prioritization</p>', unsafe_allow_html=True)
    if gaps:
        gaps_df = pd.DataFrame(gaps)[["priority", "affected_asset", "name", "severity", "risk_contribution"]]
        gaps_df = gaps_df.rename(columns={
            "priority": "Priority",
            "affected_asset": "Asset",
            "name": "Gap",
            "severity": "Severity",
            "risk_contribution": "Risk contribution",
        })
        st.dataframe(gaps_df, width="stretch")
    else:
        st.info("No material gaps were identified in the current model.")
    st.markdown('</div>', unsafe_allow_html=True)

with overview[3]:
    st.markdown('<div class="section-panel">', unsafe_allow_html=True)
    st.markdown('<p class="section-title">Recommended investment allocation</p>', unsafe_allow_html=True)
    budget_cols = st.columns(4)
    with budget_cols[0]:
        st.metric("Available budget", f"${budget:,.0f}")
    with budget_cols[1]:
        st.metric("Selected portfolio", f"${selected_cost:,.0f}")
    with budget_cols[2]:
        st.metric("Remaining budget", f"${remaining_budget:,.0f}")
    with budget_cols[3]:
        st.metric("Risk reduction estimate", f"{float(opt.get('risk_reduction_estimate', 0.0)):.2f}")

    if opt.get("selected_investments"):
        selected_df = pd.DataFrame(opt["selected_investments"])
        st.progress(min(1.0, selected_cost / max(budget, 1.0)), text=f"Budget utilization: {min(100.0, (selected_cost / max(budget, 1.0)) * 100):.0f}%")
        st.dataframe(selected_df.reindex(columns=["name", "asset", "category", "cost", "expected_risk_reduction"], fill_value=""), width="stretch")
    else:
        st.info("No investments fit under the current budget allocation.")
    st.markdown('</div>', unsafe_allow_html=True)

with overview[4]:
    incidents_df = _domain_table(state, "incidents", INCIDENT_COLUMNS)
    st.markdown('<div class="section-panel">', unsafe_allow_html=True)
    st.markdown('<p class="section-title">Security event monitoring</p>', unsafe_allow_html=True)
    st.caption("Synthetic event simulation only — this view does not represent live production telemetry.")
    if incidents_df.empty:
        st.info("No incident records are present in the current state.")
    else:
        st.dataframe(incidents_df, width="stretch")
    st.markdown('</div>', unsafe_allow_html=True)

with overview[5]:
    st.markdown('<div class="section-panel">', unsafe_allow_html=True)
    st.markdown('<p class="section-title">Remediation center</p>', unsafe_allow_html=True)
    current_controls = _domain_table(state, "controls", CONTROL_COLUMNS)
    rem_cols = st.columns(3)
    with rem_cols[0]:
        st.metric("Current risk score", f"{risk_score:.2f}")
    with rem_cols[1]:
        previous_score = float(st.session_state.baseline_assessment.get("overall_risk_score", risk_score))
        st.metric("Before baseline", f"{previous_score:.2f}")
    with rem_cols[2]:
        st.metric("Current risk class", risk_level)

    if current_controls.empty:
        st.info("No control records are available for the current assessment.")
    else:
        st.dataframe(current_controls, width="stretch")
    st.markdown('</div>', unsafe_allow_html=True)

with overview[6]:
    st.markdown('<div class="section-panel">', unsafe_allow_html=True)
    st.markdown('<p class="section-title">AI security analyst</p>', unsafe_allow_html=True)
    question = st.text_input("Ask about the current state", value="Why is the current risk score high?")
    if st.button("Analyze"):
        response = answer_question(
            question,
            state=state,
            risk_assessment=assessment,
            gaps=gaps,
            optimizer_result=opt,
        )
        st.markdown(f"<div class='section-panel'><p class='section-title'>Response</p>{response['answer']}</div>", unsafe_allow_html=True)
        st.json(response["evidence"])
    st.markdown('</div>', unsafe_allow_html=True)

st.markdown('<div class="section-panel">', unsafe_allow_html=True)
st.markdown('<p class="section-title">Operational trace</p>', unsafe_allow_html=True)
trace_df = pd.DataFrame(st.session_state.orchestration_trace)
if trace_df.empty:
    st.info("No orchestration trace is available yet.")
else:
    st.dataframe(trace_df, width="stretch")
st.markdown('</div>', unsafe_allow_html=True)

st.warning("This dashboard uses synthetic data for demonstration purposes and does not represent a calibrated breach probability or live production telemetry.")
