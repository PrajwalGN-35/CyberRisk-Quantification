import streamlit as st

st.set_page_config(
    page_title="CyberRisk Intelligence",
    page_icon="shield",
    layout="wide",
)

st.title("CyberRisk Intelligence")
st.caption(
    "Continuous Cyber Risk Quantification and Investment Optimization"
)

st.info(
    "Platform foundation initialized. Security analysis modules "
    "will be connected during implementation."
)

a, b, c = st.columns(3)
a.metric("Risk Engine", "In development")
b.metric("Investment Optimizer", "In development")
c.metric("Monitoring", "In development")

st.subheader("Platform Capabilities")
st.markdown(
    """
    - Analyze assets, vulnerabilities, threats, incidents and controls.
    - Quantify and explain cyber risk.
    - Prioritize security gaps and remediation.
    - Optimize security investments within a budget.
    - Reassess risk following new security events.
    - Provide evidence-based AI analysis.
    """
)
