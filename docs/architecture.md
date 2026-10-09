# CyberRisk Quantification

## Objective
Continuously quantify cyber risk, prioritize security gaps, and optimize
security investments under a defined budget.

## Required security data domains
1. Assets
2. Vulnerabilities
3. Threats
4. Incidents
5. Security controls

## Project structure
- backend/contracts.py: shared team interfaces
- backend/core/: risk engine, prioritizer and optimizer
- backend/data/: synthetic security data generation
- backend/services/: monitoring and AI orchestration
- backend/main.py: FastAPI backend
- app.py: Streamlit dashboard
- tests/: automated tests

## Engineering principles
- Risk calculations must be explainable and deterministic.
- Investment selection must respect the available budget.
- Avoid double-counting overlapping risk-reduction benefits.
- Use real platform outputs as evidence for AI explanations.
- Label synthetic data clearly.
- Treat risk scores as modeled indicators, not calibrated probabilities.

## Team coordination
Coordinate changes to shared interfaces before merging feature branches.
