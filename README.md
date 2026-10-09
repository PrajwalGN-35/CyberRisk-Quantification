# CyberRisk Quantification

CyberRisk Quantification is an AI-assisted cybersecurity risk intelligence platform that models the five core security domains: assets, vulnerabilities, threats, incidents, and controls. The system generates synthetic organizational security data, calculates explainable risk, prioritizes gaps, recommends investments within a constrained budget, simulates events, supports remediation planning, and exposes an AI analyst with a grounded fallback explanation engine.

## Architecture

- `backend/core/risk_engine.py`: deterministic risk calculation and explainability logic.
- `backend/core/gap_prioritizer.py`: prioritization of the most material security gaps.
- `backend/data/generator.py`: reproducible synthetic data generation.
- `backend/services/investment_optimizer.py`: budget-constrained investment selection.
- `backend/services/monitoring.py`: security event simulation and remediation application.
- `backend/services/analyst.py`: grounded analyst fallback that explains the modeled system using actual outputs.
- `backend/main.py`: FastAPI backend exposing the application endpoints.
- `app.py`: Streamlit dashboard for risk intelligence and operational workflow demonstration.
- `tests/test_integration.py`: end-to-end workflow validation for backend and analytics logic.

## Main capabilities

- Synthetic data generation for assets, vulnerabilities, threats, incidents, controls, and investments.
- Baseline risk assessment with explainable risk factors and asset-level scoring.
- Security gap prioritization based on modeled risk contributions.
- Budget-aware investment optimization using cost-benefit ranking.
- Event simulation that updates state and triggers reassessment.
- Remediation simulation that modifies underlying security posture and calculates residual risk.
- Deterministic AI analyst fallback using actual assessment output rather than invented numbers.
- Agentic orchestration trace showing real assessment and optimization stages in the dashboard.

## Technology stack

- Python 3.12
- FastAPI
- Pydantic
- Streamlit
- Pandas
- NumPy
- SciPy
- pytest
- httpx for FastAPI TestClient compatibility

## Prerequisites

- Python 3.12 installed.
- A local virtual environment recommended.
- Optional AI provider environment variables only if you later connect to an external LLM.

## Windows setup

```powershell
cd C:\Users\Prajwal G N\CyberRisk-Quantification
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

## Run the backend

```powershell
cd C:\Users\Prajwal G N\CyberRisk-Quantification
.\.venv\Scripts\Activate.ps1
uvicorn backend.main:app --host 0.0.0.0 --port 8000
```

Then open:

- http://localhost:8000/health
- http://localhost:8000/docs

## Run the dashboard

```powershell
cd C:\Users\Prajwal G N\CyberRisk-Quantification
.\.venv\Scripts\Activate.ps1
streamlit run app.py
```

## Run tests

```powershell
cd C:\Users\Prajwal G N\CyberRisk-Quantification
.\.venv\Scripts\Activate.ps1
python -m pytest -q
```

## Optional AI provider configuration

The application starts without an API key. If you add an external AI provider later, set values in `.env` using the existing template in `.env.example`:

```env
AI_PROVIDER=
AI_MODEL=
AI_API_KEY=
```

The current implementation prefers a deterministic fallback explanation engine so the system remains useful even when no AI API key is configured.

## Demo workflow

1. Launch the backend and dashboard.
2. Review the five security domains and current risk score.
3. Inspect the prioritized security gaps.
4. Adjust the budget and observe the recommended investment portfolio.
5. Simulate a critical event.
6. Reassess the model and review the explanation.
7. Apply remediation and inspect the residual risk.
8. Use the AI analyst box to ask operational questions grounded in real risk outputs.

## Known limitations

- The project intentionally uses synthetic data and not real breach probability calibration.
- The app is designed for product-style demonstration and educational use rather than production-grade telemetry ingestion.
- The AI analyst is fallback-grounded and deterministic unless an external provider is later configured intentionally.
