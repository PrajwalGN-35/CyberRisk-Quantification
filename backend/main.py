from fastapi import FastAPI

app = FastAPI(
    title="CyberRisk Quantification API",
    description="Continuous cyber risk quantification and investment optimization",
    version="0.1.0",
)


@app.get("/health")
def health_check() -> dict[str, str]:
    return {
        "status": "healthy",
        "service": "cyberrisk-api",
    }
