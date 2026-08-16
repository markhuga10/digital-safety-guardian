from fastapi import FastAPI
from pydantic import BaseModel

from detector import analyze_message
from risk_engine import calculate_risk


app = FastAPI(
    title="Digital Safety Guardian",
    version="0.1.0"
)


class MessageRequest(BaseModel):
    message: str


@app.get("/")
def home():

    return {
        "application": "Digital Safety Guardian",
        "version": "0.1.0",
        "status": "running"
    }


@app.post("/analyze")
def analyze(request: MessageRequest):

    findings = analyze_message(request.message)

    risk = calculate_risk(findings)

    return {
        "risk_score": risk["score"],
        "risk_level": risk["level"],
        "findings": findings,
    }

