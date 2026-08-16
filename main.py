from fastapi import FastAPI
from pydantic import BaseModel

from detector import analyze_message
from risk_engine import calculate_risk
from recommendation_engine import generate_recommendations

app = FastAPI(
    title="Digital Safety Guardian",
    version="0.1.0"
)


class MessageRequest(BaseModel):
    message: str


@app.post("/analyze")
def analyze(request: MessageRequest):

    findings = analyze_message(request.message)

    risk = calculate_risk(findings)

    recommendations = generate_recommendations(findings)

    return {
        "risk_score": risk["score"],
        "risk_level": risk["level"],
        "findings": findings,
        "explanations": recommendations["explanations"],
        "recommendations": recommendations["recommendations"],
        "priority_actions": recommendations["priority_actions"],
    }
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

