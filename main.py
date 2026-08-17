from fastapi import FastAPI
from pydantic import BaseModel

from detector import analyze_message
from risk_engine import calculate_risk
from recommendation_engine import generate_recommendations
from url_detector import analyze_url
from url_risk_engine import calculate_url_risk
from combined_risk_engine import calculate_overall_risk


app = FastAPI(
    title="Digital Safety Guardian",
    description=(
        "A security analysis API for detecting social engineering "
        "and suspicious URLs."
    ),
    version="0.2.1"
)


class AnalyzeRequest(BaseModel):
    message: str
    url: str | None = None


@app.get("/")
def home():

    return {
        "application": "Digital Safety Guardian",
        "version": "0.2.1",
        "status": "running"
    }


@app.post("/analyze")
def analyze(request: AnalyzeRequest):

    # -------------------------
    # Message analysis
    # -------------------------

    message_findings = analyze_message(request.message)

    message_risk = calculate_risk(message_findings)

    recommendations = generate_recommendations(
        message_findings
    )

    # -------------------------
    # URL analysis
    # -------------------------

    url_findings = []

    url_risk = {
        "score": 0,
        "level": "MINIMAL"
    }

    if request.url:

        url_findings = analyze_url(request.url)

        url_risk = calculate_url_risk(
            url_findings
        )

    # -------------------------
    # Combined risk
    # -------------------------

    overall_risk = calculate_overall_risk(
        message_risk,
        url_risk
    )

    # -------------------------
    # Final response
    # -------------------------

    return {
        "message_risk": {
            "score": message_risk["score"],
            "level": message_risk["level"],
            "findings": message_findings
        },

        "url_risk": {
            "score": url_risk["score"],
            "level": url_risk["level"],
            "findings": url_findings
        },

        "overall_risk": {
            "score": overall_risk["score"],
            "level": overall_risk["level"]
        },

        "explanations": recommendations[
            "explanations"
        ],

        "recommendations": recommendations[
            "recommendations"
        ],

        "priority_actions": recommendations[
            "priority_actions"
        ]
    }
