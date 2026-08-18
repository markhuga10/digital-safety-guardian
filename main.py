from fastapi import FastAPI
from pydantic import BaseModel

from cli import analyze as analyze_security
from models import AnalysisResult


app = FastAPI(
    title="Digital Safety Guardian",
    description=(
        "A security analysis API for detecting social engineering, "
        "suspicious URLs, and attack patterns."
    ),
    version="0.3.0",
)


class AnalyzeRequest(BaseModel):
    message: str
    url: str | None = None


@app.get("/")
def home():
    return {
        "application": "Digital Safety Guardian",
        "version": "0.3.0",
        "status": "running",
    }


@app.post(
    "/analyze",
    response_model=AnalysisResult,
)
def analyze(request: AnalyzeRequest):

    return analyze_security(
        request.message,
        request.url,
    )
