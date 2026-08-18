from urllib.parse import urlparse

from fastapi import FastAPI
from pydantic import BaseModel, Field, field_validator

from cli import analyze as analyze_security
from models import AnalysisResult


MAX_MESSAGE_LENGTH = 5000
MAX_URL_LENGTH = 2048

ALLOWED_URL_SCHEMES = {"http", "https"}


app = FastAPI(
    title="Digital Safety Guardian",
    description=(
        "A security analysis API for detecting social engineering, "
        "suspicious URLs, and attack patterns."
    ),
    version="0.3.0",
)


class AnalyzeRequest(BaseModel):
    message: str = Field(
        min_length=1,
        max_length=MAX_MESSAGE_LENGTH,
    )

    url: str | None = None

    @field_validator("message")
    @classmethod
    def validate_message(cls, value: str) -> str:
        if not value.strip():
            raise ValueError(
                "Message must contain at least one non-whitespace character."
            )

        return value

    @field_validator("url")
    @classmethod
    def validate_url(cls, value: str | None) -> str | None:
        if value is None:
            return None

        value = value.strip()

        if not value:
            raise ValueError(
                "URL must not be empty or whitespace-only."
            )

        if len(value) > MAX_URL_LENGTH:
            raise ValueError(
                f"URL must not exceed {MAX_URL_LENGTH} characters."
            )

        parsed = urlparse(value)

        if parsed.scheme.lower() not in ALLOWED_URL_SCHEMES:
            raise ValueError(
                "URL must use HTTP or HTTPS."
            )

        if not parsed.netloc:
            raise ValueError(
                "URL must contain a valid host."
            )

        return value


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
