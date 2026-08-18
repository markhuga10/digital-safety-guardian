from urllib.parse import urlparse
from pathlib import Path
import ipaddress
import re

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator

from cli import analyze as analyze_security
from models import AnalysisResult


MAX_MESSAGE_LENGTH = 5000
MAX_URL_LENGTH = 2048

ALLOWED_URL_SCHEMES = {"http", "https"}

HOSTNAME_PATTERN = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:[A-Za-z0-9]"
    r"(?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"\.)+"
    r"[A-Za-z]{2,63}$"
)

BASE_DIR = Path(__file__).resolve().parent
FRONTEND_DIR = BASE_DIR / "frontend"


app = FastAPI(
    title="Digital Safety Guardian",
    description=(
        "A security analysis API for detecting social engineering, "
        "suspicious URLs, and attack patterns."
    ),
    version="0.3.0",
)


app.mount(
    "/static",
    StaticFiles(directory=FRONTEND_DIR),
    name="static",
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

        hostname = parsed.hostname

        if not hostname:
            raise ValueError(
                "URL must contain a valid host."
            )

        try:
            ipaddress.ip_address(hostname)
            return value
        except ValueError:
            pass

        if not HOSTNAME_PATTERN.fullmatch(hostname):
            raise ValueError(
                "URL must contain a valid hostname."
            )

        return value


@app.exception_handler(Exception)
async def internal_error_handler(
    request: Request,
    exc: Exception,
):
    return JSONResponse(
        status_code=500,
        content={
            "detail": (
                "An internal error occurred "
                "while processing the request."
            )
        },
    )


@app.get("/")
def home():
    return {
        "application": "Digital Safety Guardian",
        "version": "0.3.0",
        "status": "running",
    }


@app.get(
    "/dashboard",
    response_class=HTMLResponse,
)
def dashboard():
    return FileResponse(
        FRONTEND_DIR / "index.html"
    )


@app.post(
    "/analyze",
    response_model=AnalysisResult,
)
def analyze(request: AnalyzeRequest):
    return analyze_security(
        request.message,
        request.url,
    )
