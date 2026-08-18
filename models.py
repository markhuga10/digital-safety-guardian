from pydantic import BaseModel, Field
from typing import List


class Finding(BaseModel):
    category: str
    pattern: str | None = None
    description: str | None = None


class RiskAssessment(BaseModel):
    score: int = Field(ge=0, le=100)
    level: str


class Recommendations(BaseModel):
    explanations: List[str] = []
    recommendations: List[str] = []
    priority_actions: List[str] = []


class AnalysisResult(BaseModel):
    message_findings: List[Finding]
    message_risk: RiskAssessment

    url_findings: List[Finding]
    url_risk: RiskAssessment

    overall_risk: RiskAssessment

    attack_patterns: List[str]

    recommendations: Recommendations
