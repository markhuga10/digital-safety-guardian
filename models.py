from pydantic import BaseModel, Field
from typing import List

from checkam_ng.threat_intelligence import ThreatIntelligence


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
    """
    Complete CheckAm-NG analysis result.

    Preserves the original Digital Safety Guardian
    analysis fields while adding fraud classification
    and structured threat intelligence.
    """

    message_findings: List[Finding]
    message_risk: RiskAssessment

    url_findings: List[Finding]
    url_risk: RiskAssessment

    overall_risk: RiskAssessment

    attack_patterns: List[str]

    fraud_category: str = "unknown"

    threat_intelligence: ThreatIntelligence | None = None

    recommendations: Recommendations
