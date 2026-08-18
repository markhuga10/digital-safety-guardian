from pydantic import ValidationError
import pytest

from models import (
    AnalysisResult,
    Finding,
    Recommendations,
    RiskAssessment,
)


def test_finding_accepts_valid_data():
    finding = Finding(
        category="urgency",
        pattern=r"\burgent\b",
    )

    assert finding.category == "urgency"
    assert finding.pattern == r"\burgent\b"
    assert finding.description is None


def test_finding_accepts_description():
    finding = Finding(
        category="insecure_protocol",
        description="The URL uses HTTP instead of HTTPS.",
    )

    assert finding.category == "insecure_protocol"
    assert finding.description == "The URL uses HTTP instead of HTTPS."


def test_risk_assessment_accepts_valid_score():
    risk = RiskAssessment(
        score=75,
        level="HIGH",
    )

    assert risk.score == 75
    assert risk.level == "HIGH"


def test_risk_assessment_rejects_score_above_100():
    with pytest.raises(ValidationError):
        RiskAssessment(
            score=101,
            level="CRITICAL",
        )


def test_risk_assessment_rejects_negative_score():
    with pytest.raises(ValidationError):
        RiskAssessment(
            score=-1,
            level="MINIMAL",
        )


def test_recommendations_accepts_lists():
    recommendations = Recommendations(
        explanations=["The message creates urgency."],
        recommendations=["Verify the request."],
        priority_actions=["Do not act immediately."],
    )

    assert len(recommendations.explanations) == 1
    assert len(recommendations.recommendations) == 1
    assert len(recommendations.priority_actions) == 1


def test_analysis_result_accepts_complete_result():
    result = AnalysisResult(
        message_findings=[
            Finding(
                category="urgency",
                pattern=r"\burgent\b",
            )
        ],
        message_risk=RiskAssessment(
            score=20,
            level="LOW",
        ),
        url_findings=[],
        url_risk=RiskAssessment(
            score=0,
            level="MINIMAL",
        ),
        overall_risk=RiskAssessment(
            score=12,
            level="LOW",
        ),
        attack_patterns=["payment_scam"],
        recommendations=Recommendations(
            explanations=["The message creates urgency."],
            recommendations=["Verify the request."],
            priority_actions=["Do not act immediately."],
        ),
    )

    assert result.message_risk.score == 20
    assert result.url_risk.score == 0
    assert result.overall_risk.level == "LOW"
    assert "payment_scam" in result.attack_patterns
