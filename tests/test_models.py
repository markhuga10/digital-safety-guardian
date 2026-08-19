import pytest

from models import (
    Finding,
    RiskAssessment,
    Recommendations,
    AnalysisResult,
)


def test_finding_accepts_valid_data():
    finding = Finding(
        category="urgency",
        pattern=r"\burgent\b",
    )

    assert finding.category == "urgency"
    assert finding.pattern == r"\burgent\b"


def test_finding_accepts_description():
    finding = Finding(
        category="payment_request",
        pattern="send money",
        description="The message requests payment.",
    )

    assert finding.description == "The message requests payment."


def test_risk_assessment_accepts_valid_score():
    risk = RiskAssessment(
        score=50,
        level="MODERATE",
    )

    assert risk.score == 50
    assert risk.level == "MODERATE"


def test_risk_assessment_rejects_score_above_100():
    with pytest.raises(ValueError):
        RiskAssessment(
            score=101,
            level="HIGH",
        )


def test_risk_assessment_rejects_negative_score():
    with pytest.raises(ValueError):
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
    assert result.attack_patterns == ["payment_scam"]
    assert result.fraud_category == "unknown"


def test_analysis_result_accepts_fraud_category():
    result = AnalysisResult(
        message_findings=[],
        message_risk=RiskAssessment(
            score=60,
            level="HIGH",
        ),
        url_findings=[],
        url_risk=RiskAssessment(
            score=15,
            level="MINIMAL",
        ),
        overall_risk=RiskAssessment(
            score=42,
            level="MODERATE",
        ),
        attack_patterns=[
            "credential_phishing",
            "impersonation",
        ],
        fraud_category="credential_phishing",
        recommendations=Recommendations(),
    )

    assert result.fraud_category == "credential_phishing"
