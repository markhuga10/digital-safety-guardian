from cli import analyze
from models import AnalysisResult


def test_full_analysis_pipeline_returns_valid_result():

    result = analyze(
        "URGENT! Verify your account immediately and send your OTP!",
        "http://example.com",
    )

    validated = AnalysisResult(**result)

    assert validated.message_risk.score == 60
    assert validated.message_risk.level == "HIGH"

    assert validated.url_risk.score == 15
    assert validated.url_risk.level == "MINIMAL"

    assert validated.overall_risk.score == 42
    assert validated.overall_risk.level == "MODERATE"

    assert "credential_phishing" in validated.attack_patterns
    assert "impersonation" in validated.attack_patterns

    assert validated.message_findings
    assert validated.url_findings

    assert validated.recommendations.explanations
    assert validated.recommendations.recommendations
    assert validated.recommendations.priority_actions


def test_full_analysis_pipeline_with_benign_message():

    result = analyze(
        "Hello, how are you?"
    )

    validated = AnalysisResult(**result)

    assert validated.message_risk.score == 0
    assert validated.message_risk.level == "MINIMAL"

    assert validated.url_risk.score == 0
    assert validated.url_risk.level == "MINIMAL"

    assert validated.overall_risk.score == 0
    assert validated.overall_risk.level == "MINIMAL"

    assert validated.attack_patterns == []

def test_full_analysis_pipeline_includes_threat_intelligence():

    result = analyze(
        "URGENT! Your bank account needs verification. "
        "Click the link and provide your OTP.",
        "http://example.com",
    )

    validated = AnalysisResult(**result)

    assert validated.threat_intelligence is not None

    intelligence = validated.threat_intelligence

    assert intelligence.fraud_type.value == "banking_fraud"

    assert intelligence.impersonated_entity == "Bank"

    assert intelligence.target == "Account credentials"

    assert intelligence.requested_action == (
        "Provide credentials or verification information"
    )

    assert intelligence.likely_impact == (
        "Bank account compromise and financial loss"
    )

    assert intelligence.confidence.value in {
        "medium",
        "high",
    }

    assert intelligence.evidence


def test_benign_analysis_has_low_confidence_threat_intelligence():

    result = analyze(
        "Hello, how are you?"
    )

    validated = AnalysisResult(**result)

    assert validated.threat_intelligence is not None

    intelligence = validated.threat_intelligence

    assert intelligence.fraud_type.value == "unknown"

    assert intelligence.confidence.value == "low"

    assert intelligence.impersonated_entity == "Unknown Entity"
