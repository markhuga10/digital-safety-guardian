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
