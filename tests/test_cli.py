import json

from cli import analyze, main


def test_cli_analyze_message_only():

    result = analyze(
        "URGENT! Send money immediately!"
    )

    assert result["message_risk"]["score"] == 35
    assert result["message_risk"]["level"] == "LOW"

    assert result["url_risk"]["score"] == 0
    assert result["url_risk"]["level"] == "MINIMAL"

    assert result["overall_risk"]["score"] == 21
    assert result["overall_risk"]["level"] == "LOW"


def test_cli_analyze_message_and_url():

    result = analyze(
        "URGENT! Verify your account immediately and send the processing fee!",
        "http://example.com"
    )

    assert result["message_risk"]["score"] == 50
    assert result["message_risk"]["level"] == "MODERATE"

    assert result["url_risk"]["score"] == 15
    assert result["url_risk"]["level"] == "MINIMAL"

    assert result["overall_risk"]["score"] == 36
    assert result["overall_risk"]["level"] == "LOW"


def test_cli_benign_message():

    result = analyze(
        "Hello, how are you?"
    )

    assert result["message_risk"]["score"] == 0
    assert result["message_risk"]["level"] == "MINIMAL"

    assert result["overall_risk"]["score"] == 0
    assert result["overall_risk"]["level"] == "MINIMAL"


def test_cli_suspicious_url():

    result = analyze(
        "Please check this link",
        "http://example.com"
    )

    assert result["url_risk"]["score"] == 15
    assert result["url_risk"]["level"] == "MINIMAL"


def test_cli_recommendations_are_generated():

    result = analyze(
        "URGENT! Send money immediately!"
    )

    recommendations = result["recommendations"]

    assert recommendations["explanations"]
    assert recommendations["recommendations"]
    assert recommendations["priority_actions"]


def test_cli_main_analyze_command(capsys, monkeypatch):

    monkeypatch.setattr(
        "sys.argv",
        [
            "dsg",
            "analyze",
            "URGENT! Send money immediately!"
        ]
    )

    main()

    captured = capsys.readouterr()

    assert "DIGITAL SAFETY GUARDIAN" in captured.out
    assert "OVERALL RISK" in captured.out
    assert "Score: 21/100" in captured.out


def test_cli_json_output(capsys, monkeypatch):

    monkeypatch.setattr(
        "sys.argv",
        [
            "dsg",
            "analyze",
            "URGENT! Send money immediately!",
            "--json"
        ]
    )

    main()

    captured = capsys.readouterr()

    result = json.loads(captured.out)

    assert result["message_risk"]["score"] == 35
    assert result["message_risk"]["level"] == "LOW"

    assert result["url_risk"]["score"] == 0
    assert result["url_risk"]["level"] == "MINIMAL"

    assert result["overall_risk"]["score"] == 21
    assert result["overall_risk"]["level"] == "LOW"


def test_cli_json_output_with_url(capsys, monkeypatch):

    monkeypatch.setattr(
        "sys.argv",
        [
            "dsg",
            "analyze",
            "URGENT! Verify your account immediately and send the processing fee!",
            "--url",
            "http://example.com",
            "--json"
        ]
    )

    main()

    captured = capsys.readouterr()

    result = json.loads(captured.out)

    assert result["message_risk"]["score"] == 50
    assert result["message_risk"]["level"] == "MODERATE"

    assert result["url_risk"]["score"] == 15
    assert result["url_risk"]["level"] == "MINIMAL"

    assert result["overall_risk"]["score"] == 36
    assert result["overall_risk"]["level"] == "LOW"

    assert result["url_findings"]

    assert result["url_findings"][0]["category"] == (
        "insecure_protocol"
    )
def test_cli_detects_credential_phishing_pattern():

    result = analyze(
        "URGENT! Verify your account immediately and send your OTP!"
    )

    assert "credential_phishing" in result["attack_patterns"]


def test_cli_detects_payment_scam_pattern():

    result = analyze(
        "URGENT! Send money immediately to avoid account suspension."
    )

    assert "payment_scam" in result["attack_patterns"]


def test_cli_returns_no_attack_pattern_for_benign_message():

    result = analyze(
        "Hello, how are you?"
    )

    assert result["attack_patterns"] == []
