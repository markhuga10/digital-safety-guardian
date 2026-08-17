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
        "URGENT! Verify your account immediately "
        "and send the processing fee!",
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
        "Hello, I hope you are having a great day."
    )

    assert result["message_findings"] == []

    assert result["message_risk"]["score"] == 0
    assert result["message_risk"]["level"] == "MINIMAL"

    assert result["overall_risk"]["score"] == 0
    assert result["overall_risk"]["level"] == "MINIMAL"


def test_cli_suspicious_url():

    result = analyze(
        "Please check this website.",
        "http://192.168.1.10/login"
    )

    assert result["url_findings"]

    assert result["url_risk"]["score"] > 0

    assert result["overall_risk"]["score"] > 0


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

    output = capsys.readouterr().out

    assert "DIGITAL SAFETY GUARDIAN" in output
    assert "MESSAGE RISK" in output
    assert "OVERALL RISK" in output
    assert "21/100" in output
    assert "LOW" in output
