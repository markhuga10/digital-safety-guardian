from attack_pattern_engine import classify_attack_patterns


def test_no_findings_returns_no_attack_pattern():
    result = classify_attack_patterns([])

    assert result["patterns"] == []


def test_credential_phishing_pattern():
    findings = [
        {"category": "urgency"},
        {"category": "credential_request"},
        {"category": "social_engineering"},
    ]

    result = classify_attack_patterns(findings)

    assert "credential_phishing" in result["patterns"]


def test_payment_scam_pattern():
    findings = [
        {"category": "urgency"},
        {"category": "payment_request"},
    ]

    result = classify_attack_patterns(findings)

    assert "payment_scam" in result["patterns"]


def test_account_takeover_pattern():
    findings = [
        {"category": "threat_language"},
        {"category": "credential_request"},
    ]

    result = classify_attack_patterns(findings)

    assert "account_takeover" in result["patterns"]


def test_impersonation_pattern():
    findings = [
        {"category": "social_engineering"},
        {"category": "credential_request"},
    ]

    result = classify_attack_patterns(findings)

    assert "impersonation" in result["patterns"]


def test_multiple_attack_patterns():
    findings = [
        {"category": "urgency"},
        {"category": "credential_request"},
        {"category": "payment_request"},
        {"category": "social_engineering"},
    ]

    result = classify_attack_patterns(findings)

    assert "credential_phishing" in result["patterns"]
    assert "payment_scam" in result["patterns"]
    assert "impersonation" in result["patterns"]
