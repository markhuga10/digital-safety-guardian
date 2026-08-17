from detector import analyze_message


def test_benign_message():
    findings = analyze_message(
        "Hi John, are we still meeting tomorrow at 10 AM?"
    )

    assert findings == []


def test_urgency_detection():
    findings = analyze_message(
        "Act immediately to restore your account."
    )

    categories = [finding["category"] for finding in findings]

    assert "urgency" in categories


def test_payment_request_detection():
    findings = analyze_message(
        "Please pay the processing fee immediately."
    )

    categories = [finding["category"] for finding in findings]

    assert "payment_request" in categories


def test_threat_language_detection():
    findings = analyze_message(
        "Your account has been blocked."
    )

    categories = [finding["category"] for finding in findings]

    assert "threat_language" in categories
