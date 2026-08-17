from risk_engine import calculate_risk

def test_urgency_creates_risk():
    findings = [
        {
            "category": "urgency",
            "pattern": r"\bimmediately\b"
        }
    ]

    result = calculate_risk(findings)

    assert result["score"] == 15
    assert result["level"] == "MINIMAL"
