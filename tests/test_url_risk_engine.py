from url_risk_engine import calculate_url_risk


def test_no_url_findings_is_minimal():
    result = calculate_url_risk([])

    assert result["score"] == 0
    assert result["level"] == "MINIMAL"


def test_insecure_protocol_creates_risk():
    findings = [
        {
            "category": "insecure_protocol"
        }
    ]

    result = calculate_url_risk(findings)

    assert result["score"] == 15
    assert result["level"] == "MINIMAL"


def test_lookalike_domain_creates_risk():
    findings = [
        {
            "category": "lookalike_domain"
        }
    ]

    result = calculate_url_risk(findings)

    assert result["score"] == 35
    assert result["level"] == "LOW"


def test_multiple_url_indicators_increase_risk():
    findings = [
        {
            "category": "insecure_protocol"
        },
        {
            "category": "ip_address_host"
        },
        {
            "category": "suspicious_keyword"
        }
    ]

    result = calculate_url_risk(findings)

    assert result["score"] == 40
    assert result["level"] == "MODERATE"


def test_url_score_is_capped_at_100():
    findings = [
        {"category": "lookalike_domain"},
        {"category": "embedded_credentials"},
        {"category": "ip_address_host"},
        {"category": "excessive_subdomains"},
        {"category": "insecure_protocol"},
        {"category": "suspicious_keyword"},
    ]

    result = calculate_url_risk(findings)

    assert result["score"] <= 100
