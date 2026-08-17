from url_detector import analyze_url


def test_google_is_trusted():
    findings = analyze_url("https://google.com")

    assert findings == []


def test_detects_lookalike_domain():
    findings = analyze_url("https://goggle.com")

    categories = [finding["category"] for finding in findings]

    assert "lookalike_domain" in categories


def test_detects_http():
    findings = analyze_url("http://example.com")

    categories = [finding["category"] for finding in findings]

    assert "insecure_protocol" in categories


def test_detects_ip_address():
    findings = analyze_url("http://192.168.1.50")

    categories = [finding["category"] for finding in findings]

    assert "ip_address_host" in categories


def test_detects_suspicious_keyword():
    findings = analyze_url("https://example.com/login")

    categories = [finding["category"] for finding in findings]

    assert "suspicious_keyword" in categories


def test_detects_embedded_credentials():
    findings = analyze_url(
        "https://admin:password@example.com"
    )

    categories = [finding["category"] for finding in findings]

    assert "embedded_credentials" in categories


def test_detects_excessive_subdomains():
    findings = analyze_url(
        "https://login.account.verify.secure.example.com"
    )

    categories = [finding["category"] for finding in findings]

    assert "excessive_subdomains" in categories
