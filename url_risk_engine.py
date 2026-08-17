URL_CATEGORY_SCORES = {
    "insecure_protocol": 15,
    "ip_address_host": 15,
    "embedded_credentials": 25,
    "suspicious_keyword": 10,
    "excessive_subdomains": 15,
    "lookalike_domain": 35,
    "invalid_url": 0,
}


def calculate_url_risk(findings):

    score = 0

    for finding in findings:

        category = finding.get("category")

        score += URL_CATEGORY_SCORES.get(category, 0)

    score = min(score, 100)

    if score >= 80:
        level = "CRITICAL"

    elif score >= 60:
        level = "HIGH"

    elif score >= 40:
        level = "MODERATE"

    elif score >= 20:
        level = "LOW"

    else:
        level = "MINIMAL"

    return {
        "score": score,
        "level": level
    }
