CATEGORY_SCORES = {
    "urgency": 15,
    "credential_request": 30,
    "payment_request": 20,
    "threat_language": 20,
    "social_engineering": 15,
}


def calculate_risk(findings):

    score = 0

    for finding in findings:

        category = finding["category"]

        score += CATEGORY_SCORES.get(category, 0)

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

