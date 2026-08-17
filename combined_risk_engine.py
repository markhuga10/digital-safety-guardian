def calculate_overall_risk(message_risk, url_risk):

    message_score = message_risk.get("score", 0)
    url_score = url_risk.get("score", 0)

    # Message risk carries slightly more weight
    # because social engineering content can be dangerous
    # even when the URL itself appears relatively clean.

    overall_score = (
        (message_score * 0.60)
        + (url_score * 0.40)
    )

    overall_score = round(overall_score)

    overall_score = min(overall_score, 100)

    if overall_score >= 80:
        level = "CRITICAL"

    elif overall_score >= 60:
        level = "HIGH"

    elif overall_score >= 40:
        level = "MODERATE"

    elif overall_score >= 20:
        level = "LOW"

    else:
        level = "MINIMAL"

    return {
        "score": overall_score,
        "level": level
    }
