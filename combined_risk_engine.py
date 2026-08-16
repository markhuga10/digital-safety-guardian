def calculate_overall_risk(message_risk, url_risk):
    """
    Combine message and URL risk scores into one overall score.

    Message analysis carries 60% of the weight.
    URL analysis carries 40% of the weight.
    """

    message_score = message_risk.get("score", 0)
    url_score = url_risk.get("score", 0)

    overall_score = round(
        (message_score * 0.60) +
        (url_score * 0.40)
    )

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
