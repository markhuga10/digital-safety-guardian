from combined_risk_engine import calculate_overall_risk


def test_no_risk_is_minimal():
    result = calculate_overall_risk(
        {"score": 0},
        {"score": 0}
    )

    assert result["score"] == 0
    assert result["level"] == "MINIMAL"


def test_message_risk_only():
    result = calculate_overall_risk(
        {"score": 80},
        {"score": 0}
    )

    assert result["score"] == 48
    assert result["level"] == "MODERATE"


def test_url_risk_only():
    result = calculate_overall_risk(
        {"score": 0},
        {"score": 50}
    )

    assert result["score"] == 20
    assert result["level"] == "LOW"


def test_combines_message_and_url_risk():
    result = calculate_overall_risk(
        {"score": 80},
        {"score": 50}
    )

    assert result["score"] == 68
    assert result["level"] == "HIGH"


def test_overall_score_is_capped():
    result = calculate_overall_risk(
        {"score": 100},
        {"score": 100}
    )

    assert result["score"] <= 100
