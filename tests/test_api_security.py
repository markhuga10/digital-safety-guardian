from fastapi.testclient import TestClient

from main import app


client = TestClient(app)


def test_analyze_rejects_missing_message():

    response = client.post(
        "/analyze",
        json={}
    )

    assert response.status_code == 422


def test_analyze_rejects_non_string_message():

    response = client.post(
        "/analyze",
        json={
            "message": 12345
        }
    )

    assert response.status_code == 422


def test_analyze_accepts_optional_url():

    response = client.post(
        "/analyze",
        json={
            "message": "Please check this link.",
            "url": "http://example.com"
        }
    )

    assert response.status_code == 200

    data = response.json()

    assert "url_risk" in data
    assert "overall_risk" in data


def test_analyze_returns_structured_response():

    response = client.post(
        "/analyze",
        json={
            "message": (
                "URGENT! Verify your account immediately "
                "and send your OTP!"
            )
        }
    )

    assert response.status_code == 200

    data = response.json()

    assert isinstance(data["message_risk"]["score"], int)
    assert 0 <= data["message_risk"]["score"] <= 100

    assert isinstance(data["overall_risk"]["score"], int)
    assert 0 <= data["overall_risk"]["score"] <= 100

    assert isinstance(data["attack_patterns"], list)
    assert isinstance(data["recommendations"], dict)


def test_analyze_declares_analysis_result_response_model():

    route = next(
        route
        for route in app.routes
        if getattr(route, "path", None) == "/analyze"
        and "POST" in getattr(route, "methods", set())
    )

    assert route.response_model is not None

    assert route.response_model.__name__ == "AnalysisResult"


def test_openapi_declares_analysis_result_schema():

    schema = app.openapi()

    response_schema = (
        schema["paths"]["/analyze"]["post"]
        ["responses"]["200"]
        ["content"]["application/json"]
        ["schema"]
    )

    assert response_schema == {
        "$ref": "#/components/schemas/AnalysisResult"
    }
