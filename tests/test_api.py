from fastapi.testclient import TestClient

from main import app


client = TestClient(app)


def test_home_endpoint():

    response = client.get("/")

    assert response.status_code == 200

    data = response.json()

    assert data["application"] == "Digital Safety Guardian"
    assert data["version"] == "0.3.0"
    assert data["status"] == "running"


def test_analyze_endpoint_with_message_only():

    response = client.post(
        "/analyze",
        json={
            "message": "URGENT! Send money immediately!"
        }
    )

    assert response.status_code == 200

    data = response.json()

    assert data["message_risk"]["score"] == 35
    assert data["message_risk"]["level"] == "LOW"

    assert data["url_risk"]["score"] == 0
    assert data["url_risk"]["level"] == "MINIMAL"

    assert data["overall_risk"]["score"] == 21
    assert data["overall_risk"]["level"] == "LOW"


def test_analyze_endpoint_with_message_and_url():

    response = client.post(
        "/analyze",
        json={
            "message": (
                "URGENT! Verify your account immediately "
                "and send the processing fee!"
            ),
            "url": "http://example.com"
        }
    )

    assert response.status_code == 200

    data = response.json()

    assert data["message_risk"]["score"] == 50
    assert data["message_risk"]["level"] == "MODERATE"

    assert data["url_risk"]["score"] == 15
    assert data["url_risk"]["level"] == "MINIMAL"

    assert data["overall_risk"]["score"] == 36
    assert data["overall_risk"]["level"] == "LOW"


def test_analyze_endpoint_returns_attack_patterns():

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

    assert "attack_patterns" in data
    assert "credential_phishing" in data["attack_patterns"]
    assert "impersonation" in data["attack_patterns"]


def test_analyze_endpoint_returns_recommendations():

    response = client.post(
        "/analyze",
        json={
            "message": "URGENT! Send money immediately!"
        }
    )

    assert response.status_code == 200

    data = response.json()

    assert data["recommendations"]
    assert data["recommendations"]["explanations"]
    assert data["recommendations"]["recommendations"]
    assert data["recommendations"]["priority_actions"]


def test_analyze_endpoint_rejects_missing_message():

    response = client.post(
        "/analyze",
        json={}
    )

    assert response.status_code == 422
