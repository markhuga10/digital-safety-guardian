from fastapi.testclient import TestClient

from main import app


client = TestClient(app)


def test_dashboard_is_mobile_ready():

    response = client.get("/dashboard")

    assert response.status_code == 200

    assert 'name="viewport"' in response.text
    assert "width=device-width" in response.text
    assert "initial-scale=1.0" in response.text


def test_dashboard_uses_plain_language():

    response = client.get("/dashboard")

    assert response.status_code == 200

    assert "Suspicious Message" in response.text
    assert "Optional URL" in response.text
    assert "What DSG looks for" in response.text
    assert "Recommended response" in response.text
    assert "What to do next" in response.text


def test_dashboard_has_touch_friendly_primary_action():

    response = client.get("/dashboard")

    assert response.status_code == 200
    assert 'id="analyze-button"' in response.text
    assert "ANALYZE THREAT" in response.text


def test_dashboard_has_mobile_reset_action():

    response = client.get("/dashboard")

    assert response.status_code == 200
    assert 'id="reset-button"' in response.text
    assert "NEW ANALYSIS" in response.text
