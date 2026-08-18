from fastapi.testclient import TestClient

from main import app


client = TestClient(app)


def test_dashboard_page_is_available():

    response = client.get("/dashboard")

    assert response.status_code == 200
    assert "DIGITAL SAFETY GUARDIAN" in response.text
    assert "ANALYZE" in response.text


def test_dashboard_page_contains_analysis_form():

    response = client.get("/dashboard")

    assert response.status_code == 200
    assert 'id="message"' in response.text
    assert 'id="url"' in response.text
    assert 'id="analyze-button"' in response.text


def test_dashboard_stylesheet_is_available():

    response = client.get("/static/style.css")

    assert response.status_code == 200
    assert "body" in response.text


def test_dashboard_javascript_is_available():

    response = client.get("/static/app.js")

    assert response.status_code == 200
    assert "fetch" in response.text
