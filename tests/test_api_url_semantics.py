from fastapi.testclient import TestClient

from main import app


client = TestClient(app)


def test_accepts_https_url():

    response = client.post(
        "/analyze",
        json={
            "message": "Please check this website.",
            "url": "https://example.com",
        },
    )

    assert response.status_code == 200


def test_accepts_http_url():

    response = client.post(
        "/analyze",
        json={
            "message": "Please check this website.",
            "url": "http://example.com",
        },
    )

    assert response.status_code == 200


def test_rejects_url_without_scheme():

    response = client.post(
        "/analyze",
        json={
            "message": "Please check this website.",
            "url": "example.com",
        },
    )

    assert response.status_code == 422


def test_rejects_unsupported_url_scheme():

    response = client.post(
        "/analyze",
        json={
            "message": "Please check this link.",
            "url": "ftp://example.com",
        },
    )

    assert response.status_code == 422


def test_rejects_javascript_scheme():

    response = client.post(
        "/analyze",
        json={
            "message": "Please check this link.",
            "url": "javascript:alert(1)",
        },
    )

    assert response.status_code == 422
