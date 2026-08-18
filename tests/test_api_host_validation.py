from fastapi.testclient import TestClient

from main import app


client = TestClient(app)


def test_accepts_normal_hostname():

    response = client.post(
        "/analyze",
        json={
            "message": "Please check this website.",
            "url": "https://example.com",
        },
    )

    assert response.status_code == 200


def test_accepts_hostname_with_subdomain():

    response = client.post(
        "/analyze",
        json={
            "message": "Please check this website.",
            "url": "https://login.example.com",
        },
    )

    assert response.status_code == 200


def test_accepts_ip_address_host():

    response = client.post(
        "/analyze",
        json={
            "message": "Please check this address.",
            "url": "http://192.168.1.10",
        },
    )

    assert response.status_code == 200


def test_rejects_missing_hostname():

    response = client.post(
        "/analyze",
        json={
            "message": "Please check this link.",
            "url": "https:///path",
        },
    )

    assert response.status_code == 422


def test_rejects_malformed_hostname():

    response = client.post(
        "/analyze",
        json={
            "message": "Please check this link.",
            "url": "https://.",
        },
    )

    assert response.status_code == 422


def test_rejects_hostname_with_invalid_characters():

    response = client.post(
        "/analyze",
        json={
            "message": "Please check this link.",
            "url": "https://example .com",
        },
    )

    assert response.status_code == 422
