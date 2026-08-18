from fastapi.testclient import TestClient

from main import app


client = TestClient(app)


def test_accepts_valid_url():

    response = client.post(
        "/analyze",
        json={
            "message": "Please check this website.",
            "url": "https://example.com",
        },
    )

    assert response.status_code == 200


def test_accepts_request_without_url():

    response = client.post(
        "/analyze",
        json={
            "message": "Hello, how are you?",
        },
    )

    assert response.status_code == 200


def test_rejects_non_string_url():

    response = client.post(
        "/analyze",
        json={
            "message": "Please check this website.",
            "url": 12345,
        },
    )

    assert response.status_code == 422


def test_rejects_empty_url():

    response = client.post(
        "/analyze",
        json={
            "message": "Please check this website.",
            "url": "",
        },
    )

    assert response.status_code == 422


def test_rejects_whitespace_only_url():

    response = client.post(
        "/analyze",
        json={
            "message": "Please check this website.",
            "url": "   ",
        },
    )

    assert response.status_code == 422
