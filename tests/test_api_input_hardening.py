from fastapi.testclient import TestClient

from main import app


client = TestClient(app)


def test_rejects_empty_message():

    response = client.post(
        "/analyze",
        json={
            "message": ""
        }
    )

    assert response.status_code == 422


def test_rejects_whitespace_only_message():

    response = client.post(
        "/analyze",
        json={
            "message": "   "
        }
    )

    assert response.status_code == 422


def test_accepts_normal_message():

    response = client.post(
        "/analyze",
        json={
            "message": "Hello, how are you?"
        }
    )

    assert response.status_code == 200


def test_rejects_invalid_url_type():

    response = client.post(
        "/analyze",
        json={
            "message": "Check this link.",
            "url": 12345
        }
    )

    assert response.status_code == 422
