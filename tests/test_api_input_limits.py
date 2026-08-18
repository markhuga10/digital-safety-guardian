from fastapi.testclient import TestClient

from main import app


client = TestClient(app)


def test_accepts_message_at_maximum_length():

    message = "A" * 5000

    response = client.post(
        "/analyze",
        json={
            "message": message
        }
    )

    assert response.status_code == 200


def test_rejects_message_above_maximum_length():

    message = "A" * 5001

    response = client.post(
        "/analyze",
        json={
            "message": message
        }
    )

    assert response.status_code == 422


def test_accepts_short_message():

    response = client.post(
        "/analyze",
        json={
            "message": "Hello"
        }
    )

    assert response.status_code == 200
