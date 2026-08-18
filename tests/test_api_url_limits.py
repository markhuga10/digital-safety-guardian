from fastapi.testclient import TestClient

from main import app


client = TestClient(app)


def test_accepts_url_at_maximum_length():

    url = "https://" + ("a" * 2040)

    response = client.post(
        "/analyze",
        json={
            "message": "Please check this website.",
            "url": url,
        },
    )

    assert response.status_code == 200


def test_rejects_url_above_maximum_length():

    url = "https://" + ("a" * 2041)

    response = client.post(
        "/analyze",
        json={
            "message": "Please check this website.",
            "url": url,
        },
    )

    assert response.status_code == 422


def test_accepts_short_url():

    response = client.post(
        "/analyze",
        json={
            "message": "Please check this website.",
            "url": "https://example.com",
        },
    )

    assert response.status_code == 200
