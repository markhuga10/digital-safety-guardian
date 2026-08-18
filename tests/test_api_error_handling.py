from fastapi.testclient import TestClient

import main


client = TestClient(
    main.app,
    raise_server_exceptions=False,
)


def test_internal_error_returns_controlled_response(monkeypatch):

    def failing_analysis(message, url=None):
        raise RuntimeError("database password=SECRET123")

    monkeypatch.setattr(
        main,
        "analyze_security",
        failing_analysis,
    )

    response = client.post(
        "/analyze",
        json={
            "message": "Hello, how are you?"
        },
    )

    assert response.status_code == 500

    data = response.json()

    assert data["detail"] == (
        "An internal error occurred while processing the request."
    )

    assert "SECRET123" not in response.text
    assert "RuntimeError" not in response.text
