from unittest.mock import patch

from fastapi.testclient import TestClient

from api.main import app


def test_login_rejects_untrusted_origin():
    with TestClient(app) as client:
        response = client.post(
            "/auth/login",
            headers={"Origin": "https://untrusted.example"},
            json={"password": "test-password"},
        )

    assert response.status_code == 403


def test_login_rejects_invalid_password():
    with patch("api.main.verify_dashboard_password", return_value=False):
        with TestClient(app) as client:
            response = client.post(
                "/auth/login",
                headers={"Origin": "http://localhost:5173"},
                json={"password": "wrong-test-password"},
            )

    assert response.status_code == 401
    assert "aegismem_session" not in response.cookies


def test_login_sets_httponly_session_cookie():
    with patch("api.main.verify_dashboard_password", return_value=True), \
         patch("api.main.create_dashboard_session", return_value="mock-session-id"):
        with TestClient(app) as client:
            response = client.post(
                "/auth/login",
                headers={"Origin": "http://localhost:5173"},
                json={"password": "test-password"},
            )

    assert response.status_code == 200
    assert response.json() == {"authenticated": True}
    assert response.cookies.get("aegismem_session") == "mock-session-id"
    assert "httponly" in response.headers.get("set-cookie", "").lower()


def test_session_status_is_false_without_session():
    with patch("api.main.validate_dashboard_session", return_value=False):
        response = TestClient(app).get("/auth/session")

    assert response.status_code == 200
    assert response.json() == {"authenticated": False}


def test_logout_rejects_untrusted_origin():
    with TestClient(app) as client:
        response = client.post(
            "/auth/logout",
            headers={"Origin": "https://untrusted.example"},
        )

    assert response.status_code == 403


def test_logout_revokes_session_and_clears_cookie():
    with patch("api.main.revoke_dashboard_session") as revoke:
        with TestClient(app) as client:
            client.cookies.set("aegismem_session", "mock-session-id")
            response = client.post(
                "/auth/logout",
                headers={"Origin": "http://localhost:5173"},
            )

    assert response.status_code == 200
    assert response.json() == {"authenticated": False}
    revoke.assert_called_once_with("mock-session-id")
    assert "max-age=0" in response.headers.get("set-cookie", "").lower()
