from unittest.mock import patch

from fastapi.testclient import TestClient

from api.main import app


def test_missing_owner_token_rejected_before_database_access():
    with patch("api.main.load_owner_token", return_value="test-secret"), \
         patch("core.security.owner_auth.load_owner_token", return_value="test-secret"), \
         patch("api.main.get_session") as get_session:
        response = TestClient(app).post(
            "/owner/memory/write",
            json={
                "memory_id": "auth-test",
                "content": "test",
                "authorization_id": "auth-test",
                "nonce": "auth-test",
            },
        )

    assert response.status_code == 401
    get_session.assert_not_called()


def test_invalid_owner_token_rejected_before_database_access():
    with patch("api.main.load_owner_token", return_value="expected-test-secret"), \
         patch("core.security.owner_auth.load_owner_token", return_value="expected-test-secret"), \
         patch("api.main.get_session") as get_session:
        response = TestClient(app).post(
            "/owner/memory/write",
            headers={"Authorization": "Bearer wrong-test-secret"},
            json={
                "memory_id": "auth-test",
                "content": "test",
                "authorization_id": "auth-test",
                "nonce": "auth-test",
            },
        )

    assert response.status_code == 401
    get_session.assert_not_called()


def test_valid_owner_token_without_signature_rejected_before_database_access():
    with patch("api.main.load_owner_token", return_value="expected-test-secret"), \
         patch("core.security.owner_auth.load_owner_token", return_value="expected-test-secret"), \
         patch("api.main.get_session") as get_session:
        response = TestClient(app).post(
            "/owner/memory/write",
            headers={"Authorization": "Bearer expected-test-secret"},
            json={
                "memory_id": "auth-test",
                "content": "test",
                "authorization_id": "auth-test",
                "nonce": "auth-test",
            },
        )

    assert response.status_code == 401
    assert response.json()["detail"] == "A valid owner digital signature is required."
    get_session.assert_not_called()


def test_unconfigured_owner_token_returns_service_unavailable():
    with patch("api.main.load_owner_token", return_value=None), \
         patch("core.security.owner_auth.load_owner_token", return_value=None), \
         patch("api.main.get_session") as get_session:
        response = TestClient(app).post(
            "/owner/memory/write",
            headers={"Authorization": "Bearer test-secret"},
            json={
                "memory_id": "auth-test",
                "content": "test",
                "authorization_id": "auth-test",
                "nonce": "auth-test",
            },
        )

    assert response.status_code == 503
    get_session.assert_not_called()

