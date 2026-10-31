from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from api.main import app


@pytest.mark.parametrize(
    ("method", "path", "payload"),
    [
        ("POST", "/attacker/memory/write", {
            "memory_id": "auth-test",
            "modified_content": "test"
        }),
        ("POST", "/lab/memory/write", {
            "memory_id": "auth-test",
            "modified_content": "test"
        }),
        ("POST", "/attack/poison", {
            "memory_id": "auth-test"
        }),
        ("POST", "/attack/delete", {
            "memory_id": "auth-test"
        }),
        ("POST", "/attack/tamper", {
            "memory_id": "auth-test"
        }),
        ("GET", "/aegismem/detect/AUTH-TEST-NONEXISTENT", None),
        ("GET", "/aegismem/status/AUTH-TEST-NONEXISTENT", None),
    ],
)
def test_protected_routes_reject_missing_owner_credentials_before_database_access(
    method, path, payload
):
    with patch("api.main.load_owner_token", return_value="test-secret"), \
         patch("core.security.owner_auth.load_owner_token", return_value="test-secret"), \
         patch("api.main.get_session") as get_session:
        response = TestClient(app).request(
            method,
            path,
            json=payload,
        )

    assert response.status_code == 401
    get_session.assert_not_called()


@pytest.mark.parametrize(
    ("method", "path", "payload"),
    [
        ("POST", "/owner/memory/write", {
            "memory_id": "signature-test",
            "content": "test",
            "authorization_id": "AUTH-SIG-TEST",
            "nonce": "NONCE-SIG-TEST",
        }),
        ("POST", "/attacker/memory/write", {
            "memory_id": "signature-test",
            "modified_content": "test",
        }),
        ("POST", "/lab/memory/write", {
            "memory_id": "signature-test",
            "modified_content": "test",
        }),
        ("POST", "/attack/poison", {
            "memory_id": "signature-test",
        }),
        ("POST", "/attack/delete", {
            "memory_id": "signature-test",
        }),
        ("POST", "/attack/tamper", {
            "memory_id": "signature-test",
        }),
        ("POST", "/aegismem/recover/signature-test", None),
    ],
)
def test_sensitive_routes_reject_missing_signature_before_database_access(
    method, path, payload
):
    with patch("api.main.load_owner_token", return_value="test-secret"), \
         patch("core.security.owner_auth.load_owner_token", return_value="test-secret"), \
         patch("api.main.get_session") as get_session:
        response = TestClient(app).request(
            method,
            path,
            json=payload,
            headers={"Authorization": "Bearer test-secret"},
        )

    assert response.status_code == 401
    assert "signature" in response.json()["detail"].lower()
    get_session.assert_not_called()
