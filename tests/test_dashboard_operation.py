import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from core.security.dashboard_operation import (
    ALLOWED_OPERATIONS,
    DashboardOperationAuthorizationError,
    authorize_dashboard_operation,
)


@pytest.mark.parametrize("operation", list(ALLOWED_OPERATIONS))
def test_operations_require_explicit_confirmation(operation):
    with pytest.raises(DashboardOperationAuthorizationError):
        authorize_dashboard_operation(
            operation=operation,
            memory_id="POLICY-001",
            confirmed=False,
            raw_session_id="test-session",
        )


@pytest.mark.parametrize(
    "operation",
    ["invalid.operation", "", None, [], {}],
)
def test_rejects_invalid_operations(operation):
    with pytest.raises(DashboardOperationAuthorizationError):
        authorize_dashboard_operation(
            operation=operation,
            memory_id="POLICY-001",
            confirmed=True,
            raw_session_id="test-session",
        )


@pytest.mark.parametrize(
    "memory_id",
    ["", "   ", " POLICY-001", "POLICY-001 ", None, 123],
)
def test_rejects_invalid_memory_ids(memory_id):
    with pytest.raises(DashboardOperationAuthorizationError):
        authorize_dashboard_operation(
            operation="memory.detect",
            memory_id=memory_id,
            confirmed=True,
            raw_session_id="test-session",
        )


def test_rejects_missing_session():
    with pytest.raises(DashboardOperationAuthorizationError):
        authorize_dashboard_operation(
            operation="memory.detect",
            memory_id="POLICY-001",
            confirmed=True,
            raw_session_id="",
        )


@patch("core.security.dashboard_operation.SessionLocal")
def test_successful_dashboard_authorization(mock_session_local):
    session = mock_session_local.return_value.__enter__.return_value
    session.expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
    session.id = "test-session-reference"
    mock_session_local.return_value.__enter__.return_value.get.return_value = session

    result = authorize_dashboard_operation(
        operation="memory.detect",
        memory_id="POLICY-001",
        confirmed=True,
        raw_session_id="test-session",
    )

    assert result["authorized"] is True
    assert result["operation"] == "memory.detect"
    assert result["memory_id"] == "POLICY-001"
    import hashlib
    assert result["session_ref"] == hashlib.sha256(
        b"test-session"
    ).hexdigest()
    assert result["single_use"] is True
    assert len(result["authorization_id"]) > 20


@patch("core.security.dashboard_operation.SessionLocal")
def test_rejects_unknown_session(mock_session_local):
    db = mock_session_local.return_value.__enter__.return_value
    db.get.return_value = None

    with pytest.raises(DashboardOperationAuthorizationError):
        authorize_dashboard_operation(
            operation="memory.detect",
            memory_id="POLICY-001",
            confirmed=True,
            raw_session_id="unknown-session",
        )


@patch("core.security.dashboard_operation.SessionLocal")
def test_rejects_expired_session(mock_session_local):
    db = mock_session_local.return_value.__enter__.return_value

    expired_session = type(
        "Session",
        (),
        {
            "expires_at": datetime.now(timezone.utc)
            - timedelta(minutes=1)
        },
    )()

    db.get.return_value = expired_session

    with pytest.raises(DashboardOperationAuthorizationError):
        authorize_dashboard_operation(
            operation="memory.recover",
            memory_id="POLICY-001",
            confirmed=True,
            raw_session_id="expired-session",
        )