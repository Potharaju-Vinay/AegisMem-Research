import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch, MagicMock

from core.security.dashboard_operation import (
    authorize_dashboard_operation,
    consume_dashboard_operation,
    DashboardOperationAuthorizationError,
)


SESSION_ID = "test-dashboard-session"


def make_session():
    return type(
        "Session",
        (),
        {
            "expires_at": datetime.now(timezone.utc)
            + timedelta(hours=1)
        },
    )()


@patch("core.security.dashboard_operation.record_session_audit")
@patch("core.security.dashboard_operation.SessionLocal")
def test_creates_persistent_approval(mock_session_local, mock_audit):
    db = mock_session_local.return_value.__enter__.return_value
    db.get.return_value = make_session()

    result = authorize_dashboard_operation(
        operation="memory.detect",
        memory_id="POLICY-001",
        confirmed=True,
        raw_session_id=SESSION_ID,
    )

    assert result["authorized"] is True
    assert result["single_use"] is True
    assert len(result["authorization_id"]) > 20

    db.add.assert_called_once()
    db.commit.assert_called_once()
    mock_audit.assert_called_once()


@patch("core.security.dashboard_operation.record_session_audit")
@patch("core.security.dashboard_operation.SessionLocal")
def test_consumes_approval_once(mock_session_local, mock_audit):
    db = mock_session_local.return_value.__enter__.return_value
    db.get.return_value = make_session()

    db.execute.return_value.rowcount = 1

    result = consume_dashboard_operation(
        authorization_id="approval-123",
        operation="memory.detect",
        memory_id="POLICY-001",
        raw_session_id=SESSION_ID,
    )

    assert result["consumed"] is True
    assert result["operation"] == "memory.detect"
    db.commit.assert_called_once()
    mock_audit.assert_called_once()


@patch("core.security.dashboard_operation.SessionLocal")
def test_rejects_reused_approval(mock_session_local):
    db = mock_session_local.return_value.__enter__.return_value
    db.get.return_value = make_session()
    db.execute.return_value.rowcount = 0

    with pytest.raises(DashboardOperationAuthorizationError):
        consume_dashboard_operation(
            authorization_id="approval-123",
            operation="memory.detect",
            memory_id="POLICY-001",
            raw_session_id=SESSION_ID,
        )

    db.rollback.assert_called_once()


@patch("core.security.dashboard_operation.SessionLocal")
def test_rejects_cross_session_consumption(mock_session_local):
    db = mock_session_local.return_value.__enter__.return_value
    db.get.return_value = make_session()
    db.execute.return_value.rowcount = 0

    with pytest.raises(DashboardOperationAuthorizationError):
        consume_dashboard_operation(
            authorization_id="approval-123",
            operation="memory.detect",
            memory_id="POLICY-001",
            raw_session_id="different-session",
        )


@patch("core.security.dashboard_operation.SessionLocal")
def test_rejects_expired_dashboard_session(mock_session_local):
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
        consume_dashboard_operation(
            authorization_id="approval-123",
            operation="memory.detect",
            memory_id="POLICY-001",
            raw_session_id=SESSION_ID,
        )