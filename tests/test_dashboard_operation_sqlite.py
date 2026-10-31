import hashlib
import pytest

from datetime import datetime, timedelta, timezone
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from core.memory.database import Base
from core.security.dashboard_session import DashboardSession
from core.security.dashboard_operation_approval import (
    DashboardOperationApproval,
)
from core.security.dashboard_operation import (
    authorize_dashboard_operation,
    consume_dashboard_operation,
    DashboardOperationAuthorizationError,
)


@pytest.fixture
def approval_database(tmp_path, monkeypatch):
    database_path = tmp_path / "approval_test.db"

    engine = create_engine(
        f"sqlite:///{database_path}",
        connect_args={"check_same_thread": False},
    )

    Base.metadata.create_all(
        bind=engine,
        tables=[
            DashboardSession.__table__,
            DashboardOperationApproval.__table__,
        ],
    )

    TestSessionLocal = sessionmaker(
        bind=engine,
        autoflush=False,
        autocommit=False,
    )

    monkeypatch.setattr(
        "core.security.dashboard_operation.SessionLocal",
        TestSessionLocal,
    )

    monkeypatch.setattr(
        "core.security.dashboard_operation.record_session_audit",
        lambda **kwargs: None,
    )

    raw_session_id = "sqlite-test-session"
    session_ref = hashlib.sha256(
        raw_session_id.encode("utf-8")
    ).hexdigest()

    with TestSessionLocal() as db:
        db.add(
            DashboardSession(
                id=session_ref,
                created_at=datetime.now(timezone.utc),
                expires_at=datetime.now(timezone.utc)
                + timedelta(hours=1),
            )
        )
        db.commit()

    yield TestSessionLocal, raw_session_id, engine

    engine.dispose()


def test_real_sqlite_approval_creation(approval_database):
    db_factory, raw_session_id, engine = approval_database

    result = authorize_dashboard_operation(
        operation="memory.detect",
        memory_id="POLICY-001",
        confirmed=True,
        raw_session_id=raw_session_id,
    )

    with db_factory() as db:
        approval = db.get(
            DashboardOperationApproval,
            result["authorization_id"],
        )

        assert approval is not None
        assert approval.operation == "memory.detect"
        assert approval.memory_id == "POLICY-001"
        assert approval.status == "APPROVED"
        assert approval.consumed_at is None


def test_real_sqlite_single_use_consumption(approval_database):
    db_factory, raw_session_id, engine = approval_database

    approval = authorize_dashboard_operation(
        operation="memory.detect",
        memory_id="POLICY-001",
        confirmed=True,
        raw_session_id=raw_session_id,
    )

    result = consume_dashboard_operation(
        authorization_id=approval["authorization_id"],
        operation="memory.detect",
        memory_id="POLICY-001",
        raw_session_id=raw_session_id,
    )

    assert result["consumed"] is True

    with db_factory() as db:
        stored = db.get(
            DashboardOperationApproval,
            approval["authorization_id"],
        )

        assert stored.status == "CONSUMED"
        assert stored.consumed_at is not None


def test_real_sqlite_rejects_replay(approval_database):
    db_factory, raw_session_id, engine = approval_database

    approval = authorize_dashboard_operation(
        operation="memory.recover",
        memory_id="POLICY-001",
        confirmed=True,
        raw_session_id=raw_session_id,
    )

    consume_dashboard_operation(
        authorization_id=approval["authorization_id"],
        operation="memory.recover",
        memory_id="POLICY-001",
        raw_session_id=raw_session_id,
    )

    with pytest.raises(DashboardOperationAuthorizationError):
        consume_dashboard_operation(
            authorization_id=approval["authorization_id"],
            operation="memory.recover",
            memory_id="POLICY-001",
            raw_session_id=raw_session_id,
        )


def test_real_sqlite_rejects_expired_approval(approval_database):
    db_factory, raw_session_id, engine = approval_database

    approval = authorize_dashboard_operation(
        operation="memory.detect",
        memory_id="POLICY-001",
        confirmed=True,
        raw_session_id=raw_session_id,
    )

    with db_factory() as db:
        stored = db.get(
            DashboardOperationApproval,
            approval["authorization_id"],
        )

        stored.expires_at = datetime.now(timezone.utc) - timedelta(
            seconds=1
        )
        db.commit()

    with pytest.raises(DashboardOperationAuthorizationError):
        consume_dashboard_operation(
            authorization_id=approval["authorization_id"],
            operation="memory.detect",
            memory_id="POLICY-001",
            raw_session_id=raw_session_id,
        )