import hashlib
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from core.memory.database import Base
from core.security.dashboard_session import DashboardSession
from core.security.dashboard_operation_approval import DashboardOperationApproval
from core.security.dashboard_operation import (
    authorize_dashboard_operation,
    consume_dashboard_operation,
    DashboardOperationAuthorizationError,
)


@pytest.fixture
def revocation_database(tmp_path, monkeypatch):
    engine = create_engine(
        f"sqlite:///{tmp_path / 'revocation.db'}",
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

    raw_session_id = "revocation-test-session"
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

    yield TestSessionLocal, raw_session_id

    engine.dispose()


def test_revoked_session_cannot_consume_approval(revocation_database):
    db_factory, raw_session_id = revocation_database

    approval = authorize_dashboard_operation(
        operation="memory.detect",
        memory_id="POLICY-001",
        confirmed=True,
        raw_session_id=raw_session_id,
    )

    session_ref = hashlib.sha256(
        raw_session_id.encode("utf-8")
    ).hexdigest()

    with db_factory() as db:
        session = db.get(DashboardSession, session_ref)
        db.delete(session)
        db.commit()

    with pytest.raises(DashboardOperationAuthorizationError):
        consume_dashboard_operation(
            authorization_id=approval["authorization_id"],
            operation="memory.detect",
            memory_id="POLICY-001",
            raw_session_id=raw_session_id,
        )

    with db_factory() as db:
        stored = db.get(
            DashboardOperationApproval,
            approval["authorization_id"],
        )
        assert stored.status == "APPROVED"
        assert stored.consumed_at is None