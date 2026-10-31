import hashlib
import threading
from concurrent.futures import ThreadPoolExecutor
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


def test_only_one_concurrent_consumption_succeeds(tmp_path, monkeypatch):
    engine = create_engine(
        f"sqlite:///{tmp_path / 'concurrency.db'}",
        connect_args={"check_same_thread": False, "timeout": 10},
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

    raw_session_id = "concurrent-test-session"
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

    approval = authorize_dashboard_operation(
        operation="memory.detect",
        memory_id="POLICY-001",
        confirmed=True,
        raw_session_id=raw_session_id,
    )

    barrier = threading.Barrier(2)

    def attempt_consumption():
        barrier.wait()

        try:
            consume_dashboard_operation(
                authorization_id=approval["authorization_id"],
                operation="memory.detect",
                memory_id="POLICY-001",
                raw_session_id=raw_session_id,
            )
            return "SUCCESS"
        except DashboardOperationAuthorizationError:
            return "REJECTED"

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(
            lambda _: attempt_consumption(),
            range(2),
        ))

    assert results.count("SUCCESS") == 1
    assert results.count("REJECTED") == 1

    engine.dispose()