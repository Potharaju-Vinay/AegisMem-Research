
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from core.memory.database import Base
from core.memory.repository import MemoryRepository
from core.recovery.audit import RecoveryEvent
from core.recovery.orchestrator import AegisMemRecoveryOrchestrator


def test_recovery_event_is_persisted_with_validation_outcome():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)

    with Session(engine) as session:
        repository = MemoryRepository(session)
        orchestrator = AegisMemRecoveryOrchestrator.__new__(
            AegisMemRecoveryOrchestrator
        )
        orchestrator.repository = repository

        orchestrator._record_event(
            memory_id="TEST-AUDIT-001",
            event_type="RECOVERY",
            action="ROLLBACK",
            message="Content restored; authorization not verified.",
            status="partial",
            compromised_version=3,
            restored_version=4,
            trust_score=0.95,
            suspicion_score=0.05,
            validation_result="PARTIAL",
            session_id="TEST-SESSION-001"
        )

        event = session.scalars(
            select(RecoveryEvent).where(
                RecoveryEvent.memory_id == "TEST-AUDIT-001"
            )
        ).one()

        assert event.status == "partial"
        assert event.validation_result == "PARTIAL"
        assert event.compromised_version == 3
        assert event.restored_version == 4
        assert event.session_id == "TEST-SESSION-001"
        assert "authorization not verified" in event.message.lower()

    engine.dispose()
    

def test_recovery_audit_records_successful_outcome():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)

    with Session(engine) as session:
        repository = MemoryRepository(session)
        orchestrator = AegisMemRecoveryOrchestrator.__new__(
            AegisMemRecoveryOrchestrator
        )
        orchestrator.repository = repository

        orchestrator._record_event(
            memory_id="TEST-AUDIT-SUCCESS",
            event_type="RECOVERY",
            action="ROLLBACK",
            message="Recovery and authorization verified.",
            status="success",
            validation_result="PASS"
        )

        event = session.scalars(
            select(RecoveryEvent).where(
                RecoveryEvent.memory_id == "TEST-AUDIT-SUCCESS"
            )
        ).one()

        assert event.status == "success"
        assert event.validation_result == "PASS"

    engine.dispose()


def test_recovery_audit_records_failed_outcome():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)

    with Session(engine) as session:
        repository = MemoryRepository(session)
        orchestrator = AegisMemRecoveryOrchestrator.__new__(
            AegisMemRecoveryOrchestrator
        )
        orchestrator.repository = repository

        orchestrator._record_event(
            memory_id="TEST-AUDIT-FAILED",
            event_type="RECOVERY",
            action="ROLLBACK",
            message="Recovery validation failed.",
            status="failed",
            validation_result="FAIL"
        )

        event = session.scalars(
            select(RecoveryEvent).where(
                RecoveryEvent.memory_id == "TEST-AUDIT-FAILED"
            )
        ).one()

        assert event.status == "failed"
        assert event.validation_result == "FAIL"

    engine.dispose()

from unittest.mock import patch

import pytest


def test_recovery_audit_commit_failure_rolls_back_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)

    try:
        with Session(engine) as session:
            repository = MemoryRepository(session)
            orchestrator = AegisMemRecoveryOrchestrator.__new__(
                AegisMemRecoveryOrchestrator
            )
            orchestrator.repository = repository

            with patch.object(
                session,
                "commit",
                side_effect=RuntimeError("simulated audit commit failure"),
            ):
                with pytest.raises(
                    RuntimeError,
                    match="simulated audit commit failure",
                ):
                    orchestrator._record_event(
                        memory_id="TEST-AUDIT-COMMIT-FAIL",
                        event_type="RECOVERY",
                        action="ROLLBACK",
                        message="Test audit failure.",
                        status="failed",
                    )

            assert session.is_active

            event_count = session.query(RecoveryEvent).filter_by(
                memory_id="TEST-AUDIT-COMMIT-FAIL"
            ).count()
            assert event_count == 0

    finally:
        engine.dispose()
