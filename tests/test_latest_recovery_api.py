
from datetime import datetime, timezone
from unittest.mock import patch

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import api.main as api_main
from core.memory.database import Base
from core.recovery.audit import RecoveryEvent
from core.memory.repository import MemoryRepository


def setup_client(monkeypatch):
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine)
    db = session_factory()

    monkeypatch.setattr(api_main, "get_session", lambda: db)
    monkeypatch.setattr(
        api_main,
        "require_dashboard_auth",
        lambda request: None,
    )

    return TestClient(api_main.app), db, engine


def add_recovery(db, **overrides):
    values = {
        "memory_id": "API-RECOVERY-TEST",
        "event_type": "RECOVERY",
        "action": "ROLLBACK",
        "message": "Controlled API test recovery",
        "status": "failed",
        "compromised_version": 2,
        "restored_version": 3,
        "validation_result": "FAIL",
        "created_at": datetime.now(timezone.utc),
    }
    values.update(overrides)
    event = RecoveryEvent(**values)
    db.add(event)
    db.commit()
    return event


def test_latest_recovery_returns_not_found_when_no_events(monkeypatch):
    client, db, engine = setup_client(monkeypatch)
    try:
        response = client.get("/dashboard/latest-recovery")
        assert response.status_code == 200
        assert response.json() == {"found": False}
    finally:
        db.close()
        engine.dispose()


def test_latest_recovery_does_not_verify_failed_event(monkeypatch):
    client, db, engine = setup_client(monkeypatch)
    try:
        add_recovery(db)

        response = client.get("/dashboard/latest-recovery")

        assert response.status_code == 200
        body = response.json()
        assert body["found"] is True
        assert body["recovery"]["status"] == "failed"
        assert body["recovery"]["verified_success"] is False
    finally:
        db.close()
        engine.dispose()



def test_latest_recovery_requires_provenance_validation(monkeypatch):
    client, db, engine = setup_client(monkeypatch)
    try:
        repository = MemoryRepository(db)
        repository.create(
            memory_id="API-RECOVERY-TEST",
            content="Trusted original memory",
            source="test",
            source_type="test",
        )
        repository.create(
            memory_id="API-RECOVERY-TEST",
            content="Compromised memory",
            source="test",
            source_type="test",
        )
        repository.create(
            memory_id="API-RECOVERY-TEST",
            content="Restored memory",
            source="test",
            source_type="test",
        )

        add_recovery(
            db,
            status="success",
            validation_result="PASS",
        )

        with patch.object(
            api_main,
            "RecoveryValidator",
        ) as validator_class:
            validator = validator_class.return_value
            validator.validate.return_value = {
                "version": 3,
                "content_valid": True,
                "recovery_provenance_verified": False,
                "provenance_verified": True,
                "provenance_reason": "Recovery attestation missing.",
            }

            response = client.get("/dashboard/latest-recovery")

            validator.validate.assert_called_once_with(
                "API-RECOVERY-TEST"
            )

        assert response.status_code == 200
        body = response.json()
        assert body["found"] is True
        assert body["recovery"]["verified_success"] is False
        assert (
            body["recovery"]["verification"][
                "recovery_provenance_verified"
            ]
            is False
        )
    finally:
        db.close()
        engine.dispose()
