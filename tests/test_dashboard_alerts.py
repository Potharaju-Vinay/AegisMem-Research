from datetime import datetime, timezone

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import api.main as api_main
from core.memory.database import Base
from core.soc.models import SOCAlert
from attack_lab.models import AttackEvent


def setup_client(monkeypatch):
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    TestSession = sessionmaker(bind=engine)
    db = TestSession()

    monkeypatch.setattr(api_main, "get_session", lambda: db)
    monkeypatch.setattr(
        api_main,
        "require_dashboard_auth",
        lambda request: None,
    )

    return TestClient(api_main.app), db, engine


def add_alert(db, attack_id, memory_id="MEM-1"):
    alert = SOCAlert(
        alert_id=f"ALERT-{attack_id}",
        attack_id=attack_id,
        memory_id=memory_id,
        attack_type="MEMORY_POISONING",
        severity="HIGH",
        severity_score=8.5,
        evidence_summary="Test evidence",
        status="OPEN",
        created_at=datetime.now(timezone.utc),
    )
    db.add(alert)
    db.commit()
    return alert


def add_attack(db, attack_id, memory_id="MEM-1", target_version=2):
    attack = AttackEvent(
        attack_id=attack_id,
        memory_record_id=1,
        memory_id=memory_id,
        original_content="Trusted content",
        modified_content="Tampered content",
        original_version=1,
        target_version=target_version,
        original_content_hash="original-hash",
        observed_content_hash="modified-hash",
        attack_type="MEMORY_POISONING",
        mutation_description="Unauthorized content mutation",
        attacker="test-attacker",
        attack_time=datetime.now(timezone.utc),
        source_ip="192.0.2.10",
        entry_point="/test",
        access_method="API",
        integrity_compromised=True,
        status="injected",
    )
    db.add(attack)
    db.commit()
    return attack


def test_alert_matches_exact_attack_id(monkeypatch):
    client, db, engine = setup_client(monkeypatch)
    try:
        add_alert(db, "ATTACK-1")
        add_attack(db, "ATTACK-1")

        response = client.get("/dashboard/alerts")
        assert response.status_code == 200

        item = response.json()["alerts"][0]
        assert item["attack_record_found"] is True
        assert item["attacker"] == "test-attacker"
        assert item["target_version"] == 2
        assert item["content_changed"] is True
        assert item["hash_changed"] is True
        assert item["attribution"] == "INCONCLUSIVE"
        assert item["attribution_evidence"]
    finally:
        db.close()
        engine.dispose()


def test_detection_alert_uses_version_fallback(monkeypatch):
    client, db, engine = setup_client(monkeypatch)
    try:
        add_alert(db, "DETECTION-MEM-1-V2")
        add_attack(db, "ACTUAL-ATTACK-1", target_version=2)

        response = client.get("/dashboard/alerts")
        assert response.status_code == 200

        item = response.json()["alerts"][0]
        assert item["attack_record_found"] is True
        assert item["target_version"] == 2
        assert item["source_ip"] == "192.0.2.10"
    finally:
        db.close()
        engine.dispose()


def test_alert_without_attack_record_returns_null_details(monkeypatch):
    client, db, engine = setup_client(monkeypatch)
    try:
        add_alert(db, "ATTACK-MISSING")

        response = client.get("/dashboard/alerts")
        assert response.status_code == 200

        item = response.json()["alerts"][0]
        assert item["attack_record_found"] is False
        assert item["attacker"] is None
        assert item["content_changed"] is None
        assert item["hash_changed"] is None
        assert item["attribution"] == "INCONCLUSIVE"
    finally:
        db.close()
        engine.dispose()


def test_unchanged_attack_content_reports_false(monkeypatch):
    client, db, engine = setup_client(monkeypatch)
    try:
        add_alert(db, "ATTACK-UNCHANGED")
        attack = add_attack(db, "ATTACK-UNCHANGED")
        attack.modified_content = attack.original_content
        attack.observed_content_hash = attack.original_content_hash
        db.commit()

        response = client.get("/dashboard/alerts")
        assert response.status_code == 200

        item = response.json()["alerts"][0]
        assert item["content_changed"] is False
        assert item["hash_changed"] is False
    finally:
        db.close()
        engine.dispose()
