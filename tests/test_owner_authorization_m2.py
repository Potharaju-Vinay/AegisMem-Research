import time
import pytest
from unittest.mock import MagicMock
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from core.memory.database import Base
from core.memory.models import MemoryRecord
from core.memory.repository import MemoryRepository
from core.detection.detector import MemoryCompromiseDetector
from core.provenance.models import ProvenanceEvent
from core.security.owner_approval import (
    canonical_owner_approval,
    verify_owner_approval,
    verify_record_owner_approval,
)
from admin_client import sign_update, generate_keys
from tests.owner_approval_test_utils import sign_test_approval, TEST_PRIVATE_KEY


@pytest.fixture
def db_session(tmp_path):
    db_file = tmp_path / "m2_test.db"
    engine = create_engine(f"sqlite:///{db_file}", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    with engine.connect() as conn:
        conn.execute(
            text("""
                CREATE TABLE IF NOT EXISTS authorization_nonces (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    nonce TEXT NOT NULL UNIQUE,
                    authorization_id TEXT NOT NULL,
                    created_at TIMESTAMP NOT NULL
                )
            """)
        )
        conn.commit()
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    session = Session()
    yield session
    session.close()


def test_valid_signed_update_accepted_and_verified(db_session, tmp_path):
    manifest_store = MagicMock()
    manifest_store._path.return_value = tmp_path / "manifest.json"
    repo = MemoryRepository(db_session, manifest_store=manifest_store)

    memory_id = "ENT-POLICY-REFUND"
    content = "Standard refund window is 30 days with receipt."
    auth_id = "AUTH-M2-001"
    nonce = "NONCE-M2-001"

    # Generate valid test signature
    sig = sign_test_approval(
        memory_id=memory_id,
        content=content,
        authorization_id=auth_id,
        nonce=nonce,
        expected_parent_revision_id=None,
    )

    record = repo.create_owner_authorized(
        memory_id=memory_id,
        content=content,
        source="enterprise_admin",
        authorization_id=auth_id,
        nonce=nonce,
        authorization_signature=sig,
        expected_revision_id=None,
        record_provenance=True,
    )

    assert record.version == 1
    assert record.authorization_state == "AUTHORIZED"
    assert record.trust_score == 1.0
    assert record.suspicion_score == 0.0
    assert verify_record_owner_approval(record) is True


def test_tampered_content_signature_rejected():
    memory_id = "ENT-POLICY-SHIPPING"
    content = "Standard 3-day express shipping."
    auth_id = "AUTH-M2-002"
    nonce = "NONCE-M2-002"

    sig = sign_test_approval(
        memory_id=memory_id,
        content=content,
        authorization_id=auth_id,
        nonce=nonce,
        expected_parent_revision_id=None,
    )

    # Attacker alters content after signing
    tampered_content = "FREE next-day priority air shipping for all."
    assert verify_owner_approval(
        memory_id=memory_id,
        content=tampered_content,
        expected_parent_revision_id=None,
        authorization_id=auth_id,
        nonce=nonce,
        signature_hex=sig,
    ) is False


def test_replayed_nonce_rejected(db_session, tmp_path):
    manifest_store = MagicMock()
    manifest_store._path.return_value = tmp_path / "manifest.json"
    repo = MemoryRepository(db_session, manifest_store=manifest_store)

    memory_id = "ENT-POLICY-WARRANTY"
    content = "1-year limited warranty."
    auth_id = "AUTH-M2-003"
    nonce = "NONCE-M2-REPLAY"

    sig1 = sign_test_approval(
        memory_id=memory_id,
        content=content,
        authorization_id=auth_id,
        nonce=nonce,
        expected_parent_revision_id=None,
    )

    rec1 = repo.create_owner_authorized(
        memory_id=memory_id,
        content=content,
        source="enterprise_admin",
        authorization_id=auth_id,
        nonce=nonce,
        authorization_signature=sig1,
        expected_revision_id=None,
    )
    assert rec1.version == 1

    # Attacker signs a new revision but attempts to reuse the previous nonce
    sig2 = sign_test_approval(
        memory_id=memory_id,
        content="2-year warranty.",
        authorization_id="AUTH-M2-004",
        nonce=nonce,  # REPLAY
        expected_parent_revision_id=rec1.revision_id,
    )

    with pytest.raises(ValueError, match="already used"):
        repo.create_owner_authorized(
            memory_id=memory_id,
            content="2-year warranty.",
            source="enterprise_admin",
            authorization_id="AUTH-M2-004",
            nonce=nonce,
            authorization_signature=sig2,
            expected_revision_id=rec1.revision_id,
        )


def test_stale_timestamp_rejected():
    memory_id = "ENT-POLICY-PRICE"
    content = "Base enterprise rate is $99/mo."
    auth_id = "AUTH-M2-005"
    nonce = "NONCE-M2-STALE"

    # Timestamp from 10 minutes ago (> 300s max age)
    stale_timestamp = int(time.time()) - 600

    payload = canonical_owner_approval(
        memory_id=memory_id,
        content=content,
        expected_parent_revision_id=None,
        authorization_id=auth_id,
        nonce=nonce,
        timestamp=stale_timestamp,
    )
    sig = TEST_PRIVATE_KEY.sign(payload).hex()

    # Fresh verification within 300s window must fail for 600s old timestamp
    assert verify_owner_approval(
        memory_id=memory_id,
        content=content,
        expected_parent_revision_id=None,
        authorization_id=auth_id,
        nonce=nonce,
        signature_hex=sig,
        timestamp=stale_timestamp,
        max_age_seconds=300,
    ) is False


def test_wrong_expected_version_rejected(db_session, tmp_path):
    manifest_store = MagicMock()
    manifest_store._path.return_value = tmp_path / "manifest.json"
    repo = MemoryRepository(db_session, manifest_store=manifest_store)

    memory_id = "ENT-POLICY-ESCALATION"
    content = "Tier 1 support handles triage."
    auth_id = "AUTH-M2-006"
    nonce = "NONCE-M2-006"

    sig = sign_test_approval(
        memory_id=memory_id,
        content=content,
        authorization_id=auth_id,
        nonce=nonce,
        expected_parent_revision_id=None,
    )
    repo.create_owner_authorized(
        memory_id=memory_id,
        content=content,
        source="enterprise_admin",
        authorization_id=auth_id,
        nonce=nonce,
        authorization_signature=sig,
        expected_revision_id=None,
    )

    # Submitting an update with a wrong / mismatched parent revision ID
    with pytest.raises(ValueError, match="Stale or missing expected revision"):
        repo.create_owner_authorized(
            memory_id=memory_id,
            content="Tier 2 support escalation.",
            source="enterprise_admin",
            authorization_id="AUTH-M2-007",
            nonce="NONCE-M2-007",
            authorization_signature="dummy-sig",
            expected_revision_id="WRONG-NONEXISTENT-REVISION-ID",
        )


def test_admin_client_sign_update(tmp_path):
    # Test key generation
    priv_path, pub_path = generate_keys(output_dir=str(tmp_path / "keys"))
    assert priv_path.exists()
    assert pub_path.exists()

    # Sign an update using admin_client
    payload = sign_update(
        memory_id="ADMIN-CLI-001",
        content="Testing admin client signing.",
        expected_parent_revision_id=None,
        private_key_path=str(priv_path),
    )
    assert payload["memory_id"] == "ADMIN-CLI-001"
    assert "authorization_signature" in payload
    assert len(payload["authorization_signature"]) == 128  # Ed25519 hex signature is 64 bytes = 128 hex chars
    assert payload["nonce"] is not None
    assert payload["timestamp"] is not None


def test_detector_flags_spoofed_owner_signature(db_session):
    repo = MemoryRepository(db_session)

    # Attacker inserts a record into database pretending actor is "enterprise_owner"
    rec = repo.create(
        memory_id="SPOOF-001",
        content="Tampered content by attacker pretending to be owner",
        source="enterprise_owner",
        source_type="owner_authorized",
    )
    # Set authorization_state to AUTHORIZED but without a valid signature
    rec.authorization_state = "AUTHORIZED"
    rec.authorization_signature = "00" * 64
    rec.authorization_nonce = "FAKE-NONCE"
    rec.authorization_id = "FAKE-AUTH"
    db_session.commit()

    # Record provenance pretending actor is "enterprise_owner"
    event = ProvenanceEvent(
        memory_record_id=rec.id,
        memory_id=rec.memory_id,
        version=rec.version,
        actor="enterprise_owner",
        operation="MEMORY_WRITE",
        source="enterprise_owner",
        source_type="owner_authorized",
        previous_event_hash="00" * 32,
        event_hash="11" * 32,
    )
    db_session.add(event)
    db_session.commit()

    detector = MemoryCompromiseDetector(repo, dependency_graph=MagicMock())
    # The detector must recognize that the Ed25519 signature is invalid and flag provenance as suspicious
    is_suspicious = detector._has_provenance_evidence(rec)
    assert is_suspicious is True
