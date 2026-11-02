from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from core.memory.database import Base
from core.memory.repository import MemoryRepository
from core.detection.detector import MemoryCompromiseDetector
from core.security.owner_approval import verify_record_owner_approval
from tests.owner_approval_test_utils import sign_test_approval
from core.integrity.manifest_store import IntegrityManifestStore
from core.provenance.models import ProvenanceEvent


def make_test_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    with engine.begin() as connection:
        connection.execute(text("""
            CREATE TABLE IF NOT EXISTS authorization_nonces (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nonce VARCHAR(128) NOT NULL UNIQUE,
                authorization_id VARCHAR(128) NOT NULL,
                created_at DATETIME NOT NULL
            )
        """))
    session = sessionmaker(bind=engine)()
    return engine, session


def test_valid_owner_signature_is_verified(tmp_path):
    engine, session = make_test_session()
    try:
        manifest_store = IntegrityManifestStore(
    manifest_dir=tmp_path / "integrity_manifests"
)
        repository = MemoryRepository(
    session,
    manifest_store=manifest_store,
)
        original = repository.create(
            memory_id="ATTR-001",
            content="Refunds within 30 days",
            source="test",
            source_type="policy",
        )
        content = "Refunds within 45 days"
        authorization_id = "AUTH-ATTR-001"
        nonce = "NONCE-ATTR-001"
        signature = sign_test_approval(
            memory_id=original.memory_id,
            content=content,
            authorization_id=authorization_id,
            nonce=nonce,
            expected_parent_revision_id=original.revision_id,
        )
        record = repository.create_owner_authorized(
            memory_id=original.memory_id,
            content=content,
            source="owner",
            authorization_id=authorization_id,
            nonce=nonce,
            authorization_signature=signature,
            expected_revision_id=original.revision_id,
        )

        assert verify_record_owner_approval(record) is True
    finally:
        session.close()
        engine.dispose()


def test_missing_owner_signature_is_not_verified(tmp_path):
    engine, session = make_test_session()
    try:
        manifest_store = IntegrityManifestStore(
    manifest_dir=tmp_path / "integrity_manifests"
)
        repository = MemoryRepository(
    session,
    manifest_store=manifest_store,
)
        record = repository.create(
            memory_id="ATTR-002",
            content="Original content",
            source="test",
            source_type="policy",
        )

        assert verify_record_owner_approval(record) is False
    finally:
        session.close()
        engine.dispose()


def test_unsigned_record_without_attack_evidence_is_inconclusive(tmp_path):
    engine, session = make_test_session()
    try:
        manifest_store = IntegrityManifestStore(
    manifest_dir=tmp_path / "integrity_manifests"
)
        repository = MemoryRepository(
    session,
    manifest_store=manifest_store,
)
        repository.create(
            memory_id="ATTR-003",
            content="Original content",
            source="test",
            source_type="policy",
        )

        detector = MemoryCompromiseDetector(repository=repository)
        result = detector.detect("ATTR-003")

        assert result.attribution == "INCONCLUSIVE"
    finally:
        session.close()
        engine.dispose()

from attack_lab.models import AttackEvent
from core.provenance.manager import ProvenanceManager


def test_attack_event_without_suspicious_provenance_is_inconclusive(tmp_path):
    engine, session = make_test_session()
    try:
        manifest_store = IntegrityManifestStore(
    manifest_dir=tmp_path / "integrity_manifests"
)
        repository = MemoryRepository(
    session,
    manifest_store=manifest_store,
)
        record = repository.create(
            memory_id="ATTR-004",
            content="Original policy",
            source="test",
            source_type="policy",
        )
        session.add(AttackEvent(
            attack_id="ATT-ATTR-004",
            memory_record_id=record.id,
            memory_id=record.memory_id,
            original_content=record.content,
            modified_content="Changed policy",
            original_version=record.version - 1,
            target_version=record.version,
            original_content_hash="a" * 64,
            observed_content_hash="b" * 64,
            attack_type="test",
            mutation_description="test event",
            attacker="unknown",
        ))
        session.commit()

        result = MemoryCompromiseDetector(repository).detect(record.memory_id)

        assert result.attribution == "INCONCLUSIVE"
    finally:
        session.close()
        engine.dispose()


def test_attack_event_with_suspicious_provenance_is_flagged(tmp_path):
    engine, session = make_test_session()
    try:
        manifest_store = IntegrityManifestStore(
    manifest_dir=tmp_path / "integrity_manifests"
)
        repository = MemoryRepository(
    session,
    manifest_store=manifest_store,
)
        record = repository.create(
            memory_id="ATTR-005",
            content="Modified policy",
            source="test",
            source_type="policy",
        )
        ProvenanceManager(session).record(
            memory_id=record.memory_id,
            version=record.version,
            actor="research-attacker",
            operation="MEMORY_WRITE",
            source="external_attack",
            source_type="external_memory_write",
            memory_record_id=record.id,
        )
        session.add(AttackEvent(
            attack_id="ATT-ATTR-005",
            memory_record_id=record.id,
            memory_id=record.memory_id,
            original_content="Original policy",
            modified_content=record.content,
            original_version=record.version - 1,
            target_version=record.version,
            original_content_hash="a" * 64,
            observed_content_hash="b" * 64,
            attack_type="test",
            mutation_description="test event",
            attacker="research-attacker",
        ))
        session.commit()

        result = MemoryCompromiseDetector(repository).detect(record.memory_id)

        assert result.attribution == "UNAUTHORIZED_MODIFICATION"
    finally:
        session.close()
        engine.dispose()


def test_owner_signature_with_compromise_evidence_is_not_owner_attributed(tmp_path):
    engine, session = make_test_session()
    try:
        manifest_store = IntegrityManifestStore(
    manifest_dir=tmp_path / "integrity_manifests"
)
        repository = MemoryRepository(
    session,
    manifest_store=manifest_store,
)
        original = repository.create(
            memory_id="ATTR-006",
            content="Original policy",
            source="test",
            source_type="policy",
        )
        content = "Authorized policy update"
        authorization_id = "AUTH-ATTR-006"
        nonce = "NONCE-ATTR-006"
        signature = sign_test_approval(
            memory_id=original.memory_id,
            content=content,
            authorization_id=authorization_id,
            nonce=nonce,
            expected_parent_revision_id=original.revision_id,
        )
        record = repository.create_owner_authorized(
            memory_id=original.memory_id,
            content=content,
            source="owner",
            authorization_id=authorization_id,
            nonce=nonce,
            authorization_signature=signature,
            expected_revision_id=original.revision_id,
        )
        record.status = "CORRUPTED"
        session.commit()

        result = MemoryCompromiseDetector(repository).detect(record.memory_id)

        assert result.attribution != "OWNER_AUTHORIZED"
    finally:
        session.close()
        engine.dispose()
        

def test_owner_signature_without_integrity_manifest_is_inconclusive(tmp_path):
    engine, session = make_test_session()
    try:
        manifest_store = IntegrityManifestStore(
    manifest_dir=tmp_path / "integrity_manifests"
)
        repository = MemoryRepository(
    session,
    manifest_store=manifest_store,
)
        original = repository.create(
            memory_id="ATTR-007",
            content="Original policy",
            source="test",
            source_type="policy",
        )

        content = "Updated policy"
        authorization_id = "AUTH-ATTR-007"
        nonce = "NONCE-ATTR-007"
        signature = sign_test_approval(
            memory_id=original.memory_id,
            content=content,
            authorization_id=authorization_id,
            nonce=nonce,
            expected_parent_revision_id=original.revision_id,
        )

        repository.create_owner_authorized(
            memory_id=original.memory_id,
            content=content,
            source="owner",
            authorization_id=authorization_id,
            nonce=nonce,
            authorization_signature=signature,
            expected_revision_id=original.revision_id,
        )

        result = MemoryCompromiseDetector(repository).detect(
            original.memory_id
        )

        assert result.evidence.authorization_valid is True
        assert result.evidence.integrity_anchor_status == "UNANCHORED"
        assert result.attribution == "INCONCLUSIVE"
    finally:
        session.close()
        engine.dispose()
        

def test_owner_signature_rejects_modified_content(tmp_path):
    engine, session = make_test_session()
    try:
        manifest_store = IntegrityManifestStore(
            manifest_dir=tmp_path / "integrity_manifests"
        )
        repository = MemoryRepository(
            session,
            manifest_store=manifest_store,
        )
        original = repository.create(
            memory_id="ATTR-TAMPER-001",
            content="Original policy",
            source="test",
            source_type="policy",
        )
        content = "Authorized policy"
        signature = sign_test_approval(
            memory_id=original.memory_id,
            content=content,
            authorization_id="AUTH-TAMPER-001",
            nonce="NONCE-TAMPER-001",
            expected_parent_revision_id=original.revision_id,
        )
        record = repository.create_owner_authorized(
            memory_id=original.memory_id,
            content=content,
            source="owner",
            authorization_id="AUTH-TAMPER-001",
            nonce="NONCE-TAMPER-001",
            authorization_signature=signature,
            expected_revision_id=original.revision_id,
        )
        record.content = "Tampered policy"
        assert verify_record_owner_approval(record) is False
    finally:
        session.close()
        engine.dispose()


def test_owner_signature_rejects_modified_parent_revision(tmp_path):
    engine, session = make_test_session()
    try:
        manifest_store = IntegrityManifestStore(
            manifest_dir=tmp_path / "integrity_manifests"
        )
        repository = MemoryRepository(
            session,
            manifest_store=manifest_store,
        )
        original = repository.create(
            memory_id="ATTR-TAMPER-002",
            content="Original policy",
            source="test",
            source_type="policy",
        )
        content = "Authorized policy"
        signature = sign_test_approval(
            memory_id=original.memory_id,
            content=content,
            authorization_id="AUTH-TAMPER-002",
            nonce="NONCE-TAMPER-002",
            expected_parent_revision_id=original.revision_id,
        )
        record = repository.create_owner_authorized(
            memory_id=original.memory_id,
            content=content,
            source="owner",
            authorization_id="AUTH-TAMPER-002",
            nonce="NONCE-TAMPER-002",
            authorization_signature=signature,
            expected_revision_id=original.revision_id,
        )
        record.parent_revision_id = "UNEXPECTED-PARENT"
        assert verify_record_owner_approval(record) is False
    finally:
        session.close()
        engine.dispose()
def test_owner_authorized_write_records_exactly_one_provenance_event(tmp_path):
    engine, session = make_test_session()
    try:
        manifest_store = IntegrityManifestStore(
            manifest_dir=tmp_path / "integrity_manifests"
        )

        repository = MemoryRepository(
            session,
            manifest_store=manifest_store,
        )

        original = repository.create(
            memory_id="OWNER-PROVENANCE-001",
            content="Original policy",
            source="test",
            source_type="policy",
        )

        content = "Updated authorized policy"
        authorization_id = "AUTH-OWNER-PROVENANCE-001"
        nonce = "NONCE-OWNER-PROVENANCE-001"

        signature = sign_test_approval(
            memory_id=original.memory_id,
            content=content,
            authorization_id=authorization_id,
            nonce=nonce,
            expected_parent_revision_id=original.revision_id,
        )

        record = repository.create_owner_authorized(
    memory_id=original.memory_id,
    content=content,
    source="owner",
    authorization_id=authorization_id,
    nonce=nonce,
    authorization_signature=signature,
    expected_revision_id=original.revision_id,
    record_provenance=True,
)

        events = session.query(ProvenanceEvent).filter_by(
            memory_id=record.memory_id,
            version=record.version,
        ).all()

        assert len(events) == 1
        assert events[0].memory_record_id == record.id
        assert events[0].actor == "enterprise_owner"
        assert events[0].operation == "MEMORY_WRITE"
    finally:
        session.close()
        engine.dispose()


