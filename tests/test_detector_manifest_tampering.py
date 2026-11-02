from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from core.detection.detector import MemoryCompromiseDetector
from core.integrity.manifest_store import IntegrityManifestStore
from core.memory.database import Base
from core.memory.repository import MemoryRepository


def test_detector_flags_direct_edit_against_signed_manifest(tmp_path):
    private_key = Ed25519PrivateKey.generate()
    private_path = tmp_path / "anchor_private.pem"
    public_path = tmp_path / "anchor_public.pem"

    private_path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    public_path.write_bytes(
        private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )

    store = IntegrityManifestStore(
        manifest_dir=tmp_path / "manifests",
        private_key_path=private_path,
        public_key_path=public_path,
    )

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

    try:
        repository = MemoryRepository(session)
        record = repository.create(
            memory_id="TEST-MANIFEST-TAMPER",
            content="Refunds allowed within 30 days.",
            source="test",
            source_type="policy",
        )

        store.create_for_record(record)
        assert store.verify_record(record) is True

        record.content = "Refunds allowed within 365 days."
        session.commit()
        session.expire_all()

        detector = MemoryCompromiseDetector(
            repository=repository,
            manifest_store=store,
        )
        result = detector.detect("TEST-MANIFEST-TAMPER")

        assert result.evidence.integrity_anchor_status == "TAMPERED"
        assert result.evidence.integrity_compromised is True
        assert result.attribution == "INCONCLUSIVE"
    finally:
        session.close()
        engine.dispose()
