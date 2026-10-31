from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from core.integrity.hash import calculate_version_hash
from core.integrity.manifest_store import IntegrityManifestStore
from core.integrity.verifier import IntegrityVerifier
from core.memory.database import Base
from core.memory.repository import MemoryRepository


def test_coordinated_content_and_hash_tampering(tmp_path):
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

    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()

    try:
        repository = MemoryRepository(session)
        memory = repository.create(
            memory_id="POLICY-COORDINATED-ATTACK-001",
            content="Refunds are available within 30 days.",
            source="refund_policy",
            source_type="enterprise_policy",
        )

        store.create_for_record(memory)
        verifier = IntegrityVerifier(manifest_store=store)
        assert verifier.verify_memory(memory)

        memory.content = "Refunds are available within 365 days."
        memory.content_hash = calculate_version_hash(
            memory.content, memory.previous_hash
        )
        session.commit()
        session.refresh(memory)

        assert not verifier.verify_memory(memory), (
            "The verifier accepted coordinated content-and-hash tampering."
        )
    finally:
        session.close()
        engine.dispose()
