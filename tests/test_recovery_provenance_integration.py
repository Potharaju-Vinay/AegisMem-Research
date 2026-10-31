
import json

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from core.memory.database import Base
from core.memory.repository import MemoryRepository
from core.provenance.manager import ProvenanceManager
from core.provenance.checkpoint import ProvenanceCheckpointStore
from core.provenance.trusted_head import TrustedCheckpointHeadStore


def test_recovery_event_can_be_checkpointed_and_trusted(tmp_path):
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)

    private_key = Ed25519PrivateKey.generate()
    private_path = tmp_path / "private.pem"
    public_path = tmp_path / "public.pem"

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

    checkpoint_store = ProvenanceCheckpointStore(
        checkpoint_dir=tmp_path / "checkpoints",
        private_key_path=private_path,
        public_key_path=public_path,
    )

    head_store = TrustedCheckpointHeadStore(
        head_dir=tmp_path / "heads",
        private_key_path=private_path,
        public_key_path=public_path,
        checkpoint_store=checkpoint_store,
    )

    try:
        with Session(engine) as session:
            repository = MemoryRepository(session)
            manager = ProvenanceManager(session)

            memory = repository.create(
                memory_id="RECOVERY-PROVENANCE-TEST",
                content="Trusted test policy",
                source="test",
                source_type="test",
            )

            manager.record(
                memory_record_id=memory.id,
                memory_id=memory.memory_id,
                version=memory.version,
                actor="test-owner",
                operation="CREATE",
                source=memory.source,
                source_type=memory.source_type,
            )

            events = manager.get_events(memory.memory_id)

            checkpoint_store.create_checkpoint(events)
            head_store.advance(events)

            assert checkpoint_store.verify_checkpoint(events) == "VALID"
            assert head_store.verify_events(events) == "VALID"
    finally:
        engine.dispose()
