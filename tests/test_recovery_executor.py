
from unittest.mock import patch

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from core.memory.database import Base
from core.memory.repository import MemoryRepository
from core.recovery.executor import RecoveryExecutor
from tests.owner_approval_test_utils import sign_test_approval
from core.integrity.manifest_store import IntegrityManifestStore
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from core.provenance.manager import ProvenanceManager
from core.provenance.checkpoint import ProvenanceCheckpointStore
from core.provenance.trusted_head import TrustedCheckpointHeadStore



def test_executor_rejects_broken_history_link(tmp_path):
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)

    with Session(engine) as session:
        manifest_store = IntegrityManifestStore(
            manifest_dir=tmp_path / "integrity_manifests"
        )
        repository = MemoryRepository(
    session,
    manifest_store=manifest_store,
)

        with patch(
            "core.memory.repository.verify_and_register_nonce",
            return_value=True
        ):
            trusted = repository.create_owner_authorized(
    memory_id="TEST-EXECUTOR",
    content="Trusted policy content",
    source="test",
    authorization_id="TEST-EXECUTOR-AUTH",
    nonce="TEST-EXECUTOR-NONCE",
    authorization_signature=sign_test_approval(
        "TEST-EXECUTOR",
        "Trusted policy content",
        "TEST-EXECUTOR-AUTH",
        "TEST-EXECUTOR-NONCE",
    ),
)
            

        repository.create(
            memory_id="TEST-EXECUTOR",
            content="Modified policy content",
            source="test",
            source_type="controlled_test"
        )

        trusted.previous_hash = "broken-history-link"
        session.commit()

        executor = RecoveryExecutor(repository)
        result = executor.rollback(
            compromised_memory_id="TEST-EXECUTOR",
            trusted_version=trusted.version
        )

        assert result.success is False
        assert "history link verification failed" in result.message.lower()
        assert len(repository.get_history("TEST-EXECUTOR")) == 2

    engine.dispose()
    

def test_executor_rejects_unauthorized_recovery_target():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)

    with Session(engine) as session:
        repository = MemoryRepository(session)

        repository.create(
            memory_id="TEST-UNAUTHORIZED-EXECUTOR",
            content="Unverified baseline content",
            source="test",
            source_type="controlled_test"
        )

        repository.create(
            memory_id="TEST-UNAUTHORIZED-EXECUTOR",
            content="Modified content",
            source="test",
            source_type="controlled_test"
        )

        executor = RecoveryExecutor(repository)

        result = executor.rollback(
            compromised_memory_id="TEST-UNAUTHORIZED-EXECUTOR",
            trusted_version=1
        )

        assert result.success is False
        assert "authorization verification failed" in result.message.lower()
        assert len(repository.get_history("TEST-UNAUTHORIZED-EXECUTOR")) == 2

    engine.dispose()



def test_executor_rejects_recovery_when_provenance_checkpoint_is_missing(tmp_path):
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)

    try:
        with Session(engine) as session:
            manifest_store = IntegrityManifestStore(
                manifest_dir=tmp_path / "integrity_manifests"
            )
            repository = MemoryRepository(
                session,
                manifest_store=manifest_store,
            )

            with patch(
                "core.memory.repository.verify_and_register_nonce",
                return_value=True,
            ):
                trusted = repository.create_owner_authorized(
                    memory_id="TEST-MISSING-CHECKPOINT",
                    content="Trusted policy content",
                    source="test",
                    authorization_id="TEST-MISSING-CHECKPOINT-AUTH",
                    nonce="TEST-MISSING-CHECKPOINT-NONCE",
                    authorization_signature=sign_test_approval(
                        "TEST-MISSING-CHECKPOINT",
                        "Trusted policy content",
                        "TEST-MISSING-CHECKPOINT-AUTH",
                        "TEST-MISSING-CHECKPOINT-NONCE",
                    ),
                )

            repository.create(
                memory_id="TEST-MISSING-CHECKPOINT",
                content="Modified policy content",
                source="test",
                source_type="controlled_test",
            )

            executor = RecoveryExecutor(
    repository,
    manifest_store=manifest_store,
)

            result = executor.rollback(
                compromised_memory_id="TEST-MISSING-CHECKPOINT",
                trusted_version=trusted.version,
            )

            assert result.success is False
            assert (
                "provenance" in result.message.lower()
                or "checkpoint" in result.message.lower()
            )
            assert len(
                repository.get_history("TEST-MISSING-CHECKPOINT")
            ) == 2
    finally:
        engine.dispose()

def test_executor_quarantines_revision_when_attestation_creation_fails(
    tmp_path,
):
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)

    try:
        with Session(engine) as session:
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

            manifest_store = IntegrityManifestStore(
                manifest_dir=tmp_path / "manifests",
                private_key_path=private_path,
                public_key_path=public_path,
            )
            repository = MemoryRepository(
                session,
                manifest_store=manifest_store,
            )

            memory_id = "TEST-ATTESTATION-FAILURE"

            with patch(
                "core.memory.repository.verify_and_register_nonce",
                return_value=True,
            ):
                trusted = repository.create_owner_authorized(
                    memory_id=memory_id,
                    content="Trusted policy content",
                    source="test",
                    authorization_id="TEST-ATTESTATION-FAILURE-AUTH",
                    nonce="TEST-ATTESTATION-FAILURE-NONCE",
                    authorization_signature=sign_test_approval(
                        memory_id,
                        "Trusted policy content",
                        "TEST-ATTESTATION-FAILURE-AUTH",
                        "TEST-ATTESTATION-FAILURE-NONCE",
                    ),
                )

            provenance_manager = ProvenanceManager(session)
            provenance_dir = tmp_path / "provenance"

            checkpoint_store = ProvenanceCheckpointStore(
                checkpoint_dir=provenance_dir / "checkpoints",
                private_key_path=private_path,
                public_key_path=public_path,
            )

            trusted_head_store = TrustedCheckpointHeadStore(
                head_dir=provenance_dir / "trusted_heads",
                private_key_path=private_path,
                public_key_path=public_path,
                checkpoint_store=checkpoint_store,
            )

            provenance_manager.record(
                memory_record_id=trusted.id,
                memory_id=memory_id,
                version=trusted.version,
                actor="controlled_test",
                operation="CREATE",
                source=trusted.source,
                source_type=trusted.source_type,
            )

            events = provenance_manager.get_events(memory_id)
            checkpoint_store.create_checkpoint(events)
            trusted_head_store.advance(events)

            repository.create(
                memory_id=memory_id,
                content="Modified policy content",
                source="test",
                source_type="controlled_test",
            )

            executor = RecoveryExecutor(
                repository,
                manifest_store=manifest_store,
                provenance_manager=provenance_manager,
                checkpoint_store=checkpoint_store,
                trusted_head_store=trusted_head_store,
            )

            with patch.object(
                executor.attestation_store,
                "create_for_record",
                side_effect=RuntimeError(
                    "simulated attestation failure"
                ),
            ):
                result = executor.rollback(
                    compromised_memory_id=memory_id,
                    trusted_version=trusted.version,
                )

            history = repository.get_history(memory_id)
            latest = history[-1]

            assert result.success is False
            assert result.restored_version is not None
            assert "quarantined" in result.message.lower()
            assert latest.status == "quarantined"
            assert len(history) == 3
    finally:
        engine.dispose()
