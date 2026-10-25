import pytest

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)
from cryptography.hazmat.primitives import serialization
from sqlalchemy import create_engine, delete
from sqlalchemy.orm import Session

from core.integrity.manifest_store import IntegrityManifestStore
from core.memory.database import Base
from core.memory.repository import MemoryRepository
from core.recovery.executor import RecoveryExecutor
from tests.owner_approval_test_utils import sign_test_approval


def create_test_manifest_store(tmp_path):
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

    return IntegrityManifestStore(
        manifest_dir=tmp_path / "manifests",
        private_key_path=private_path,
        public_key_path=public_path,
    )


def test_recovery_after_latest_revision_deletion(tmp_path):
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)

    from sqlalchemy import text

    with engine.begin() as connection:
        connection.execute(
            text(
            "CREATE TABLE authorization_nonces ("
            "nonce VARCHAR(128) PRIMARY KEY, "
            "authorization_id VARCHAR(128) NOT NULL, "
            "created_at DATETIME NOT NULL)"
            )
        )

    with Session(engine) as session:
        repository = MemoryRepository(session)
        manifest_store = create_test_manifest_store(tmp_path)

        memory_id = "TEST-DELETION-RECOVERY"
        content = "Trusted original policy"

        authorization_id = "TEST-DELETION-AUTH"
        nonce = "TEST-DELETION-NONCE"

        signature = sign_test_approval(
            memory_id=memory_id,
            content=content,
            expected_parent_revision_id=None,
            authorization_id=authorization_id,
            nonce=nonce,
        )

        trusted = repository.create_owner_authorized(
            memory_id=memory_id,
            content=content,
            source="controlled_test",
            authorization_id=authorization_id,
            nonce=nonce,
            authorization_signature=signature,
            expected_revision_id=None,
        )

        manifest_store.create_for_record(trusted)

        compromised = repository.create(
            memory_id=memory_id,
            content="Untrusted follow-up revision",
            source="controlled_test",
            source_type="controlled_test",
        )

        manifest_store.create_for_record(compromised)

        session.execute(
            delete(type(compromised)).where(
                type(compromised).id == compromised.id
            )
        )
        session.commit()

        assert repository.get_version(memory_id, 2) is None
        assert repository.get_version(memory_id, 1) is not None

        result = RecoveryExecutor(
            repository,
            manifest_store=manifest_store,
        ).rollback(
            compromised_memory_id=memory_id,
            trusted_version=trusted.version,
        )

        assert result.success is False
        assert "quarantined" in result.message.lower()

        restored = repository.get_version(memory_id, 2)
        assert restored is not None
        assert restored.status == "quarantined"

        assert repository.get_version(memory_id, 1).content == content

    engine.dispose()