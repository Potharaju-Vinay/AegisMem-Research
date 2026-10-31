from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from core.integrity.manifest_store import IntegrityManifestStore
from core.memory.database import Base
from core.memory.repository import MemoryRepository
from core.recovery.validator import RecoveryValidator


def create_test_store(tmp_path):
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


def test_validator_separates_content_validity_from_authorization(tmp_path):
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)

    with Session(engine) as session:
        repository = MemoryRepository(session)
        record = repository.create(
            memory_id="TEST-VALIDATOR",
            content="Recovered policy content",
            source="test",
            source_type="controlled_test",
        )

        store = create_test_store(tmp_path)
        store.create_for_record(record)
        validator = RecoveryValidator(repository, manifest_store=store)

        with patch.object(
            validator,
            "_has_valid_authorization",
            return_value=False,
        ):
            result = validator.validate("TEST-VALIDATOR")

        assert result["content_valid"] is True
        assert result["valid"] is True
        assert result["authorization"] is False
        assert result["fully_verified"] is False

    engine.dispose()


def test_validator_reports_fully_verified_content(tmp_path):
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)

    with Session(engine) as session:
        repository = MemoryRepository(session)
        record = repository.create(
            memory_id="TEST-VALIDATOR-2",
            content="Verified policy content",
            source="test",
            source_type="controlled_test",
        )

        store = create_test_store(tmp_path)
        store.create_for_record(record)
        validator = RecoveryValidator(repository, manifest_store=store)

        with (
            patch.object(
                validator,
                "_has_valid_authorization",
                return_value=True,
            ),
            patch.object(
                validator,
                "_verify_provenance",
                return_value={
                    "verified": True,
                    "checkpoint_status": "VALID",
                    "trusted_head_status": "VALID",
                    "reason": "Provenance verified.",
                },
            ),
        ):
            result = validator.validate("TEST-VALIDATOR-2")

        assert result["content_valid"] is True
        assert result["authorization"] is True
        assert result["fully_verified"] is True

    engine.dispose()
    
def test_validator_does_not_fully_verify_when_provenance_fails(tmp_path):
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)

    with Session(engine) as session:
        repository = MemoryRepository(session)
        record = repository.create(
            memory_id="TEST-PROVENANCE-FAIL",
            content="Verified policy content",
            source="test",
            source_type="controlled_test",
        )

        store = create_test_store(tmp_path)
        store.create_for_record(record)
        validator = RecoveryValidator(repository, manifest_store=store)

        with (
            patch.object(
                validator,
                "_has_valid_authorization",
                return_value=True,
            ),
            patch.object(
                validator,
                "_verify_provenance",
                return_value={
                    "verified": False,
                    "checkpoint_status": "INVALID",
                    "trusted_head_status": "INVALID",
                    "reason": "Test provenance failure.",
                },
            ),
        ):
            result = validator.validate("TEST-PROVENANCE-FAIL")

        assert result["content_valid"] is True
        assert result["provenance_verified"] is False
        assert result["fully_verified"] is False

    engine.dispose()
def test_recovery_attestation_alone_does_not_bypass_provenance(tmp_path):
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)

    with Session(engine) as session:
        repository = MemoryRepository(session)
        record = repository.create(
            memory_id="TEST-RECOVERY-ATTESTATION",
            content="Recovered policy content",
            source="recovery",
            source_type="verified_recovery",
        )

        store = create_test_store(tmp_path)
        store.create_for_record(record)
        validator = RecoveryValidator(repository, manifest_store=store)

        with (
            patch.object(
                validator,
                "_has_valid_authorization",
                return_value=False,
            ),
            patch.object(
                validator,
                "_has_valid_recovery_attestation",
                return_value=True,
            ),
            patch.object(
                validator,
                "_verify_provenance",
                return_value={
                    "verified": False,
                    "checkpoint_status": "INVALID",
                    "trusted_head_status": "INVALID",
                    "reason": "Provenance verification failed.",
                },
            ),
        ):
            result = validator.validate("TEST-RECOVERY-ATTESTATION")

        assert result["owner_authorization_valid"] is False
        assert result["recovery_attestation_valid"] is True
        assert result["provenance_verified"] is False
        assert result["recovery_provenance_verified"] is False
        assert result["fully_verified"] is False

    engine.dispose()

def test_validator_does_not_fully_verify_when_manifest_is_missing(tmp_path):
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)

    try:
        with Session(engine) as session:
            repository = MemoryRepository(session)
            record = repository.create(
                memory_id="TEST-MISSING-MANIFEST",
                content="Trusted policy content",
                source="test",
                source_type="controlled_test",
            )

            store = create_test_store(tmp_path)
            store.create_for_record(record)
            manifest_path = store._path(record.memory_id, record.version)
            validator = RecoveryValidator(
                repository,
                manifest_store=store,
            )

            manifest_path.unlink()

            result = validator.validate("TEST-MISSING-MANIFEST")

            assert result["content_valid"] is False
            assert result["fully_verified"] is False
    finally:
        engine.dispose()
        
def test_validator_classifies_verified_recovery_separately(
    tmp_path,
):
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)

    try:
        with Session(engine) as session:
            repository = MemoryRepository(session)
            record = repository.create(
                memory_id="TEST-RECOVERY-CLASSIFICATION",
                content="Recovered policy content",
                source="recovery",
                source_type="verified_recovery",
            )

            store = create_test_store(tmp_path)
            store.create_for_record(record)

            validator = RecoveryValidator(
                repository,
                manifest_store=store,
            )

            with (
                patch.object(
                    validator,
                    "_has_valid_authorization",
                    return_value=False,
                ),
                patch.object(
                    validator,
                    "_has_valid_recovery_attestation",
                    return_value=True,
                ),
                patch.object(
                    validator,
                    "_verify_provenance",
                    return_value={
                        "verified": True,
                        "checkpoint_status": "VALID",
                        "trusted_head_status": "VALID",
                        "reason": "Test provenance verified.",
                    },
                ),
            ):
                result = validator.validate(
                    "TEST-RECOVERY-CLASSIFICATION"
                )

            assert result["content_valid"] is True
            assert result["owner_authorization_valid"] is False
            assert result["recovery_attestation_valid"] is True
            assert result["provenance_verified"] is True
            assert result["recovery_provenance_verified"] is True
            assert result["authorization_type"] == "RECOVERY"
            assert result["fully_verified"] is True
            assert result["owner_fully_verified"] is False
            assert result["recovery_fully_verified"] is True
    finally:
        engine.dispose()
def test_validator_fails_closed_when_attestation_verification_raises(tmp_path):
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)

    try:
        with Session(engine) as session:
            repository = MemoryRepository(session)
            record = repository.create(
                memory_id="TEST-ATTESTATION-EXCEPTION",
                content="Recovered policy content",
                source="test",
                source_type="controlled_test",
            )

            store = create_test_store(tmp_path)
            store.create_for_record(record)

            validator = RecoveryValidator(
                repository,
                manifest_store=store,
            )

            with (
                patch.object(
                    validator,
                    "_has_valid_authorization",
                    return_value=False,
                ),
                patch.object(
                    validator.attestation_store,
                    "load_verified_attestation",
                    side_effect=RuntimeError(
                        "simulated attestation verification failure"
                    ),
                ),
                patch.object(
                    validator,
                    "_verify_provenance",
                    return_value={
                        "verified": True,
                        "checkpoint_status": "VALID",
                        "trusted_head_status": "VALID",
                        "reason": "Test provenance verified.",
                    },
                ),
            ):
                result = validator.validate(
                    "TEST-ATTESTATION-EXCEPTION"
                )

            assert result["recovery_attestation_valid"] is False
            assert result["recovery_provenance_verified"] is False
            assert result["fully_verified"] is False
    finally:
        engine.dispose()
