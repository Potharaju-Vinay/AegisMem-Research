import json
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session
from sqlalchemy import update
from core.memory.models import MemoryRecord
from core.memory.database import Base
from core.memory.repository import MemoryRepository
from core.integrity.manifest_store import IntegrityManifestStore
from core.recovery.resolver import TrustedVersionResolver
from tests.owner_approval_test_utils import sign_test_approval


def test_resolver_rejects_unverified_historical_revision(tmp_path):
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)

    with engine.begin() as connection:
        connection.execute(
            text(
                "CREATE TABLE authorization_nonces ("
                "nonce VARCHAR(128) PRIMARY KEY, "
                "authorization_id VARCHAR(128) NOT NULL, "
                "created_at DATETIME NOT NULL)"
            )
        )

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

    try:
        with Session(engine) as session:
            repository = MemoryRepository(
                session,
                manifest_store=manifest_store,
            )

            memory_id = "RESOLVER-REGRESSION-001"
            content = "Controlled trusted baseline"
            authorization_id = "RESOLVER-AUTH-001"
            nonce = "RESOLVER-NONCE-001"

            trusted = repository.create_owner_authorized(
                memory_id=memory_id,
                content=content,
                source="isolated_regression_test",
                authorization_id=authorization_id,
                nonce=nonce,
                authorization_signature=sign_test_approval(
                    memory_id=memory_id,
                    content=content,
                    authorization_id=authorization_id,
                    nonce=nonce,
                    expected_parent_revision_id=None,
                ),
                expected_revision_id=None,
            )
            session.refresh(trusted)
            assert manifest_store.has_manifest(trusted)
            assert manifest_store.verify_record(trusted)

            # Add a later revision so the trusted baseline is historical.
            repository.create(
                memory_id=memory_id,
                content="Temporary follow-up revision",
                source="isolated_regression_test",
                source_type="controlled_test",
            )

            resolver = TrustedVersionResolver(
                repository,
                manifest_store=manifest_store,
            )
            report = resolver.evaluate_candidates(memory_id)

            assert report["decision"] == "TRUSTED_RECOVERY_POINT"
            assert report["selected_version"] == trusted.version

            selected = next(
                candidate
                for candidate in report["candidates"]
                if candidate["version"] == trusted.version
            )
            assert selected["status"] == "TRUSTED_CANDIDATE"
            assert all(selected["checks"].values())

    finally:
        engine.dispose()

def test_resolver_rejects_unverified_historical_revision_without_manifest(tmp_path):
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)

    try:
        with Session(engine) as session:
            repository = MemoryRepository(session)
            memory_id = "RESOLVER-UNVERIFIED-001"

            first = repository.create(
                memory_id=memory_id,
                content="Unverified historical content",
                source="isolated_regression_test",
                source_type="controlled_test",
            )

            repository.create(
                memory_id=memory_id,
                content="Latest follow-up content",
                source="isolated_regression_test",
                source_type="controlled_test",
            )

            resolver = TrustedVersionResolver(repository)
            report = resolver.evaluate_candidates(memory_id)

            assert report["decision"] == "NO_TRUSTED_RECOVERY_POINT"
            assert report["selected_version"] is None

            candidate = report["candidates"][0]
            assert candidate["version"] == first.version
            assert candidate["checks"]["owner_authorization"] is False
            assert candidate["checks"]["integrity_manifest"] is False

    finally:
        engine.dispose()

def test_resolver_returns_no_trusted_point_when_all_candidates_are_unverified():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)

    try:
        with Session(engine) as session:
            repository = MemoryRepository(session)
            memory_id = "RESOLVER-NO-TRUSTED-POINT"

            repository.create(
                memory_id=memory_id,
                content="Unverified historical content",
                source="isolated_negative_test",
                source_type="controlled_test",
            )

            repository.create(
                memory_id=memory_id,
                content="Unverified latest content",
                source="isolated_negative_test",
                source_type="controlled_test",
            )

            resolver = TrustedVersionResolver(repository)
            report = resolver.evaluate_candidates(memory_id)

            assert report["decision"] == "NO_TRUSTED_RECOVERY_POINT"
            assert report["selected_version"] is None
            assert report["candidates"]

            for candidate in report["candidates"]:
                assert candidate["status"] != "TRUSTED_CANDIDATE"
                assert candidate["checks"]["owner_authorization"] is False
                assert candidate["checks"]["integrity_manifest"] is False
    finally:
        engine.dispose()

def test_resolver_rejects_tampered_historical_content(tmp_path):
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)

    with engine.begin() as connection:
        connection.execute(
            text(
                "CREATE TABLE authorization_nonces ("
                "nonce VARCHAR(128) PRIMARY KEY, "
                "authorization_id VARCHAR(128) NOT NULL, "
                "created_at DATETIME NOT NULL)"
            )
        )

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

    try:
        with Session(engine) as session:
            repository = MemoryRepository(
                session,
                manifest_store=manifest_store,
            )

            memory_id = "RESOLVER-TAMPER-001"
            content = "Trusted baseline content"
            authorization_id = "RESOLVER-TAMPER-AUTH"
            nonce = "RESOLVER-TAMPER-NONCE"

            trusted = repository.create_owner_authorized(
                memory_id=memory_id,
                content=content,
                source="isolated_regression_test",
                authorization_id=authorization_id,
                nonce=nonce,
                authorization_signature=sign_test_approval(
                    memory_id=memory_id,
                    content=content,
                    authorization_id=authorization_id,
                    nonce=nonce,
                    expected_parent_revision_id=None,
                ),
                expected_revision_id=None,
            )

            repository.create(
                memory_id=memory_id,
                content="Later follow-up revision",
                source="isolated_regression_test",
                source_type="controlled_test",
            )

            session.execute(
                update(MemoryRecord)
                .where(MemoryRecord.id == trusted.id)
                .values(content="TAMPERED baseline content")
            )
            session.commit()

            resolver = TrustedVersionResolver(
                repository,
                manifest_store=manifest_store,
            )
            report = resolver.evaluate_candidates(memory_id)

            assert report["decision"] == "NO_TRUSTED_RECOVERY_POINT"
            assert report["selected_version"] is None

            candidate = next(
                item
                for item in report["candidates"]
                if item["version"] == trusted.version
            )
            assert candidate["status"] == "REJECTED_CANDIDATE"
            assert candidate["checks"]["history_chain"] is False
            assert candidate["checks"]["integrity_manifest"] is False

    finally:
        engine.dispose()

def test_resolver_rejects_tampered_signed_manifest(tmp_path):
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)

    with engine.begin() as connection:
        connection.execute(
            text(
                "CREATE TABLE authorization_nonces ("
                "nonce VARCHAR(128) PRIMARY KEY, "
                "authorization_id VARCHAR(128) NOT NULL, "
                "created_at DATETIME NOT NULL)"
            )
        )

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

    try:
        with Session(engine) as session:
            repository = MemoryRepository(
                session,
                manifest_store=manifest_store,
            )

            memory_id = "RESOLVER-MANIFEST-TAMPER"
            content = "Trusted baseline"
            authorization_id = "MANIFEST-TAMPER-AUTH"
            nonce = "MANIFEST-TAMPER-NONCE"

            trusted = repository.create_owner_authorized(
                memory_id=memory_id,
                content=content,
                source="isolated_regression_test",
                authorization_id=authorization_id,
                nonce=nonce,
                authorization_signature=sign_test_approval(
                    memory_id=memory_id,
                    content=content,
                    authorization_id=authorization_id,
                    nonce=nonce,
                    expected_parent_revision_id=None,
                ),
                expected_revision_id=None,
            )

            repository.create(
                memory_id=memory_id,
                content="Later follow-up revision",
                source="isolated_regression_test",
                source_type="controlled_test",
            )

            manifest_path = manifest_store._path(
                trusted.memory_id,
                trusted.version,
            )
            manifest = json.loads(
                manifest_path.read_text(encoding="utf-8")
            )
            manifest["content_hash"] = "tampered-hash"
            manifest_path.write_text(
                json.dumps(manifest),
                encoding="utf-8",
            )

            assert manifest_store.verify_record(trusted) is False

            resolver = TrustedVersionResolver(
                repository,
                manifest_store=manifest_store,
            )
            report = resolver.evaluate_candidates(memory_id)

            assert report["decision"] == "NO_TRUSTED_RECOVERY_POINT"
            assert report["selected_version"] is None

            candidate = next(
                item
                for item in report["candidates"]
                if item["version"] == trusted.version
            )
            assert candidate["status"] == "REJECTED_CANDIDATE"
            assert candidate["checks"]["integrity_manifest"] is False

    finally:
        engine.dispose()

