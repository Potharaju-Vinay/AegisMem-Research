from tests.owner_approval_test_utils import sign_test_approval

from unittest.mock import patch

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from core.memory.database import Base
from core.memory.repository import MemoryRepository
from core.recovery.resolver import TrustedVersionResolver

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from core.integrity.manifest_store import IntegrityManifestStore


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


def test_resolver_selects_authorized_trusted_version(tmp_path):
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
                memory_id="TEST-RESOLVER",
                content="Trusted policy content",
                source="test",
                authorization_id="TEST-AUTH-001",
                nonce="TEST-NONCE-001", authorization_signature=sign_test_approval("TEST-RESOLVER", "Trusted policy content", "TEST-AUTH-001", "TEST-NONCE-001")
            )

        store = create_test_store(tmp_path)
        store.create_for_record(trusted)

        repository.create(
            memory_id="TEST-RESOLVER",
            content="Modified policy content",
            source="test",
            source_type="controlled_test"
        )

        resolver = TrustedVersionResolver(repository, manifest_store=store)
        selected = resolver.find_trusted_version("TEST-RESOLVER")

        assert selected is not None
        assert selected.version == trusted.version
        assert selected.content == "Trusted policy content"
        assert selected.authorization_state == "AUTHORIZED"

    engine.dispose()

def test_resolver_rejects_tampered_trusted_version(tmp_path):
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
                memory_id="TEST-TAMPER",
                content="Trusted policy content",
                source="test",
                authorization_id="TEST-AUTH-002",
                nonce="TEST-NONCE-002", authorization_signature=sign_test_approval("TEST-TAMPER", "Trusted policy content", "TEST-AUTH-002", "TEST-NONCE-002")
            )

        repository.create(
            memory_id="TEST-TAMPER",
            content="Modified policy content",
            source="test",
            source_type="controlled_test"
        )

        trusted.content_hash = "tampered-hash"
        session.commit()

        resolver = TrustedVersionResolver(repository)
        selected = resolver.find_trusted_version("TEST-TAMPER")

        assert selected is None

    engine.dispose()


def test_resolver_rejects_candidate_when_earlier_history_is_tampered(tmp_path):
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
            first = repository.create_owner_authorized(
                memory_id="TEST-CHAIN-TAMPER",
                content="Original trusted content",
                source="test",
                authorization_id="TEST-CHAIN-AUTH-001",
                nonce="TEST-CHAIN-NONCE-001", authorization_signature=sign_test_approval("TEST-CHAIN-TAMPER", "Original trusted content", "TEST-CHAIN-AUTH-001", "TEST-CHAIN-NONCE-001")
            )

            repository.create_owner_authorized(
                memory_id="TEST-CHAIN-TAMPER",
                content="Second trusted version",
                source="test",
                authorization_id="TEST-CHAIN-AUTH-002",
                nonce="TEST-CHAIN-NONCE-002", authorization_signature=sign_test_approval("TEST-CHAIN-TAMPER", "Second trusted version", "TEST-CHAIN-AUTH-002", "TEST-CHAIN-NONCE-002", first.revision_id), expected_revision_id=first.revision_id
            )

        repository.create(
            memory_id="TEST-CHAIN-TAMPER",
            content="Latest modified version",
            source="test",
            source_type="controlled_test"
        )

        first.content = "Tampered original content"
        session.commit()

        resolver = TrustedVersionResolver(repository)
        selected = resolver.find_trusted_version("TEST-CHAIN-TAMPER")

        assert selected is None

    engine.dispose()


def test_repository_rejects_forged_owner_approval(tmp_path):
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

            signature = sign_test_approval(
                "TEST-FORGED",
                "Approved content",
                "TEST-FORGED-AUTH",
                "TEST-FORGED-NONCE",
            )

            with patch(
                "core.memory.repository.verify_and_register_nonce",
                return_value=True,
            ):
                try:
                    repository.create_owner_authorized(
                        memory_id="TEST-FORGED",
                        content="Modified content",
                        source="test",
                        authorization_id="TEST-FORGED-AUTH",
                        nonce="TEST-FORGED-NONCE",
                        authorization_signature=signature,
                        expected_revision_id=None,
                    )
                    assert False, "Forged approval should be rejected"
                except ValueError as exc:
                    assert "signature verification failed" in str(exc)

            assert repository.get_latest("TEST-FORGED") is None
    finally:
        engine.dispose()


def test_repository_rejects_stale_expected_revision(tmp_path):
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
                first = repository.create_owner_authorized(
                    memory_id="TEST-STALE",
                    content="First trusted content",
                    source="test",
                    authorization_id="TEST-STALE-AUTH-1",
                    nonce="TEST-STALE-NONCE-1",
                    authorization_signature=sign_test_approval(
                        "TEST-STALE",
                        "First trusted content",
                        "TEST-STALE-AUTH-1",
                        "TEST-STALE-NONCE-1",
                    ),
                    expected_revision_id=None,
                )

                second = repository.create_owner_authorized(
                    memory_id="TEST-STALE",
                    content="Second trusted content",
                    source="test",
                    authorization_id="TEST-STALE-AUTH-2",
                    nonce="TEST-STALE-NONCE-2",
                    authorization_signature=sign_test_approval(
                        "TEST-STALE",
                        "Second trusted content",
                        "TEST-STALE-AUTH-2",
                        "TEST-STALE-NONCE-2",
                        first.revision_id,
                    ),
                    expected_revision_id=first.revision_id,
                )

                try:
                    repository.create_owner_authorized(
                        memory_id="TEST-STALE",
                        content="Stale write attempt",
                        source="test",
                        authorization_id="TEST-STALE-AUTH-3",
                        nonce="TEST-STALE-NONCE-3",
                        authorization_signature=sign_test_approval(
                            "TEST-STALE",
                            "Stale write attempt",
                            "TEST-STALE-AUTH-3",
                            "TEST-STALE-NONCE-3",
                            first.revision_id,
                        ),
                        expected_revision_id=first.revision_id,
                    )
                    assert False, "Stale revision should be rejected"
                except ValueError as exc:
                    assert "Stale or missing expected revision" in str(exc)

            latest = repository.get_latest("TEST-STALE")
            assert latest.revision_id == second.revision_id
            assert latest.version == 2
    finally:
        engine.dispose()


def test_repository_rejects_changed_authorization_id_or_nonce(tmp_path):
    cases = [
        ("TEST-BIND-AUTH", "Original authorization", "Changed authorization"),
        ("TEST-BIND-NONCE", "Original nonce", "Changed nonce"),
    ]

    for memory_id, original_value, changed_value in cases:
        engine = create_engine("sqlite:///:memory:")
        try:
            Base.metadata.create_all(engine)
            with sessionmaker(bind=engine)() as session:
                
                manifest_store = IntegrityManifestStore(
                manifest_dir=tmp_path / "integrity_manifests"
)
                repository = MemoryRepository(
    session,
    manifest_store=manifest_store,
)
                authorization_id = "TEST-BIND-AUTH-ID"
                nonce = "TEST-BIND-NONCE-ID"
                signed_authorization_id = (
                    original_value if memory_id == "TEST-BIND-AUTH"
                    else authorization_id
                )
                signed_nonce = (
                    original_value if memory_id == "TEST-BIND-NONCE"
                    else nonce
                )
                signature = sign_test_approval(
                    memory_id,
                    "Signed content",
                    signed_authorization_id,
                    signed_nonce,
                )

                with patch(
                    "core.memory.repository.verify_and_register_nonce",
                    return_value=True,
                ):
                    try:
                        repository.create_owner_authorized(
                            memory_id=memory_id,
                            content="Signed content",
                            source="test",
                            authorization_id=(
                                changed_value if memory_id == "TEST-BIND-AUTH"
                                else authorization_id
                            ),
                            nonce=(
                                changed_value if memory_id == "TEST-BIND-NONCE"
                                else nonce
                            ),
                            authorization_signature=signature,
                            expected_revision_id=None,
                        )
                        assert False, "Changed signed authorization data must be rejected"
                    except ValueError as exc:
                        assert "signature verification failed" in str(exc)

                assert repository.get_latest(memory_id) is None
        finally:
            engine.dispose()

def test_evaluate_candidates_reports_trust_checks_and_rejections(tmp_path):
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
                    memory_id="TEST-EVALUATION",
                    content="Trusted policy content",
                    source="test",
                    authorization_id="TEST-EVAL-AUTH",
                    nonce="TEST-EVAL-NONCE",
                    authorization_signature=sign_test_approval(
                        "TEST-EVALUATION",
                        "Trusted policy content",
                        "TEST-EVAL-AUTH",
                        "TEST-EVAL-NONCE",
                    ),
                )

            rejected = repository.create(
                memory_id="TEST-EVALUATION",
                content="Unapproved intermediate revision",
                source="test",
                source_type="controlled_test",
            )
            
            store = create_test_store(tmp_path)
            store.create_for_record(trusted)

            repository.create(
                memory_id="TEST-EVALUATION",
                content="Latest modified revision",
                source="test",
                source_type="controlled_test",
            )

            resolver = TrustedVersionResolver(repository, manifest_store=store)
            report = resolver.evaluate_candidates("TEST-EVALUATION")

            assert report["decision"] == "TRUSTED_RECOVERY_POINT"
            assert report["selected_version"] == trusted.version
            assert report["candidate_count"] == 2

            by_version = {
                item["version"]: item for item in report["candidates"]
            }
            trusted_result = by_version[trusted.version]
            rejected_result = by_version[rejected.version]

            assert trusted_result["status"] == "TRUSTED_CANDIDATE"
            assert all(trusted_result["checks"].values())

            assert rejected_result["status"] == "REJECTED_CANDIDATE"
            assert rejected_result["checks"]["owner_authorization"] is False
            assert any(
                "Owner approval signature" in reason
                for reason in rejected_result["reasons"]
            )
    finally:
        engine.dispose()



def test_candidate_report_and_selection_agree_after_historical_hash_tampering(tmp_path):
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
                    memory_id="TEST-REPORT-CONSISTENCY",
                    content="First trusted policy",
                    source="test",
                    authorization_id="TEST-REPORT-AUTH-1",
                    nonce="TEST-REPORT-NONCE-1",
                    authorization_signature=sign_test_approval(
                        "TEST-REPORT-CONSISTENCY",
                        "First trusted policy",
                        "TEST-REPORT-AUTH-1",
                        "TEST-REPORT-NONCE-1",
                    ),
                    expected_revision_id=None,
                )
                newer_trusted = repository.create_owner_authorized(
                    memory_id="TEST-REPORT-CONSISTENCY",
                    content="Second trusted policy",
                    source="test",
                    authorization_id="TEST-REPORT-AUTH-2",
                    nonce="TEST-REPORT-NONCE-2",
                    authorization_signature=sign_test_approval(
                        "TEST-REPORT-CONSISTENCY",
                        "Second trusted policy",
                        "TEST-REPORT-AUTH-2",
                        "TEST-REPORT-NONCE-2",
                        trusted.revision_id,
                    ),
                    expected_revision_id=trusted.revision_id,
                )
                
            store = create_test_store(tmp_path)
            store.create_for_record(trusted)
            store.create_for_record(newer_trusted)

            repository.create(
                memory_id="TEST-REPORT-CONSISTENCY",
                content="Latest unapproved revision",
                source="test",
                source_type="controlled_test",
            )

            newer_trusted.content_hash = "0" * 64
            session.commit()

            resolver = TrustedVersionResolver(repository, manifest_store=store)
            report = resolver.evaluate_candidates("TEST-REPORT-CONSISTENCY")
            selected = resolver.find_trusted_version("TEST-REPORT-CONSISTENCY")

            assert report["decision"] == "TRUSTED_RECOVERY_POINT"
            assert report["selected_version"] == trusted.version
            assert selected is not None
            assert selected.version == report["selected_version"]

            candidates = {
                candidate["version"]: candidate
                for candidate in report["candidates"]
            }
            assert candidates[newer_trusted.version]["status"] == "REJECTED_CANDIDATE"
            assert candidates[newer_trusted.version]["checks"]["history_chain"] is False
    finally:
        engine.dispose()

def test_resolver_refuses_recovery_when_no_candidate_meets_trust_threshold(tmp_path):
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
                    memory_id="TEST-NO-TRUSTED-CANDIDATE",
                    content="Historically authorized policy",
                    source="test",
                    authorization_id="TEST-NO-TRUST-AUTH",
                    nonce="TEST-NO-TRUST-NONCE",
                    authorization_signature=sign_test_approval(
                        "TEST-NO-TRUSTED-CANDIDATE",
                        "Historically authorized policy",
                        "TEST-NO-TRUST-AUTH",
                        "TEST-NO-TRUST-NONCE",
                    ),
                )

            trusted.trust_score = 0.1
        

            repository.create(
                memory_id="TEST-NO-TRUSTED-CANDIDATE",
                content="Latest unapproved revision",
                source="test",
                source_type="controlled_test",
            )
            session.commit()

            resolver = TrustedVersionResolver(repository)
            report = resolver.evaluate_candidates(
                "TEST-NO-TRUSTED-CANDIDATE"
            )

            assert report["decision"] == "NO_TRUSTED_RECOVERY_POINT"
            assert report["selected_version"] is None
            assert report["candidates"][0]["checks"]["trust_threshold"] is False
            assert resolver.find_trusted_version(
                "TEST-NO-TRUSTED-CANDIDATE"
            ) is None
    finally:
        engine.dispose()

def test_resolver_skips_candidate_with_missing_manifest(tmp_path):
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)

    try:
        with Session(engine) as session:
            store = create_test_store(tmp_path)
            repository = MemoryRepository(
                session,
                manifest_store=store,
            )

            with patch(
                "core.memory.repository.verify_and_register_nonce",
                return_value=True,
            ):
                older = repository.create_owner_authorized(
                    memory_id="TEST-MISSING-MANIFEST-RECOVERY",
                    content="Older trusted policy",
                    source="test",
                    authorization_id="TEST-MANIFEST-AUTH-1",
                    nonce="TEST-MANIFEST-NONCE-1",
                    authorization_signature=sign_test_approval(
                        "TEST-MISSING-MANIFEST-RECOVERY",
                        "Older trusted policy",
                        "TEST-MANIFEST-AUTH-1",
                        "TEST-MANIFEST-NONCE-1",
                    ),
                    expected_revision_id=None,
                )

                newer = repository.create_owner_authorized(
                    memory_id="TEST-MISSING-MANIFEST-RECOVERY",
                    content="Newer trusted policy",
                    source="test",
                    authorization_id="TEST-MANIFEST-AUTH-2",
                    nonce="TEST-MANIFEST-NONCE-2",
                    authorization_signature=sign_test_approval(
                        "TEST-MISSING-MANIFEST-RECOVERY",
                        "Newer trusted policy",
                        "TEST-MANIFEST-AUTH-2",
                        "TEST-MANIFEST-NONCE-2",
                        older.revision_id,
                    ),
                    expected_revision_id=older.revision_id,
                )

            repository.create(
                memory_id="TEST-MISSING-MANIFEST-RECOVERY",
                content="Unapproved latest revision",
                source="test",
                source_type="controlled_test",
            )

            newer_manifest_path = store._path(
                newer.memory_id,
                newer.version,
            )
            newer_manifest_path.unlink()

            resolver = TrustedVersionResolver(
                repository,
                manifest_store=store,
            )
            report = resolver.evaluate_candidates(
                "TEST-MISSING-MANIFEST-RECOVERY"
            )
            selected = resolver.find_trusted_version(
                "TEST-MISSING-MANIFEST-RECOVERY"
            )

            assert report["decision"] == "TRUSTED_RECOVERY_POINT"
            assert report["selected_version"] == older.version
            assert selected is not None
            assert selected.version == older.version

            candidates = {
                item["version"]: item
                for item in report["candidates"]
            }
            assert (
                candidates[newer.version]["checks"]["integrity_manifest"]
                is False
            )
            assert (
                candidates[newer.version]["status"]
                == "REJECTED_CANDIDATE"
            )
    finally:
        engine.dispose()

