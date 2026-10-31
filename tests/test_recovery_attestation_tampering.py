
import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from core.recovery.attestation import RecoveryAttestationStore


def test_tampered_recovery_attestation_is_rejected(tmp_path):
    private_key = Ed25519PrivateKey.generate()
    private_path = tmp_path / "recovery_private.pem"
    public_path = tmp_path / "recovery_public.pem"

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

    store = RecoveryAttestationStore(
        attestation_dir=tmp_path / "attestations",
        private_key_path=private_path,
        public_key_path=public_path,
    )

    class Record:
        memory_id = "TEST-TAMPER"
        version = 2
        revision_id = "revision-2"
        content_hash = "original-hash"

    record = Record()
    path = store._path(record.memory_id, record.version)
    path.parent.mkdir(parents=True, exist_ok=True)

    attestation = {
        "protocol": "aegismem-recovery-attestation-v1",
        "operation": "memory.recovery",
        "memory_id": record.memory_id,
        "source_revision_id": "revision-1",
        "source_version": 1,
        "source_content_hash": "source-hash",
        "compromised_revision_id": "compromised-revision",
        "compromised_version": 2,
        "compromised_content_hash": "compromised-hash",
        "recovered_revision_id": record.revision_id,
        "recovered_version": record.version,
        "recovered_content_hash": record.content_hash,
        "created_at": "2026-10-25T00:00:00+00:00",
    }

    from core.recovery.attestation import canonical_payload
    attestation["signature"] = __import__("base64").b64encode(
        private_key.sign(canonical_payload(attestation))
    ).decode("ascii")

    path.write_text(json.dumps(attestation), encoding="utf-8")

    assert store.load_verified_attestation(record) is not None

    attestation["recovered_content_hash"] = "tampered-hash"
    path.write_text(json.dumps(attestation), encoding="utf-8")

    assert store.load_verified_attestation(record) is None
    assert store.verify_record(record) is False
