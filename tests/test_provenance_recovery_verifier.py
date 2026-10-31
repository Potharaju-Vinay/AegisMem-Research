
import json

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from core.integrity.hash import calculate_version_hash
from core.provenance.checkpoint import ProvenanceCheckpointStore
from core.provenance.recovery_verifier import ProvenanceRecoveryVerifier
from core.provenance.trusted_head import TrustedCheckpointHeadStore


class FakeEvent:
    def __init__(self, version, previous_event_hash):
        self.memory_record_id = version
        self.memory_id = "RECOVERY-TEST"
        self.version = version
        self.actor = "owner"
        self.operation = "UPDATE"
        self.source = "test"
        self.source_type = "test"
        self.previous_event_hash = previous_event_hash
        self.event_metadata = json.dumps({})

        payload = {
            "memory_record_id": self.memory_record_id,
            "memory_id": self.memory_id,
            "version": self.version,
            "actor": self.actor,
            "operation": self.operation,
            "source": self.source,
            "source_type": self.source_type,
            "previous_event_hash": self.previous_event_hash,
            "metadata": {},
        }

        self.event_hash = calculate_version_hash(
            json.dumps(payload, sort_keys=True), None
        )


@pytest.fixture
def verifier_setup(tmp_path):
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

    verifier = ProvenanceRecoveryVerifier(
        checkpoint_store=checkpoint_store,
        trusted_head_store=head_store,
    )

    first = FakeEvent(1, None)
    second = FakeEvent(2, first.event_hash)
    events = [first, second]

    return verifier, events


def test_missing_events_fail_closed(verifier_setup):
    verifier, _ = verifier_setup

    result = verifier.verify([])

    assert result["verified"] is False
    assert result["checkpoint_status"] == "CHECKPOINT_MISSING"


def test_missing_checkpoint_is_rejected(verifier_setup):
    verifier, events = verifier_setup

    result = verifier.verify(events)

    assert result["verified"] is False
    assert result["checkpoint_status"] == "CHECKPOINT_MISSING"


def test_valid_checkpoint_and_head_pass(verifier_setup):
    verifier, events = verifier_setup

    verifier.checkpoint_store.create_checkpoint(events)
    verifier.initialize_trusted_head(events)

    result = verifier.verify(events)

    assert result["verified"] is True
    assert result["checkpoint_status"] == "VALID"
    assert result["trusted_head_status"] == "VALID"


def test_tampered_event_is_rejected(verifier_setup):
    verifier, events = verifier_setup

    verifier.checkpoint_store.create_checkpoint(events)
    verifier.initialize_trusted_head(events)
    events[1].actor = "attacker"

    result = verifier.verify(events)

    assert result["verified"] is False
    assert result["checkpoint_status"] == "CHAIN_TAMPERED"


def test_head_initialization_requires_valid_checkpoint(verifier_setup):
    verifier, events = verifier_setup

    with pytest.raises(ValueError, match="Cannot initialize trusted head"):
        verifier.initialize_trusted_head(events)
