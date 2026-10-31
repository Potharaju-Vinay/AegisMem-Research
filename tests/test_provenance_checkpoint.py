import json

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from core.integrity.hash import calculate_version_hash
from core.provenance.checkpoint import ProvenanceCheckpointStore


class FakeEvent:
    def __init__(
        self,
        version,
        previous_event_hash,
        actor="owner",
        metadata=None,
    ):
        self.memory_record_id = version
        self.memory_id = "TEST-MEMORY"
        self.version = version
        self.actor = actor
        self.operation = "UPDATE"
        self.source = "test"
        self.source_type = "test"
        self.previous_event_hash = previous_event_hash
        self.event_metadata = json.dumps(metadata or {}, sort_keys=True)

        payload = {
            "memory_record_id": self.memory_record_id,
            "memory_id": self.memory_id,
            "version": self.version,
            "actor": self.actor,
            "operation": self.operation,
            "source": self.source,
            "source_type": self.source_type,
            "previous_event_hash": self.previous_event_hash,
            "metadata": json.loads(self.event_metadata),
        }
        self.event_hash = calculate_version_hash(
            json.dumps(payload, sort_keys=True), None
        )


@pytest.fixture
def checkpoint_setup(tmp_path):
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

    store = ProvenanceCheckpointStore(
        checkpoint_dir=tmp_path / "checkpoints",
        private_key_path=private_path,
        public_key_path=public_path,
    )

    first = FakeEvent(1, None)
    second = FakeEvent(2, first.event_hash)
    return store, [first, second]


def test_create_and_verify_checkpoint(checkpoint_setup):
    store, events = checkpoint_setup

    checkpoint = store.create_checkpoint(events)

    assert checkpoint["version"] == 2
    assert checkpoint["event_count"] == 2
    assert store.verify_checkpoint(events) == "VALID"


def test_missing_checkpoint(checkpoint_setup):
    store, events = checkpoint_setup

    assert store.verify_checkpoint(events) == "CHECKPOINT_MISSING"


def test_tampered_event_is_detected(checkpoint_setup):
    store, events = checkpoint_setup
    store.create_checkpoint(events)

    events[1].actor = "attacker"

    assert store.verify_checkpoint(events) == "CHAIN_TAMPERED"


def test_invalid_signature_is_detected(checkpoint_setup):
    store, events = checkpoint_setup
    store.create_checkpoint(events)

    path = store._path(events[0].memory_id, events[-1].version)
    checkpoint = json.loads(path.read_text(encoding="utf-8"))
    checkpoint["signature"] = "invalid-signature"
    path.write_text(json.dumps(checkpoint), encoding="utf-8")

    assert store.verify_checkpoint(events) == "CHECKPOINT_INVALID"


def test_invalid_chain_cannot_be_checkpointed(checkpoint_setup):
    store, events = checkpoint_setup
    events[1].actor = "attacker"

    with pytest.raises(ValueError, match="invalid provenance chain"):
        store.create_checkpoint(events)
