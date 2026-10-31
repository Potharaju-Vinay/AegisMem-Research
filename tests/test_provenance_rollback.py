import json

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from core.integrity.hash import calculate_version_hash
from core.provenance.checkpoint import ProvenanceCheckpointStore


class FakeEvent:
    def __init__(self, version, previous_event_hash):
        self.memory_record_id = version
        self.memory_id = "ROLLBACK-TEST"
        self.version = version
        self.actor = "owner"
        self.operation = "UPDATE"
        self.source = "test"
        self.source_type = "test"
        self.previous_event_hash = previous_event_hash
        self.event_metadata = "{}"

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
def rollback_setup(tmp_path):
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


def test_older_history_has_no_latest_checkpoint(rollback_setup):
    store, events = rollback_setup
    store.create_checkpoint(events)

    assert store.verify_checkpoint(events[:1]) == "CHECKPOINT_MISSING"


def test_deleted_latest_checkpoint_is_detected(rollback_setup):
    store, events = rollback_setup
    store.create_checkpoint(events)

    path = store._path(events[0].memory_id, events[-1].version)
    path.unlink()

    assert store.verify_checkpoint(events) == "CHECKPOINT_MISSING"


def test_modified_checkpoint_version_is_rejected(rollback_setup):
    store, events = rollback_setup
    store.create_checkpoint(events)

    path = store._path(events[0].memory_id, events[-1].version)
    checkpoint = json.loads(path.read_text(encoding="utf-8"))
    checkpoint["version"] -= 1
    path.write_text(json.dumps(checkpoint), encoding="utf-8")

    assert store.verify_checkpoint(events) == "CHECKPOINT_INVALID"
