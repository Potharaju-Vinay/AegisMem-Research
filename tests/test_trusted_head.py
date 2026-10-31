
import json

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from core.integrity.hash import calculate_version_hash
from core.provenance.checkpoint import ProvenanceCheckpointStore
from core.provenance.trusted_head import TrustedCheckpointHeadStore


def make_valid_events(memory_id, count):
    events = []
    previous_hash = None

    for version in range(1, count + 1):
        metadata = {}
        payload = {
            "memory_record_id": version,
            "memory_id": memory_id,
            "version": version,
            "actor": "owner",
            "operation": "UPDATE",
            "source": "test",
            "source_type": "test",
            "previous_event_hash": previous_hash,
            "metadata": metadata,
        }

        event_hash = calculate_version_hash(
            json.dumps(payload, sort_keys=True), None
        )

        events.append(type("TestEvent", (), {
            "memory_record_id": version,
            "memory_id": memory_id,
            "version": version,
            "actor": "owner",
            "operation": "UPDATE",
            "source": "test",
            "source_type": "test",
            "previous_event_hash": previous_hash,
            "event_hash": event_hash,
            "event_metadata": json.dumps(metadata, sort_keys=True),
        })())

        previous_hash = event_hash

    return events


@pytest.fixture
def head_store(tmp_path):
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

    store = TrustedCheckpointHeadStore(
        head_dir=tmp_path / "trusted-heads",
        private_key_path=private_path,
        public_key_path=public_path,
        checkpoint_store=checkpoint_store,
    )

    return store, checkpoint_store


def prepare_events(setup, count):
    store, checkpoint_store = setup
    events = make_valid_events("MEM-1", count)
    checkpoint_store.create_checkpoint(events)
    return store, events


def test_trusted_head_accepts_initial_checkpoint(head_store):
    store, events = prepare_events(head_store, 2)

    head = store.advance(events)

    assert head["version"] == 2
    assert head["event_hash"] == events[-1].event_hash
    assert head["event_count"] == 2


def test_trusted_head_rejects_rollback(head_store):
    store, events = prepare_events(head_store, 3)
    store.advance(events)

    with pytest.raises(ValueError, match="roll back"):
        store.advance(events[:2])


def test_trusted_head_rejects_conflicting_same_version(head_store):
    store, events = prepare_events(head_store, 2)
    store.advance(events)

    changed_events = make_valid_events("MEM-1", 2)
    changed_events[-1].actor = "attacker"

    with pytest.raises(ValueError):
        store.advance(changed_events)


def test_trusted_head_rejects_invalid_signature(head_store):
    store, events = prepare_events(head_store, 1)
    store.advance(events)

    path = store._path("MEM-1")
    path.write_text(
        '{"memory_id":"MEM-1","version":1}',
        encoding="utf-8",
    )

    newer_events = make_valid_events("MEM-1", 2)
    store.checkpoint_store.create_checkpoint(newer_events)

    with pytest.raises(ValueError, match="Existing trusted head is invalid"):
        store.advance(newer_events)


def test_older_history_is_detected_as_rollback(head_store):
    store, events = prepare_events(head_store, 3)
    store.advance(events)

    assert store.verify_events(events[:2]) == "ROLLBACK_DETECTED"


def test_matching_trusted_head_is_valid(head_store):
    store, events = prepare_events(head_store, 2)
    store.advance(events)

    assert store.verify_events(events) == "VALID"


def test_newer_history_reports_trusted_head_behind(head_store):
    store, events = prepare_events(head_store, 2)

    first_event = events[:1]
    store.checkpoint_store.create_checkpoint(first_event)
    store.advance(first_event)

    assert store.verify_events(events) == "TRUSTED_HEAD_BEHIND"


def test_trusted_head_rejects_initialization_without_checkpoint(head_store):
    store, checkpoint_store = head_store
    events = make_valid_events("MEM-NO-CHECKPOINT", 2)

    with pytest.raises(ValueError, match="valid checkpoint"):
        store.advance(events)

    assert not store._path("MEM-NO-CHECKPOINT").exists()
