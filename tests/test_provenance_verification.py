import json

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from core.memory.database import Base
from core.memory.repository import MemoryRepository
from core.provenance.manager import ProvenanceManager
from core.integrity.verifier import IntegrityVerifier


def create_test_events():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()

    repository = MemoryRepository(session)
    memory = repository.create(
        memory_id="PROVENANCE-VERIFY-001",
        content="Trusted policy",
        source="test",
        source_type="test",
    )

    manager = ProvenanceManager(session)
    manager.record(
        memory_record_id=memory.id,
        memory_id=memory.memory_id,
        version=1,
        actor="owner",
        operation="CREATE",
        source="test",
        source_type="test",
        metadata={"case": "first"},
    )
    manager.record(
        memory_record_id=memory.id,
        memory_id=memory.memory_id,
        version=2,
        actor="owner",
        operation="UPDATE",
        source="test",
        source_type="test",
        metadata={"case": "second"},
    )

    events = manager.get_events(memory.memory_id)
    return engine, session, events


def test_valid_provenance_chain_passes():
    engine, session, events = create_test_events()
    try:
        assert IntegrityVerifier().verify_provenance_chain(events)
    finally:
        session.close()
        engine.dispose()


def test_modified_actor_fails_verification():
    engine, session, events = create_test_events()
    try:
        events[1].actor = "attacker"
        assert not IntegrityVerifier().verify_provenance_chain(events)
    finally:
        session.close()
        engine.dispose()


def test_broken_predecessor_link_fails_verification():
    engine, session, events = create_test_events()
    try:
        events[1].previous_event_hash = "broken-link"
        assert not IntegrityVerifier().verify_provenance_chain(events)
    finally:
        session.close()
        engine.dispose()


def test_malformed_metadata_fails_closed():
    engine, session, events = create_test_events()
    try:
        events[1].event_metadata = "{invalid-json"
        assert not IntegrityVerifier().verify_provenance_chain(events)
    finally:
        session.close()
        engine.dispose()


def test_reordered_events_fail_verification():
    engine, session, events = create_test_events()
    try:
        assert not IntegrityVerifier().verify_provenance_chain(
            list(reversed(events))
        )
    finally:
        session.close()
        engine.dispose()
