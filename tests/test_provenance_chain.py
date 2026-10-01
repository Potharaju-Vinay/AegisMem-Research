
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from core.memory.database import Base
from core.memory.repository import MemoryRepository
from core.provenance.manager import ProvenanceManager
from core.integrity.verifier import IntegrityVerifier


def test_provenance_hash_chain():

    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False}
    )

    Base.metadata.create_all(engine)

    Session = sessionmaker(bind=engine)
    session = Session()

    repository = MemoryRepository(session)
    provenance = ProvenanceManager(session)
    verifier = IntegrityVerifier()

    memory = repository.create(
        memory_id="POLICY-CHAIN-001",
        content="Refunds are available within 30 days.",
        source="refund_policy",
        source_type="enterprise_policy"
    )

    event1 = provenance.record(
        memory_record_id=memory.id,
        memory_id=memory.memory_id,
        version=1,
        actor="policy-admin",
        operation="CREATE",
        source=memory.source,
        source_type=memory.source_type
    )

    event2 = provenance.record(
        memory_record_id=memory.id,
        memory_id=memory.memory_id,
        version=2,
        actor="policy-admin",
        operation="UPDATE",
        source=memory.source,
        source_type=memory.source_type
    )

    assert event1.previous_event_hash is None

    assert event2.previous_event_hash == event1.event_hash

    events = provenance.get_events(
        memory.memory_id
    )

    assert verifier.verify_provenance_chain(events)

    event2.event_metadata = '{"tampered":true}'

    session.commit()

    events = provenance.get_events(
        memory.memory_id
    )

    assert not verifier.verify_provenance_chain(events)
