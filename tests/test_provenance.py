from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from core.memory.database import Base
from core.memory.repository import MemoryRepository
from core.provenance.manager import ProvenanceManager
from core.integrity.verifier import IntegrityVerifier


def test_provenance_and_integrity():

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
        memory_id="POLICY-001",
        content="Refunds are available within 30 days.",
        source="refund_policy",
        source_type="enterprise_policy"
    )

    event = provenance.record(
        memory_record_id=memory.id,
        memory_id=memory.memory_id,
        version=memory.version,
        actor="policy-admin",
        operation="CREATE",
        source=memory.source,
        source_type=memory.source_type
    )

    assert event.memory_id == "POLICY-001"
    assert event.actor == "policy-admin"
    assert event.operation == "CREATE"

    assert verifier.verify_memory(memory)

    history = repository.get_history("POLICY-001")

    assert verifier.verify_chain(history)