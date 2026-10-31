from attack_lab.external_attack import ExternalMemoryAttacker
from core.soc.models import SOCAlert
from attack_lab.models import AttackEvent
from core.provenance.models import ProvenanceEvent
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from core.memory.database import Base
from core.memory.repository import MemoryRepository
from attack_lab.corruption import MemoryCorruptionAttack


def test_memory_corruption_attack():

    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False}
    )

    Base.metadata.create_all(engine)

    Session = sessionmaker(bind=engine)
    session = Session()

    repository = MemoryRepository(session)

    memory = repository.create(
        memory_id="POLICY-001",
        content="Refunds are available within 30 days.",
        source="refund_policy",
        source_type="enterprise_policy"
    )

    attack = MemoryCorruptionAttack(session)

    event = attack.corrupt(
        memory_id="POLICY-001",
        modified_content="Refunds are available within 90 days."
    )

    assert event.memory_id == "POLICY-001"
    assert event.attack_type == "content_tampering"
    assert event.status == "CORRUPTED"

    assert event.original_content == (
        "Refunds are available within 30 days."
    )

    assert event.modified_content == (
        "Refunds are available within 90 days."
    )

    assert event.integrity_compromised

    assert event.original_content_hash != (
        event.observed_content_hash
    )
def test_external_attack_marks_new_revision_as_compromised():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False}
    )

    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()

    repository = MemoryRepository(session)

    repository.create(
        memory_id="POLICY-EXT-001",
        content="Refunds are available within 30 days.",
        source="refund_policy",
        source_type="enterprise_policy"
    )

    attacker = ExternalMemoryAttacker(session)

    result = attacker.modify_memory(
        memory_id="POLICY-EXT-001",
        modified_content="Refunds are available within 180 days.",
        attacker="test-attacker"
    )

    compromised = repository.get_latest("POLICY-EXT-001")
    
    events = session.query(ProvenanceEvent).filter_by(
        memory_id="POLICY-EXT-001",
        version=compromised.version
        ).all()

    assert len(events) == 1
    assert events[0].memory_record_id == compromised.id
    assert events[0].actor == "test-attacker"
    assert events[0].operation == "MEMORY_WRITE"

    assert result["status"] == "CORRUPTED"
    assert compromised.trust_score == 0.0
    assert compromised.suspicion_score == 1.0
    assert compromised.status == "CORRUPTED"

    session.close()
    engine.dispose()
