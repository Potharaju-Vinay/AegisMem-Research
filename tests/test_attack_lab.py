
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
