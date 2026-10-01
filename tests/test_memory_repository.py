from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from core.memory.database import Base
from core.memory.repository import MemoryRepository


def test_memory_version_chain():

    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False}
    )

    Base.metadata.create_all(engine)

    Session = sessionmaker(bind=engine)

    session = Session()

    repository = MemoryRepository(session)

    first = repository.create(
        memory_id="POLICY-001",
        content="Refunds are available within 30 days.",
        source="refund_policy_v1",
        source_type="enterprise_policy"
    )

    second = repository.create(
        memory_id="POLICY-001",
        content="Refunds are available within 45 days.",
        source="refund_policy_v2",
        source_type="enterprise_policy"
    )

    assert first.version == 1
    assert second.version == 2

    assert second.previous_hash == first.content_hash

    history = repository.get_history("POLICY-001")

    assert len(history) == 2