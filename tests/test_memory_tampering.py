
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from core.integrity.verifier import IntegrityVerifier
from core.memory.database import Base
from core.memory.repository import MemoryRepository


def test_memory_tampering_is_detected():

    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False}
    )

    Base.metadata.create_all(engine)

    Session = sessionmaker(bind=engine)
    session = Session()

    repository = MemoryRepository(session)
    verifier = IntegrityVerifier()

    memory = repository.create(
        memory_id="POLICY-ATTACK-001",
        content="Refunds are available within 30 days.",
        source="refund_policy",
        source_type="enterprise_policy"
    )

    assert verifier.verify_memory(memory)

    memory.content = "Refunds are available within 365 days."

    session.commit()

    session.refresh(memory)

    assert not verifier.verify_memory(memory)
