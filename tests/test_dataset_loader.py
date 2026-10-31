from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from core.memory.database import Base
from core.memory.repository import MemoryRepository
from datasets.loader import EnterpriseDatasetLoader
from pathlib import Path


def test_enterprise_dataset_loader():

    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False}
    )

    Base.metadata.create_all(engine)

    Session = sessionmaker(bind=engine)
    session = Session()

    repository = MemoryRepository(session)
    loader = EnterpriseDatasetLoader(repository)

    dataset_path = (
    Path(__file__).resolve().parent.parent
    / "datasets"
    / "enterprise"
    / "enterprise_memories.json"
)

    memories = loader.load(dataset_path)

    assert len(memories) == 5
    assert memories[0].memory_id == "POLICY-001"
    assert memories[0].version == 1
    assert memories[0].status == "active"
