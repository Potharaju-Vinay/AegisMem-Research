from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from core.memory.database import Base
from core.memory.repository import MemoryRepository
from core.graph.dependency.repository import DependencyRepository
from core.graph.dependency.engine import DependencyGraph


def test_dependency_graph():

    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False}
    )

    Base.metadata.create_all(engine)

    Session = sessionmaker(bind=engine)
    session = Session()

    memory_repository = MemoryRepository(session)

    dependency_repository = DependencyRepository(session)

    memory_repository.create(
        memory_id="M001",
        content="Company refund policy.",
        source="policy",
        source_type="enterprise_policy"
    )

    memory_repository.create(
        memory_id="M014",
        content="Customer refund procedure.",
        source="procedure",
        source_type="enterprise_procedure"
    )

    memory_repository.create(
        memory_id="M031",
        content="Support response rule.",
        source="support",
        source_type="enterprise_rule"
    )

    dependency_repository.add_dependency(
        source_memory_id="M001",
        target_memory_id="M014",
        dependency_type="semantic",
        strength=0.95
    )

    dependency_repository.add_dependency(
        source_memory_id="M014",
        target_memory_id="M031",
        dependency_type="derived",
        strength=0.90
    )

    graph = DependencyGraph(
        dependency_repository
    )

    graph.load()

    affected = graph.descendants("M001")

    assert affected == {"M014", "M031"}