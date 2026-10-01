from datetime import datetime, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from core.memory.database import Base
from core.graph.dependency.repository import DependencyRepository
from core.graph.dependency.engine import DependencyGraph


def test_temporal_dependency_graph():

    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False}
    )

    Base.metadata.create_all(engine)

    Session = sessionmaker(bind=engine)
    session = Session()

    repository = DependencyRepository(session)

    january = datetime(
        2026,
        1,
        1,
        tzinfo=timezone.utc
    )

    june = datetime(
        2026,
        6,
        1,
        tzinfo=timezone.utc
    )

    august = datetime(
        2026,
        8,
        1,
        tzinfo=timezone.utc
    )

    repository.add_dependency(
        source_memory_id="M001",
        target_memory_id="M002",
        dependency_type="semantic",
        strength=0.95,
        valid_from=january,
        valid_until=june
    )

    repository.add_dependency(
        source_memory_id="M001",
        target_memory_id="M003",
        dependency_type="derived",
        strength=0.90,
        valid_from=june
    )

    graph = DependencyGraph(repository)

    january_affected = graph.temporal_descendants(
        "M001",
        datetime(
            2026,
            3,
            1,
            tzinfo=timezone.utc
        )
    )

    assert january_affected == {"M002"}

    august_affected = graph.temporal_descendants(
        "M001",
        august
    )

    assert august_affected == {"M003"}