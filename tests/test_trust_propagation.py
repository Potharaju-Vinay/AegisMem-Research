
from datetime import datetime, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from core.memory.database import Base
from core.graph.dependency.repository import DependencyRepository
from core.graph.dependency.engine import DependencyGraph
from core.trust.propagation import TemporalTrustPropagator


def test_temporal_trust_propagation():

    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False}
    )

    Base.metadata.create_all(engine)

    Session = sessionmaker(bind=engine)
    session = Session()

    repository = DependencyRepository(session)

    timestamp = datetime(
        2026,
        3,
        1,
        tzinfo=timezone.utc
    )

    repository.add_dependency(
        source_memory_id="M001",
        target_memory_id="M002",
        dependency_type="semantic",
        strength=0.9,
        valid_from=datetime(
            2026,
            1,
            1,
            tzinfo=timezone.utc
        )
    )

    repository.add_dependency(
        source_memory_id="M002",
        target_memory_id="M003",
        dependency_type="derived",
        strength=0.8,
        valid_from=datetime(
            2026,
            1,
            1,
            tzinfo=timezone.utc
        )
    )

    graph = DependencyGraph(repository)

    propagator = TemporalTrustPropagator(
        graph,
        decay=1.0
    )

    result = propagator.propagate(
        compromised_memory_id="M001",
        timestamp=timestamp
    )

    assert "M001" in result
    assert "M002" in result
    assert "M003" in result

    assert result["M002"].trust == 0.9
    assert result["M003"].trust == 0.72

    assert result["M002"].distance == 1
    assert result["M003"].distance == 2
