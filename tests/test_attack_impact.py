from datetime import datetime, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from core.memory.database import Base
from core.graph.dependency.repository import DependencyRepository
from core.graph.dependency.engine import DependencyGraph
from attack_lab.impact import AttackImpactAnalyzer


def test_attack_impact_propagation():

    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False}
    )

    Base.metadata.create_all(engine)

    Session = sessionmaker(bind=engine)
    session = Session()

    repository = DependencyRepository(session)

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

    analyzer = AttackImpactAnalyzer(
        graph,
        decay=1.0
    )

    result = analyzer.analyze(
        compromised_memory_id="M001",
        timestamp=datetime(
            2026,
            3,
            1,
            tzinfo=timezone.utc
        )
    )

    assert "M001" in result
    assert "M002" in result
    assert "M003" in result

    assert result["M002"].trust == 0.9
    assert result["M003"].trust == 0.72

    assert result["M002"].distance == 1
    assert result["M003"].distance == 2

    assert result["M002"].parent_memory_id == "M001"
    assert result["M003"].parent_memory_id == "M002"

    assert result["M001"].impact_score == 1.0
    assert result["M002"].impact_score == 0.1
    assert result["M003"].impact_score == 0.28
