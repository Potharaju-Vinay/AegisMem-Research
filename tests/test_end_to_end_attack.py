from datetime import datetime, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from core.memory.database import Base
from core.memory.repository import MemoryRepository
from core.graph.dependency.repository import DependencyRepository
from core.graph.dependency.engine import DependencyGraph
from attack_lab.corruption import MemoryCorruptionAttack
from attack_lab.impact import AttackImpactAnalyzer


def test_end_to_end_memory_corruption_impact():

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
        memory_id="POLICY-REFUND-001",
        content="Customer refunds are permitted within 30 days.",
        source="refund_policy",
        source_type="enterprise_policy"
    )

    memory_repository.create(
        memory_id="POLICY-ACCESS-002",
        content="Privileged access requires MFA.",
        source="access_policy",
        source_type="enterprise_policy"
    )

    memory_repository.create(
        memory_id="SOP-SUPPORT-003",
        content="Security incidents must be escalated.",
        source="support_sop",
        source_type="enterprise_sop"
    )

    dependency_repository.add_dependency(
        source_memory_id="POLICY-REFUND-001",
        target_memory_id="POLICY-ACCESS-002",
        dependency_type="semantic",
        strength=0.9,
        valid_from=datetime(
            2026,
            1,
            1,
            tzinfo=timezone.utc
        )
    )

    dependency_repository.add_dependency(
        source_memory_id="POLICY-ACCESS-002",
        target_memory_id="SOP-SUPPORT-003",
        dependency_type="derived",
        strength=0.8,
        valid_from=datetime(
            2026,
            1,
            1,
            tzinfo=timezone.utc
        )
    )

    attack = MemoryCorruptionAttack(session)

    event = attack.corrupt(
        memory_id="POLICY-REFUND-001",
        modified_content="Customer refunds are permitted within 180 days."
    )

    assert event.status == "CORRUPTED"
    assert event.integrity_compromised

    graph = DependencyGraph(dependency_repository)

    analyzer = AttackImpactAnalyzer(
        graph,
        decay=1.0
    )

    result = analyzer.analyze(
        compromised_memory_id="POLICY-REFUND-001",
        timestamp=datetime(
            2026,
            3,
            1,
            tzinfo=timezone.utc
        )
    )

    assert "POLICY-REFUND-001" in result
    assert "POLICY-ACCESS-002" in result
    assert "SOP-SUPPORT-003" in result

    assert result["POLICY-ACCESS-002"].trust == 0.9
    assert result["SOP-SUPPORT-003"].trust == 0.72

    assert result["POLICY-ACCESS-002"].impact_score == 0.1
    assert result["SOP-SUPPORT-003"].impact_score == 0.28
