from datetime import datetime, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from core.memory.database import Base
from core.memory.repository import MemoryRepository
from core.graph.dependency.repository import DependencyRepository
from core.graph.dependency.engine import DependencyGraph
from attack_lab.scenarios import EnterpriseAttackScenarios
from attack_lab.corruption import MemoryCorruptionAttack
from attack_lab.impact import AttackImpactAnalyzer


def test_enterprise_refund_policy_attack():

    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False}
    )

    Base.metadata.create_all(engine)

    Session = sessionmaker(bind=engine)
    session = Session()

    memory_repository = MemoryRepository(session)
    dependency_repository = DependencyRepository(session)

    scenario = EnterpriseAttackScenarios.REFUND_POLICY

    memory = memory_repository.create(
        memory_id=scenario["memory_id"],
        content=scenario["trusted_content"],
        source="enterprise_refund_policy",
        source_type="enterprise_policy"
    )

    dependency_repository.add_dependency(
        source_memory_id=scenario["memory_id"],
        target_memory_id="LOAN-DECISION-001",
        dependency_type="derived",
        strength=0.9,
        valid_from=datetime(
            2026,
            1,
            1,
            tzinfo=timezone.utc
        )
    )

    dependency_repository.add_dependency(
        source_memory_id="LOAN-DECISION-001",
        target_memory_id="CUSTOMER-ACTION-001",
        dependency_type="semantic",
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
        memory_id=scenario["memory_id"],
        modified_content=scenario["corrupted_content"]
    )

    assert event.memory_id == scenario["memory_id"]
    assert event.status == "CORRUPTED"
    assert event.integrity_compromised is True

    graph = DependencyGraph(dependency_repository)

    analyzer = AttackImpactAnalyzer(
        graph,
        decay=1.0
    )

    result = analyzer.analyze(
        compromised_memory_id=scenario["memory_id"],
        timestamp=datetime(
            2026,
            3,
            1,
            tzinfo=timezone.utc
        )
    )

    assert scenario["memory_id"] in result
    assert "LOAN-DECISION-001" in result
    assert "CUSTOMER-ACTION-001" in result

    assert result["LOAN-DECISION-001"].distance == 1
    assert result["CUSTOMER-ACTION-001"].distance == 2

    assert result["LOAN-DECISION-001"].trust == 0.9
    assert result["CUSTOMER-ACTION-001"].trust == 0.72

    assert result["LOAN-DECISION-001"].impact_score == 0.1
    assert result["CUSTOMER-ACTION-001"].impact_score == 0.28
