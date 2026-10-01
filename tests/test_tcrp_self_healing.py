from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from core.graph.dependency.engine import DependencyGraph
from core.graph.dependency.repository import DependencyRepository
from core.memory.database import Base
from core.memory.repository import MemoryRepository
from core.recovery.orchestrator import (
    AegisMemRecoveryOrchestrator
)
from core.trust.propagation import TemporalTrustPropagator


def test_tcrp_automatic_self_healing():

    engine = create_engine(
        "sqlite:///:memory:"
    )

    Base.metadata.create_all(engine)

    session = Session(engine)

    memory_repo = MemoryRepository(session)

    # ---------------------------------------------
    # Trusted memory
    # ---------------------------------------------

    memory = memory_repo.create(
        memory_id="M001",
        content=(
            "Refunds are allowed within 30 days."
        ),
        source="policy",
        source_type="enterprise_policy"
    )

    # ---------------------------------------------
    # Poisoned version
    # ---------------------------------------------

    poisoned = memory_repo.create(
        memory_id="M001",
        content=(
            "Refunds are allowed within 180 days."
        ),
        source="attacker",
        source_type="memory_poisoning"
    )

    poisoned.trust_score = 0.0
    poisoned.suspicion_score = 1.0
    poisoned.status = "CORRUPTED"

    session.commit()

    # ---------------------------------------------
    # Build graph
    # ---------------------------------------------

    dependency_repo = DependencyRepository(
        session
    )

    dependency_repo.add_dependency(
        source_memory_id="M001",
        target_memory_id="M002",
        dependency_type="derived_from",
        strength=0.9
    )

    dependency_repo.add_dependency(
        source_memory_id="M002",
        target_memory_id="M003",
        dependency_type="derived_from",
        strength=0.8
    )

    graph = DependencyGraph(
        dependency_repo
    )

    impact_analyzer = __import__(
        "attack_lab.impact",
        fromlist=["AttackImpactAnalyzer"]
    ).AttackImpactAnalyzer(
        graph
    )

    # ---------------------------------------------
    # AegisMem orchestrator
    # ---------------------------------------------

    orchestrator = AegisMemRecoveryOrchestrator(
        repository=memory_repo,
        impact_analyzer=impact_analyzer
    )

    result = orchestrator.recover_from_attack(
        compromised_memory_id="M001"
    )

    assert result["success"] is True

    recovered = memory_repo.get_latest(
        "M001"
    )

    assert recovered.content == (
        "Refunds are allowed within 30 days."
    )

    assert recovered.trust_score == 1.0

    assert recovered.suspicion_score == 0.0

    assert recovered.status == "active"

    session.close()