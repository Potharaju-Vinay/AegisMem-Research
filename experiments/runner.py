from datetime import datetime, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from core.memory.database import Base
from core.memory.repository import MemoryRepository
from core.graph.dependency.repository import DependencyRepository
from core.graph.dependency.engine import DependencyGraph

from attack_lab.corruption import MemoryCorruptionAttack
from attack_lab.impact import AttackImpactAnalyzer
from attack_lab.baseline import PropagationBaseline
from attack_lab.metrics import ImpactMetricCalculator


def run_experiment():

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
        content="Customer refunds are permitted within 30 days.",
        source="refund_policy",
        source_type="enterprise_policy"
    )

    memory_repository.create(
        memory_id="M002",
        content="Privileged access requires MFA.",
        source="access_policy",
        source_type="enterprise_policy"
    )

    memory_repository.create(
        memory_id="M003",
        content="Security incidents must be escalated.",
        source="support_sop",
        source_type="enterprise_sop"
    )

    dependency_repository.add_dependency(
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

    dependency_repository.add_dependency(
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

    attack = MemoryCorruptionAttack(session)

    event = attack.corrupt(
        memory_id="M001",
        modified_content="Customer refunds are permitted within 180 days."
    )

    graph = DependencyGraph(dependency_repository)

    analyzer = AttackImpactAnalyzer(
        graph,
        decay=1.0
    )

    aegismem_result = analyzer.analyze(
        compromised_memory_id="M001",
        timestamp=datetime(
            2026,
            3,
            1,
            tzinfo=timezone.utc
        )
    )

    metrics = ImpactMetricCalculator().calculate(
        aegismem_result
    )

    baseline_result = {
        "M001": aegismem_result["M001"],
        "M002": type(aegismem_result["M002"])(
            memory_id="M002",
            trust=0.8,
            distance=1,
            parent_memory_id="M001",
            impact_score=0.2
        ),
        "M003": type(aegismem_result["M003"])(
            memory_id="M003",
            trust=0.6,
            distance=2,
            parent_memory_id="M002",
            impact_score=0.4
        )
    }

    comparison = PropagationBaseline().compare(
        baseline_result,
        aegismem_result
    )

    print()
    print("AegisMem Research Experiment")
    print("============================")
    print()
    print("Attack Scenario")
    print("----------------")
    print("Scenario: Memory Corruption")
    print("Compromised Memory: M001")
    print(f"Integrity Compromised: {event.integrity_compromised}")
    print()
    print("AegisMem Metrics")
    print("-----------------")
    print(f"Total Memories: {metrics.total_memories}")
    print(f"Affected Memories: {metrics.affected_memories}")
    print(f"Maximum Distance: {metrics.maximum_distance}")
    print(f"Average Impact: {metrics.average_impact}")
    print(f"Cumulative Impact: {metrics.cumulative_impact}")
    print()
    print("Baseline vs AegisMem")
    print("--------------------")
    print(f"Baseline Impact: {comparison.baseline_impact}")
    print(f"AegisMem Impact: {comparison.aegismem_impact}")
    print(f"Improvement: {comparison.improvement}")
    print()


if __name__ == "__main__":
    run_experiment()
