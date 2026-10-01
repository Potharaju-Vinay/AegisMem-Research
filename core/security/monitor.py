from datetime import datetime, timezone

from core.memory.repository import MemoryRepository
from core.detection.detector import MemoryCompromiseDetector
from core.recovery.orchestrator import AegisMemRecoveryOrchestrator
from core.graph.dependency.engine import DependencyGraph
from core.graph.dependency.repository import DependencyRepository
from core.recovery.audit import RecoveryEvent
from attack_lab.impact import AttackImpactAnalyzer


class AegisMemSecurityMonitor:

    def __init__(self, session):
        self.session = session
        self.repository = MemoryRepository(session)

    def build_graph(self):
        dependency_repo = DependencyRepository(self.session)

        existing = dependency_repo.get_dependencies("POLICY-001")

        if not existing:
            dependency_repo.add_dependency(
                source_memory_id="POLICY-001",
                target_memory_id="POLICY-002",
                dependency_type="derived_from",
                strength=0.9
            )

            dependency_repo.add_dependency(
                source_memory_id="POLICY-002",
                target_memory_id="SOP-003",
                dependency_type="derived_from",
                strength=0.8
            )

        graph = DependencyGraph(dependency_repo)
        graph.load()

        return graph

    def process(self, memory_id: str):
        graph = self.build_graph()

        detector = MemoryCompromiseDetector(
            repository=self.repository,
            dependency_graph=graph
        )

        detection = detector.detect(memory_id)

        if not detection.compromised:
            return {
                "detected": False,
                "recovered": False,
                "message": "No compromise detected."
            }

        impact_analyzer = AttackImpactAnalyzer(graph)

        orchestrator = AegisMemRecoveryOrchestrator(
            repository=self.repository,
            impact_analyzer=impact_analyzer
        )

        recovery = orchestrator.recover_from_attack(
            compromised_memory_id=memory_id,
            attack_time=datetime.now(timezone.utc)
        )

        current = self.repository.get_latest(memory_id)

        return {
            "detected": True,
            "recovered": recovery.get("success", False),
            "detection": {
                "compromised": detection.compromised,
                "suspicion_score": detection.suspicion_score,
                "reason": detection.reason
            },
            "recovery": recovery,
            "current_version": current.version if current else None,
            "current_content": current.content if current else None,
            "current_status": current.status if current else None,
            "current_trust_score": (
                current.trust_score if current else None
            )
        }