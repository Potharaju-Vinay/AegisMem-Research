
from datetime import datetime, timezone

from core.memory.repository import MemoryRepository
from core.detection.detector import MemoryCompromiseDetector
from core.recovery.orchestrator import AegisMemRecoveryOrchestrator
from core.graph.dependency.engine import DependencyGraph
from core.graph.dependency.repository import DependencyRepository
from core.integrity.manifest_store import IntegrityManifestStore
from core.provenance.manager import ProvenanceManager
from core.provenance.checkpoint import ProvenanceCheckpointStore
from core.provenance.trusted_head import TrustedCheckpointHeadStore
from attack_lab.impact import AttackImpactAnalyzer


class AegisMemSecurityMonitor:
    def __init__(
        self,
        session,
        manifest_store=None,
        provenance_manager=None,
        checkpoint_store=None,
        trusted_head_store=None,
    ):
        self.session = session

        self.manifest_store = (
            manifest_store
            if manifest_store is not None
            else IntegrityManifestStore()
        )

        self.repository = MemoryRepository(session)

        self.provenance_manager = (
            provenance_manager
            if provenance_manager is not None
            else ProvenanceManager(session)
        )

        self.checkpoint_store = checkpoint_store
        self.trusted_head_store = trusted_head_store

    def build_graph(self):
        dependency_repo = DependencyRepository(self.session)
        existing = dependency_repo.get_dependencies("POLICY-001")

        if not existing:
            dependency_repo.add_dependency(
                source_memory_id="POLICY-001",
                target_memory_id="POLICY-002",
                dependency_type="derived_from",
                strength=0.9,
            )
            dependency_repo.add_dependency(
                source_memory_id="POLICY-002",
                target_memory_id="SOP-003",
                dependency_type="derived_from",
                strength=0.8,
            )

        graph = DependencyGraph(dependency_repo)
        graph.load()
        return graph

    def process(self, memory_id: str):
        graph = self.build_graph()

        detector = MemoryCompromiseDetector(
            repository=self.repository,
            dependency_graph=graph,
            manifest_store=self.manifest_store,
        )

        detection = detector.detect(memory_id)

        if not detection.compromised:
            return {
                "detected": False,
                "recovered": False,
                "message": "No compromise detected.",
            }

        impact_analyzer = AttackImpactAnalyzer(graph)

        orchestrator = AegisMemRecoveryOrchestrator(
            repository=self.repository,
            impact_analyzer=impact_analyzer,
            manifest_store=self.manifest_store,
            provenance_manager=self.provenance_manager,
            checkpoint_store=self.checkpoint_store,
            trusted_head_store=self.trusted_head_store,
        )

        recovery = orchestrator.recover_from_attack(
            compromised_memory_id=memory_id,
            attack_time=datetime.now(timezone.utc),
        )

        current = self.repository.get_latest(memory_id)

        recovery_results = recovery.get("results", [])
        content_recovered = any(
            result.get("action") == "ROLLBACK"
            and result.get("content_recovered", False)
            and result.get("recovery_provenance_verified", False)
            for result in recovery_results
        )

        return {
            "detected": True,
            "recovered": content_recovered,
            "recovery_workflow_success": recovery.get("success", False),
            "detection": {
                "compromised": detection.compromised,
                "suspicion_score": detection.suspicion_score,
                "reason": detection.reason,
                "attribution": detection.attribution,
                "attribution_evidence": detection.attribution_evidence,
                "integrity_anchor_status": (
                    detection.evidence.integrity_anchor_status
                ),
            },
            "recovery": recovery,
            "current_version": current.version if current else None,
            "current_content": current.content if current else None,
            "current_status": current.status if current else None,
            "current_trust_score": (
                current.trust_score if current else None
            ),
        }
