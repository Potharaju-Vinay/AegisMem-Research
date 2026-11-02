
import os
import time
from datetime import datetime, timezone

from core.memory.repository import MemoryRepository
from core.detection.detector import MemoryCompromiseDetector
from core.recovery.orchestrator import AegisMemRecoveryOrchestrator
from core.graph.dependency.engine import DependencyGraph
from core.graph.dependency.repository import DependencyRepository
from core.integrity.manifest_store import IntegrityManifestStore
from core.recovery.vault import ReplicatedTrustVault
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
        vault_store=None,
    ):
        self.session = session

        self.manifest_store = (
            manifest_store
            if manifest_store is not None
            else IntegrityManifestStore()
        )

        self.vault_store = (
            vault_store
            if vault_store is not None
            else ReplicatedTrustVault()
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

    def process(self, memory_id: str, t_write: float | None = None):
        import time
        from core.detection.telemetry import get_detection_telemetry

        t0_write = t_write if t_write is not None else time.perf_counter()
        graph = self.build_graph()

        detector = MemoryCompromiseDetector(
            repository=self.repository,
            dependency_graph=graph,
            manifest_store=self.manifest_store,
        )

        detection = detector.detect(memory_id)
        t_detect = time.perf_counter()

        if not detection.compromised:
            t_finish = time.perf_counter()
            telemetry_rec = get_detection_telemetry().record_incident(
                memory_id=memory_id,
                version=self.repository.get_latest(memory_id).version if self.repository.get_latest(memory_id) else 1,
                t_write=t0_write,
                t_detect=t_detect,
                t_decide=t_detect,
                t_recover=t_finish,
                t_validate=t_finish,
                detected=False,
                recovered=False,
                action_taken="NO_OP",
            )
            return {
                "detected": False,
                "recovered": False,
                "message": "No compromise detected.",
                "telemetry": telemetry_rec,
            }

        # Record detection alert in SOC database if compromise is detected
        try:
            from core.soc.engine import create_soc_alert
            from attack_lab.models import AttackEvent

            latest_attack = (
                self.session.query(AttackEvent)
                .filter(AttackEvent.memory_id == memory_id)
                .order_by(AttackEvent.attack_time.desc())
                .first()
            )
            latest_mem = self.repository.get_latest(memory_id)
            curr_v = latest_mem.version if latest_mem else 1
            attack_id = latest_attack.attack_id if latest_attack else f"DETECTION-{memory_id}-V{curr_v}"
            attack_type = latest_attack.attack_type if latest_attack else "memory_compromise_detection"
            evidence_dict = {
                "integrity_compromised": detection.evidence.integrity_compromised,
                "provenance_suspicious": detection.evidence.provenance_suspicious,
                "attack_detected": detection.evidence.attack_detected,
                "unauthorized_access": not detection.evidence.authorization_valid,
                "content_changed": detection.evidence.content_changed,
                "dependency_contamination": detection.evidence.dependency_exposure,
            }
            create_soc_alert(
                session=self.session,
                memory_id=memory_id,
                attack_id=attack_id,
                attack_type=attack_type,
                evidence=evidence_dict,
            )
        except Exception as alert_err:
            print(f"[AegisMem Monitor] Notice: Failed to log soc_alert: {alert_err}")

        t_decide_start = time.perf_counter()
        impact_analyzer = AttackImpactAnalyzer(graph)

        orchestrator = AegisMemRecoveryOrchestrator(
            repository=self.repository,
            impact_analyzer=impact_analyzer,
            manifest_store=self.manifest_store,
            provenance_manager=self.provenance_manager,
            checkpoint_store=self.checkpoint_store,
            trusted_head_store=self.trusted_head_store,
            vault_store=self.vault_store,
        )
        t_decide = time.perf_counter()

        recovery_service_url = os.getenv("RECOVERY_SERVICE_URL")
        recovery = None
        if recovery_service_url:
            try:
                import urllib.request, json
                internal_token = os.getenv("AEGISMEM_INTERNAL_TOKEN", "")
                hdrs = {"Content-Type": "application/json"}
                if internal_token:
                    hdrs["X-Recovery-Token"] = internal_token
                body = json.dumps({"memory_id": memory_id}).encode("utf-8")
                req = urllib.request.Request(
                    f"{recovery_service_url}/recovery/execute",
                    data=body,
                    headers=hdrs,
                    method="POST"
                )
                with urllib.request.urlopen(req, timeout=10) as resp:
                    recovery = json.loads(resp.read().decode("utf-8"))
            except Exception as rec_err:
                print(f"[AegisMem Monitor] Delegation to recovery service failed: {rec_err}")

        if recovery is None:
            recovery = orchestrator.recover_from_attack(
                compromised_memory_id=memory_id,
                attack_time=datetime.now(timezone.utc),
            )
        t_recover = time.perf_counter()

        current = self.repository.get_latest(memory_id)
        t_validate = time.perf_counter()

        recovery_results = recovery.get("results", [])
        content_recovered = any(
            result.get("action") == "ROLLBACK"
            and result.get("content_recovered", False)
            and result.get("recovery_provenance_verified", False)
            for result in recovery_results
        )

        action_taken = "ROLLBACK" if content_recovered else "QUARANTINE"
        telemetry_rec = get_detection_telemetry().record_incident(
            memory_id=memory_id,
            version=current.version if current else 1,
            t_write=t0_write,
            t_detect=t_detect,
            t_decide=t_decide,
            t_recover=t_recover,
            t_validate=t_validate,
            detected=True,
            recovered=content_recovered,
            action_taken=action_taken,
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
            "telemetry": telemetry_rec,
        }
