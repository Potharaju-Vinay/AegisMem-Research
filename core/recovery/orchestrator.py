import json
from datetime import datetime, timezone

from core.detection.detector import MemoryCompromiseDetector

from core.recovery.engine import SelfHealingRecoveryEngine
from core.recovery.models import RecoveryAction
from core.recovery.tcrp import TCRPRecoveryPlanner
from core.recovery.audit import RecoveryEvent

class AegisMemRecoveryOrchestrator:

    def _record_event(
    self,
    memory_id: str,
    event_type: str,
    action: str,
    message: str,
    status: str,
    compromised_version=None,
restored_version=None,
trust_score=None,
suspicion_score=None,
validation_result=None,
impact_score=None,
dependency_exposure=None,
selected_action_cost=None,
candidate_costs=None,
feasible_actions=None
):
        event = RecoveryEvent(
    memory_id=memory_id,
    event_type=event_type,
    action=action,
    message=message,
    status=status,
    compromised_version=compromised_version,
    restored_version=restored_version,
    trust_score=trust_score,
    suspicion_score=suspicion_score,
    validation_result=validation_result,
    impact_score=impact_score,
    dependency_exposure=dependency_exposure,
    selected_action_cost=selected_action_cost,
    candidate_costs=candidate_costs,
    feasible_actions=feasible_actions
)

        self.repository.session.add(event)
        self.repository.session.commit()

    def __init__(
        self,
        repository,
        impact_analyzer,
        rollback_threshold: float = 0.30,
        quarantine_threshold: float = 0.70
    ):

        self.repository = repository

        self.detector = MemoryCompromiseDetector(
            repository,
            dependency_graph=impact_analyzer.graph
        )

        self.impact_analyzer = impact_analyzer

        self.tcrp = TCRPRecoveryPlanner(
            rollback_threshold=rollback_threshold,
            quarantine_threshold=quarantine_threshold
        )

        self.recovery_engine = SelfHealingRecoveryEngine(
            repository
        )

    def recover_from_attack(
        self,
        compromised_memory_id: str,
        attack_time=None
    ) -> dict:

        if attack_time is None:
            attack_time = datetime.now(timezone.utc)

        current_memory = self.repository.get_latest(
            compromised_memory_id
        )

        if current_memory is None:
            return {
                "success": False,
                "reason": (
                    f"Memory '{compromised_memory_id}' "
                    "does not exist."
                ),
                "decisions": [],
                "results": []
            }

        current_detection = self.detector.detect(
            compromised_memory_id
        )

        current_is_trusted = (
            current_memory.trust_score >= 0.8
            and current_memory.suspicion_score <= 0.2
            and not current_detection.compromised
        )

        if (
            current_memory.status.upper() == "QUARANTINED"
            and current_is_trusted
        ):
            current_memory.status = "active"
            self.repository.session.commit()
            self.repository.session.refresh(
                current_memory
            )

            self._record_event(
                memory_id=compromised_memory_id,
                event_type="VALIDATION",
                action="REACTIVATE",
                message=(
                    "Verified trusted memory reactivated "
                    "after successful integrity and compromise checks."
                ),
                status="success"
            )

            return {
                "success": True,
                "compromised_memory": compromised_memory_id,
                "decisions": [
                    {
                        "memory_id": compromised_memory_id,
                        "trust_score": current_memory.trust_score,
                        "impact_score": 0.0,
                        "distance": 0,
                        "action": "REACTIVATE",
                        "reason": (
                            "Current memory is trusted, has low "
                            "suspicion, and has no detected compromise."
                        )
                    }
                ],
                "results": [
                    {
                        "memory_id": compromised_memory_id,
                        "action": "REACTIVATE",
                        "success": True,
                        "message": (
                            "Verified trusted memory reactivated."
                        )
                    }
                ]
            }

        print()
        print("==================================================")
        print("              AEGISMEM TCRP RECOVERY")
        print("==================================================")

        print()
        print("[1] Compromised memory")
        print(
            f"    Target : {compromised_memory_id}"
        )

        print()
        print("[2] Running dependency-aware trust propagation...")

        impacted = self.impact_analyzer.analyze(
            compromised_memory_id=compromised_memory_id,
            timestamp=attack_time
        )

        if not impacted:
            return {
                "success": False,
                "reason": "No impacted memories identified.",
                "decisions": [],
                "results": []
            }

        print()
        print("TCRP PHASE 1 — TRUST CASCADING")
        print("------------------------------------------")

        for memory_id, state in impacted.items():
            print(
                f"{memory_id:<15} "
                f"Trust={state.trust:.2f} "
                f"Impact={state.impact_score:.2f} "
                f"Distance={state.distance}"
            )

        # -------------------------------------------------
        # LOCAL EVIDENCE ANALYSIS
        # -------------------------------------------------

        print()
        print("TCRP LOCAL EVIDENCE ANALYSIS")
        print("------------------------------------------")

        detection_results = {}

        for memory_id in impacted:

            memory = self.repository.get_latest(
                memory_id
            )

            # A dependency can reference a memory that is
            # not currently present in the memory store.
            # Such a node receives no local compromise claim.
            if memory is None:

                print(
                    f"{memory_id:<15} "
                    f"Compromised=NO "
                    f"Suspicion=0.00 "
                    f"(memory record unavailable)"
                )

                continue

            detection = self.detector.detect(
                memory_id
            )

            detection_results[memory_id] = detection

            print(
                f"{memory_id:<15} "
                f"Compromised="
                f"{'YES' if detection.compromised else 'NO'} "
                f"Suspicion={detection.suspicion_score:.2f}"
            )

        # -------------------------------------------------
        # TCRP PHASE 2
        # -------------------------------------------------

        print()
        print("TCRP PHASE 2 — RECOVERY PLANNING")
        print("------------------------------------------")

        decisions = self.tcrp.plan(
            impacted_memories=impacted,
            repository=self.repository,
            detection_results=detection_results
        )

        for decision in decisions:

            print(
                f"{decision.memory_id:<15} "
                f"{decision.action.value:<12} "
                f"Trust={decision.trust_score:.2f}"
            )

            print(
                f"{'':15}"
                f"Reason: {decision.reason}"
            )

            decision_memory = self.repository.get_latest(
                decision.memory_id
            )

            decision_detection = detection_results.get(
                decision.memory_id
            )

            self._record_event(
    memory_id=decision.memory_id,
    event_type="TCRP_DECISION",
    action=decision.action.value,
    message=decision.reason,
    status="completed",
    compromised_version=(
        decision_memory.version
        if decision_memory is not None
        else None
    ),
    trust_score=decision.trust_score,
    suspicion_score=(
        decision_detection.suspicion_score
        if decision_detection is not None
        else None
    ),
    impact_score=decision.impact_score,
    dependency_exposure=decision.dependency_exposure,
    selected_action_cost=decision.action_cost,
                candidate_costs=json.dumps(
                decision.candidate_costs,
                sort_keys=True
            )
            if decision.candidate_costs is not None
            else None,
            feasible_actions=json.dumps(
                decision.feasible_actions
            )
            if decision.feasible_actions is not None
            else None
        )
        # -------------------------------------------------
        # RECOVERY EXECUTION
        # -------------------------------------------------

        print()
        print("TCRP RECOVERY EXECUTION")
        print("------------------------------------------")

        results = []

        for decision in decisions:

            if decision.action == RecoveryAction.RETAIN:

                print(
                    f"{decision.memory_id:<15}"
                    f"RETAIN ✓"
                )

                results.append({
                    "memory_id": decision.memory_id,
                    "action": "RETAIN",
                    "success": True,
                    "message": "Memory retained."
                })

                continue

            if decision.action == RecoveryAction.ROLLBACK:

                print(
                    f"{decision.memory_id:<15}"
                    f"ROLLBACK..."
                )

                memory = self.repository.get_latest(
                    decision.memory_id
                )

                if memory is None:

                    results.append({
                        "memory_id": decision.memory_id,
                        "action": "ROLLBACK",
                        "success": False,
                        "message": (
                            "Memory record unavailable; "
                            "rollback cannot be executed."
                        )
                    })

                    continue

                recovery = self.recovery_engine.recover(
                    memory_id=decision.memory_id,
                    trust_score=decision.trust_score
                )

                self._record_event(
    memory_id=decision.memory_id,
    event_type="RECOVERY",
    action="ROLLBACK",
    message=(
        "Memory rollback executed successfully."
        if recovery["success"]
        else "Memory rollback failed."
    ),
    status="success" if recovery["success"] else "failed",
    compromised_version=recovery.get("previous_version"),
    restored_version=recovery.get("restored_version"),
    trust_score=decision.trust_score,
    suspicion_score=detection_results.get(
        decision.memory_id
    ).suspicion_score if detection_results.get(
        decision.memory_id
    ) else None,
    validation_result=(
        "PASS"
        if recovery.get("validation", {}).get("valid")
        else "FAIL"
    )
)
                

                results.append({
                    "memory_id": decision.memory_id,
                    "action": "ROLLBACK",
                    "success": recovery["success"],
                    "details": recovery
                })

                continue

            if decision.action == RecoveryAction.QUARANTINE:

                print(
                    f"{decision.memory_id:<15}"
                    f"QUARANTINE"
                )

                memory = self.repository.get_latest(
                    decision.memory_id
                )

                if memory:

                    memory.status = "QUARANTINED"

                    self.repository.session.commit()

                    self._record_event(
                        memory_id=decision.memory_id,
                        event_type="RECOVERY",
                        action="QUARANTINE",
                        message="Memory isolated pending verification.",
                        status="success"
                    )

                    results.append({
                        "memory_id": decision.memory_id,
                        "action": "QUARANTINE",
                        "success": True,
                        "message": (
                            "Memory isolated pending verification."
                        )
                    })

                else:

                    results.append({
                        "memory_id": decision.memory_id,
                        "action": "QUARANTINE",
                        "success": False,
                        "message": "Memory record unavailable."
                    })

                continue

            if decision.action == RecoveryAction.DELETE:

                print(
                    f"{decision.memory_id:<15}"
                    f"DELETE"
                )

                results.append({
                    "memory_id": decision.memory_id,
                    "action": "DELETE",
                    "success": False,
                    "message": (
                        "Deletion execution is intentionally "
                        "disabled until explicit policy is configured."
                    )
                })

        successful = all(
            result["success"]
            for result in results
        )

        print()
        print("==================================================")

        if successful:

            print(
                "          ✓ AEGISMEM SELF-HEALING COMPLETE"
            )

        else:

            print(
                "          ✗ AEGISMEM RECOVERY INCOMPLETE"
            )

        print("==================================================")

        return {
            "success": successful,
            "compromised_memory": compromised_memory_id,
            "decisions": decisions,
            "results": results
        }