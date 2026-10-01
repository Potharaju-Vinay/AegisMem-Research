from dataclasses import dataclass

from core.recovery.models import RecoveryAction


@dataclass
class TCRPDecision:
    memory_id: str
    trust_score: float
    impact_score: float
    distance: int
    action: RecoveryAction
    reason: str
    local_suspicion: float = 0.0
    dependency_exposure: float = 0.0
    action_cost: float = 0.0
    candidate_costs: dict[str, float] | None = None
    feasible_actions: list[str] | None = None


class TCRPRecoveryPlanner:

    def __init__(
        self,
        rollback_threshold: float = 0.30,
        quarantine_threshold: float = 0.70,
        high_impact_threshold: float = 0.60,
        moderate_impact_threshold: float = 0.30,
        trust_weight: float = 0.35,
        suspicion_weight: float = 0.30,
        impact_weight: float = 0.25,
        disruption_weight: float = 0.10
    ):
        if not 0.0 <= rollback_threshold < quarantine_threshold <= 1.0:
            raise ValueError(
                "Thresholds must satisfy 0 <= rollback < quarantine <= 1."
            )

        if not 0.0 <= moderate_impact_threshold <= high_impact_threshold <= 1.0:
            raise ValueError(
                "Impact thresholds must satisfy 0 <= moderate <= high <= 1."
            )

        weights = (
            trust_weight,
            suspicion_weight,
            impact_weight,
            disruption_weight
        )

        if any(weight < 0.0 for weight in weights):
            raise ValueError(
                "TCRP weights cannot be negative."
            )

        total = sum(weights)

        if total == 0.0:
            raise ValueError(
                "At least one TCRP weight must be greater than zero."
            )

        self.rollback_threshold = rollback_threshold
        self.quarantine_threshold = quarantine_threshold
        self.high_impact_threshold = high_impact_threshold
        self.moderate_impact_threshold = moderate_impact_threshold

        self.trust_weight = trust_weight / total
        self.suspicion_weight = suspicion_weight / total
        self.impact_weight = impact_weight / total
        self.disruption_weight = disruption_weight / total

    def _clamp(self, value: float) -> float:
        return max(0.0, min(1.0, float(value)))

    def _candidate_costs(
        self,
        trust_score: float,
        impact_score: float,
        local_suspicion: float,
        dependency_exposure: float,
        distance: int,
        detected_compromise: bool
    ) -> dict[str, float]:

        trust_deficit = 1.0 - trust_score

        distance_factor = min(
            1.0,
            distance / 5.0
        )

        retain_cost = (
            self.trust_weight * trust_deficit
            + self.suspicion_weight * local_suspicion
            + self.impact_weight * impact_score
        )

        quarantine_cost = (
            self.trust_weight * 0.20
            + self.suspicion_weight * (1.0 - local_suspicion)
            + self.impact_weight * (1.0 - dependency_exposure)
            + self.disruption_weight * 0.35
            + 0.10 * distance_factor
        )

        rollback_cost = (
            self.trust_weight * (1.0 - trust_score)
            + self.suspicion_weight * (1.0 - local_suspicion)
            + self.impact_weight * (1.0 - impact_score)
            + self.disruption_weight * 0.20
        )

        delete_cost = (
            self.trust_weight * 0.15
            + self.suspicion_weight * (1.0 - local_suspicion)
            + self.impact_weight * (1.0 - impact_score)
            + self.disruption_weight * 0.90
        )

        if detected_compromise:
            retain_cost = 1.0
            quarantine_cost *= 0.85
            rollback_cost *= 0.55

        if max(
            local_suspicion,
            dependency_exposure,
            trust_deficit
        ) >= 0.80:
            retain_cost = max(
                retain_cost,
                0.90
            )

        return {
            "RETAIN": self._clamp(retain_cost),
            "ROLLBACK": self._clamp(rollback_cost),
            "QUARANTINE": self._clamp(quarantine_cost),
            "DELETE": self._clamp(delete_cost)
        }

    def _feasible_actions(
        self,
        local_status: str,
        detected_compromise: bool,
        trust_score: float,
        local_suspicion: float,
        impact_score: float,
        dependency_exposure: float,
        repository=None,
        memory_id: str | None = None
    ) -> list[str]:

        status = local_status.upper()

        feasible = []

        if not detected_compromise:
            if (
                trust_score >= self.rollback_threshold
                and local_suspicion < 0.50
                and dependency_exposure < 0.70
                and impact_score < self.high_impact_threshold
            ):
                feasible.append(
                    RecoveryAction.RETAIN.value
                )

        if detected_compromise:
            feasible.append(
                RecoveryAction.ROLLBACK.value
            )

        elif repository is not None and memory_id is not None:
            history = repository.get_history(memory_id)

            if history:
                feasible.append(
                    RecoveryAction.ROLLBACK.value
                )

        if (
            detected_compromise
            or local_suspicion >= 0.50
            or dependency_exposure >= 0.70
            or impact_score >= self.moderate_impact_threshold
            or status in {"CORRUPTED", "DELETED"}
        ):
            feasible.append(
                RecoveryAction.QUARANTINE.value
            )

        # DELETE remains disabled by the current recovery policy.
        # It is intentionally excluded from feasible actions.

        if status in {"CORRUPTED", "DELETED"}:
            feasible = [
                action
                for action in feasible
                if action != RecoveryAction.RETAIN.value
            ]

        if detected_compromise:
            feasible = [
                action
                for action in feasible
                if action != RecoveryAction.RETAIN.value
            ]

        return list(
            dict.fromkeys(feasible)
        )

    def decide(
        self,
        memory_id: str,
        trust_score: float,
        impact_score: float,
        distance: int,
        local_status: str = "active",
        local_suspicion: float = 0.0,
        dependency_exposure: float = 0.0,
        detected_compromise: bool = False,
        repository=None
    ) -> TCRPDecision:

        trust_score = self._clamp(trust_score)
        impact_score = self._clamp(impact_score)
        local_suspicion = self._clamp(local_suspicion)
        dependency_exposure = self._clamp(dependency_exposure)
        distance = max(0, distance)

        candidate_costs = self._candidate_costs(
            trust_score=trust_score,
            impact_score=impact_score,
            local_suspicion=local_suspicion,
            dependency_exposure=dependency_exposure,
            distance=distance,
            detected_compromise=detected_compromise
        )

        feasible_actions = self._feasible_actions(
            local_status=local_status,
            detected_compromise=detected_compromise,
            trust_score=trust_score,
            local_suspicion=local_suspicion,
            impact_score=impact_score,
            dependency_exposure=dependency_exposure,
            repository=repository,
            memory_id=memory_id
        )

        if not feasible_actions:
            feasible_actions = [
                RecoveryAction.QUARANTINE.value
            ]

        selected_action_name = min(
            feasible_actions,
            key=lambda action: candidate_costs[action]
        )

        selected_action = RecoveryAction(
            selected_action_name
        )

        if detected_compromise:
            reason = (
                "Direct compromise evidence made retention infeasible; "
                "TCRP selected the minimum-cost feasible recovery action."
            )

        elif selected_action == RecoveryAction.ROLLBACK:
            reason = (
                "A trusted historical version is available and rollback "
                "has the minimum cost among feasible recovery actions."
            )

        elif selected_action == RecoveryAction.QUARANTINE:
            reason = (
                "Recovery evidence or dependency impact prevents safe "
                "retention; TCRP selected the minimum-cost feasible "
                "containment action."
            )

        else:
            reason = (
                "No sufficient compromise evidence was present and "
                "retention remained feasible."
            )

        return TCRPDecision(
            memory_id=memory_id,
            trust_score=trust_score,
            impact_score=impact_score,
            distance=distance,
            action=selected_action,
            reason=reason,
            local_suspicion=local_suspicion,
            dependency_exposure=dependency_exposure,
            action_cost=candidate_costs[selected_action_name],
            candidate_costs=candidate_costs,
            feasible_actions=feasible_actions
        )

    def plan(
        self,
        impacted_memories,
        repository=None,
        detection_results=None
    ):

        decisions = []

        detection_results = (
            detection_results
            if detection_results is not None
            else {}
        )

        for memory_id, state in impacted_memories.items():

            local_status = "active"
            local_suspicion = 0.0
            dependency_exposure = 0.0
            detected_compromise = False

            if repository is not None:

                current = repository.get_latest(
                    memory_id
                )

                if current is not None:
                    local_status = current.status
                    local_suspicion = float(
                        current.suspicion_score
                    )

            detection = detection_results.get(
                memory_id
            )

            if detection is not None:

                detected_compromise = (
                    detection.compromised
                )

                local_suspicion = max(
                    local_suspicion,
                    detection.suspicion_score
                )

                if hasattr(
                    detection,
                    "evidence"
                ):
                    dependency_exposure = self._clamp(
                        getattr(
                            detection.evidence,
                            "dependency_exposure",
                            0.0
                        )
                    )

            decision = self.decide(
                memory_id=memory_id,
                trust_score=state.trust,
                impact_score=state.impact_score,
                distance=state.distance,
                local_status=local_status,
                local_suspicion=local_suspicion,
                dependency_exposure=dependency_exposure,
                detected_compromise=detected_compromise,
                repository=repository
            )

            decisions.append(
                decision
            )

        return decisions