from dataclasses import dataclass
from enum import Enum

from experiments.benchmark.graph_generator import BenchmarkGraph
from core.recovery.tcrp import TCRPRecoveryPlanner


class RecoveryAction(str, Enum):
    ROLLBACK = "ROLLBACK"
    RETAIN = "RETAIN"


@dataclass(frozen=True)
class RecoveryPlan:
    strategy: str
    recovered_memory_ids: set[str]


class FullRollbackBaseline:
    name = "FullRollback"

    def _descendants(self, graph: BenchmarkGraph, root: str) -> set[str]:
        recovered = {root}
        queue = [root]

        while queue:
            current = queue.pop(0)

            for child in graph.successors(current):
                if child not in recovered:
                    recovered.add(child)
                    queue.append(child)

        return recovered

    def plan(
        self,
        graph: BenchmarkGraph,
        root_memory_id: str,
        detection_results=None
    ) -> RecoveryPlan:
        return RecoveryPlan(
            strategy=self.name,
            recovered_memory_ids=self._descendants(
                graph,
                root_memory_id
            )
        )


class TrustOnlyBaseline:
    name = "TrustOnly"

    def __init__(self, rollback_threshold: float = 0.30):
        self.rollback_threshold = rollback_threshold

    def _calculate_trust(
        self,
        graph: BenchmarkGraph,
        root: str
    ) -> dict[str, float]:

        trust = {root: 0.0}
        queue = [root]

        while queue:
            current = queue.pop(0)

            for child in graph.successors(current):
                strength = graph.edge_strength(current, child)

                propagated = (
                    strength
                    if current == root
                    else trust[current] * strength
                )

                if child not in trust or propagated > trust[child]:
                    trust[child] = propagated
                    queue.append(child)

        return trust

    def plan(
        self,
        graph: BenchmarkGraph,
        root_memory_id: str,
        detection_results=None
    ) -> RecoveryPlan:

        trust_scores = self._calculate_trust(
            graph,
            root_memory_id
        )

        recovered = {
            memory_id
            for memory_id, trust in trust_scores.items()
            if trust < self.rollback_threshold
        }

        return RecoveryPlan(
            strategy=self.name,
            recovered_memory_ids=recovered
        )


class DependencyOnlyBaseline:
    name = "DependencyOnly"

    def _direct_dependents(
        self,
        graph: BenchmarkGraph,
        root: str
    ) -> set[str]:

        return set(graph.successors(root))

    def plan(
        self,
        graph: BenchmarkGraph,
        root_memory_id: str,
        detection_results=None
    ) -> RecoveryPlan:

        recovered = {
            root_memory_id,
            *self._direct_dependents(
                graph,
                root_memory_id
            )
        }

        return RecoveryPlan(
            strategy=self.name,
            recovered_memory_ids=recovered
        )


class DetectionOnlyBaseline:
    name = "DetectionOnly"

    def plan(
        self,
        graph: BenchmarkGraph,
        root_memory_id: str,
        detection_results=None
    ) -> RecoveryPlan:

        return RecoveryPlan(
            strategy=self.name,
            recovered_memory_ids=set()
        )


class AegisMemTCRPBaseline:
    name = "AegisMem-TCRP"

    def __init__(
        self,
        rollback_threshold: float = 0.30,
        quarantine_threshold: float = 0.70
    ):
        self.planner = TCRPRecoveryPlanner(
            rollback_threshold=rollback_threshold,
            quarantine_threshold=quarantine_threshold
        )

    def _propagate(
        self,
        graph: BenchmarkGraph,
        root: str
    ) -> dict[str, tuple[float, int]]:

        states = {
            root: (0.0, 0)
        }

        queue = [root]

        while queue:
            current = queue.pop(0)

            current_trust, distance = states[current]

            for child in graph.successors(current):

                strength = graph.edge_strength(
                    current,
                    child
                )

                if current == root:
                    propagated_trust = strength
                else:
                    propagated_trust = (
                        current_trust * strength
                    )

                new_distance = distance + 1

                if (
                    child not in states
                    or propagated_trust > states[child][0]
                ):
                    states[child] = (
                        propagated_trust,
                        new_distance
                    )

                    queue.append(child)

        return states

    def plan(
        self,
        graph: BenchmarkGraph,
        root_memory_id: str,
        detection_results=None
    ) -> RecoveryPlan:

        states = self._propagate(
            graph,
            root_memory_id
        )

        impacted_memories = {}

        for memory_id, (
            trust,
            distance
        ) in states.items():

            impact = 1.0 - trust

            impacted_memories[memory_id] = type(
                "ImpactState",
                (),
                {
                    "trust": trust,
                    "impact_score": impact,
                    "distance": distance
                }
            )()

        decisions = self.planner.plan(
            impacted_memories=impacted_memories,
            detection_results=detection_results
        )

        recovered = {
            decision.memory_id
            for decision in decisions
            if decision.action.value in {
                "ROLLBACK",
                "QUARANTINE"
            }
        }

        return RecoveryPlan(
            strategy=self.name,
            recovered_memory_ids=recovered
        )