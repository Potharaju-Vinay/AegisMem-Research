from dataclasses import dataclass

from core.graph.dependency.engine import DependencyGraph
from core.trust.propagation import TemporalTrustPropagator


@dataclass
class ImpactedMemory:
    memory_id: str
    trust: float
    distance: int
    parent_memory_id: str | None
    impact_score: float


class AttackImpactAnalyzer:

    def __init__(
        self,
        graph: DependencyGraph,
        decay: float = 1.0
    ):
        self.graph = graph
        self.propagator = TemporalTrustPropagator(
            graph,
            decay=decay
        )

    def analyze(
        self,
        compromised_memory_id: str,
        timestamp
    ) -> dict[str, ImpactedMemory]:

        result = self.propagator.propagate(
            compromised_memory_id=compromised_memory_id,
            timestamp=timestamp
        )

        impacted = {}

        for memory_id, state in result.items():

            # Preserve the mathematically derived impact
            # from the trust propagation stage.
            impact_score = round(
                1.0 - state.trust,
                10
            )

            impacted[memory_id] = ImpactedMemory(
                memory_id=state.memory_id,
                trust=state.trust,
                distance=state.distance,
                parent_memory_id=state.parent_memory_id,
                impact_score=impact_score
            )

        return impacted