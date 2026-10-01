from dataclasses import dataclass
from datetime import datetime

from core.graph.dependency.engine import DependencyGraph


@dataclass(frozen=True)
class TrustState:
    memory_id: str
    trust: float
    distance: int
    parent_memory_id: str | None
    impact_score: float


class TemporalTrustPropagator:

    def __init__(
        self,
        graph: DependencyGraph,
        decay: float = 1.0
    ):
        if not 0.0 < decay <= 1.0:
            raise ValueError(
                "Decay must be between 0 and 1."
            )

        self.graph = graph
        self.decay = decay

    def propagate(
        self,
        compromised_memory_id: str,
        timestamp: datetime
    ) -> dict[str, TrustState]:

        self.graph.load_at(timestamp)

        if compromised_memory_id not in self.graph.graph:
            return {}

        trust_states: dict[str, TrustState] = {}

        queue = [
            (
                compromised_memory_id,
                0.0,
                0,
                None
            )
        ]

        visited: dict[str, float] = {}

        while queue:

            current, current_trust, distance, parent = queue.pop(0)

            if current in visited:
                if visited[current] >= current_trust:
                    continue

            visited[current] = current_trust

            # Impact is the loss of trust.
            # Root compromised memory:
            # trust = 0.0
            # impact = 1.0
            impact_score = round(
                1.0 - current_trust,
                12
            )

            trust_states[current] = TrustState(
                memory_id=current,
                trust=round(
                    current_trust,
                    12
                ),
                distance=distance,
                parent_memory_id=parent,
                impact_score=impact_score
            )

            for neighbor in self.graph.graph.successors(current):

                strength = self.graph.edge_strength(
                    current,
                    neighbor
                )

                if distance == 0:
                    propagated_trust = (
                        strength * self.decay
                    )
                else:
                    propagated_trust = (
                        current_trust
                        * strength
                        * self.decay
                    )

                propagated_trust = round(
                    propagated_trust,
                    12
                )

                queue.append(
                    (
                        neighbor,
                        propagated_trust,
                        distance + 1,
                        current
                    )
                )

        return trust_states