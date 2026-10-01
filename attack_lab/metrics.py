from dataclasses import dataclass


@dataclass
class ImpactMetrics:
    total_memories: int
    affected_memories: int
    maximum_distance: int
    average_impact: float
    cumulative_impact: float


class ImpactMetricCalculator:

    def calculate(self, impact_result) -> ImpactMetrics:

        memories = list(impact_result.values())

        if not memories:
            return ImpactMetrics(
                total_memories=0,
                affected_memories=0,
                maximum_distance=0,
                average_impact=0.0,
                cumulative_impact=0.0
            )

        downstream = [
            memory
            for memory in memories
            if memory.distance > 0
        ]

        impacts = [
            memory.impact_score
            for memory in downstream
        ]

        return ImpactMetrics(
            total_memories=len(memories),
            affected_memories=len(downstream),
            maximum_distance=max(
                memory.distance for memory in memories
            ),
            average_impact=round(
                sum(impacts) / len(impacts),
                10
            ) if impacts else 0.0,
            cumulative_impact=round(
                sum(impacts),
                10
            )
        )
