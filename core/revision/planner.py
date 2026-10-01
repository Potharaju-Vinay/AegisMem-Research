from core.revision.models import RevisionCandidate


class DependencyAwareRevisionPlanner:

    def __init__(
        self,
        impact_threshold: float = 0.1,
        trust_threshold: float = 0.9
    ):
        self.impact_threshold = impact_threshold
        self.trust_threshold = trust_threshold

    def rank(
        self,
        impact_result,
        provenance_weights=None,
        temporal_weights=None
    ) -> list[RevisionCandidate]:

        provenance_weights = provenance_weights or {}
        temporal_weights = temporal_weights or {}

        candidates = []

        for memory_id, state in impact_result.items():

            if state.distance == 0:
                continue

            provenance_weight = provenance_weights.get(
                memory_id,
                1.0
            )

            temporal_weight = temporal_weights.get(
                memory_id,
                1.0
            )

            priority = round(
                state.impact_score
                * (1.0 / state.distance)
                * provenance_weight
                * temporal_weight,
                10
            )

            requires_revision = (
                state.impact_score >= self.impact_threshold
                or state.trust < self.trust_threshold
            )

            candidates.append(
                RevisionCandidate(
                    memory_id=memory_id,
                    current_trust=state.trust,
                    impact_score=state.impact_score,
                    dependency_distance=state.distance,
                    provenance_weight=provenance_weight,
                    temporal_weight=temporal_weight,
                    priority_score=priority,
                    requires_revision=requires_revision
                )
            )

        candidates.sort(
            key=lambda candidate: candidate.priority_score,
            reverse=True
        )

        return candidates
