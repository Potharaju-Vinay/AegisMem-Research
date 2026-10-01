from dataclasses import dataclass
import random
from experiments.benchmark.attack_generator import AttackScenario


@dataclass(frozen=True)
class BenchmarkDetectionEvidence:
    memory_id: str
    attack_evidence: bool
    provenance_evidence: bool
    suspicion_score: float

    @property
    def compromised(self) -> bool:
        return self.attack_evidence or self.provenance_evidence


class BenchmarkEvidenceGenerator:
    def __init__(self, seed: int = 42):
        self.random = random.Random(seed)

    def generate(self, scenario: AttackScenario) -> dict[str, BenchmarkDetectionEvidence]:
        evidence = {}

        all_memory_ids = (
            scenario.contaminated_memory_ids
            | scenario.exposed_memory_ids
            | scenario.unaffected_memory_ids
        )

        for memory_id in all_memory_ids:
            if memory_id == scenario.root_memory_id:
                evidence[memory_id] = BenchmarkDetectionEvidence(
                    memory_id=memory_id,
                    attack_evidence=True,
                    provenance_evidence=True,
                    suspicion_score=1.0
                )

            elif memory_id in scenario.contaminated_memory_ids:
                provenance_detected = self.random.random() < 0.75
                suspicion = 0.65 if provenance_detected else 0.40

                evidence[memory_id] = BenchmarkDetectionEvidence(
                    memory_id=memory_id,
                    attack_evidence=False,
                    provenance_evidence=provenance_detected,
                    suspicion_score=suspicion
                )

            else:
                evidence[memory_id] = BenchmarkDetectionEvidence(
                    memory_id=memory_id,
                    attack_evidence=False,
                    provenance_evidence=False,
                    suspicion_score=0.0
                )

        return evidence