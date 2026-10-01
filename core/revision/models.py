from dataclasses import dataclass


@dataclass
class RevisionCandidate:
    memory_id: str
    current_trust: float
    impact_score: float
    dependency_distance: int
    provenance_weight: float
    temporal_weight: float
    priority_score: float
    requires_revision: bool
