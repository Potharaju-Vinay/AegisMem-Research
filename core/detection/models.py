from dataclasses import dataclass


@dataclass
class DetectionEvidence:

    integrity_compromised: bool

    provenance_suspicious: bool

    attack_detected: bool

    status_corrupted: bool

    suspicion_score: float

    dependency_exposure: float

    dependency_contamination: bool


@dataclass
class DetectionResult:

    memory_id: str

    compromised: bool

    suspicion_score: float

    evidence: DetectionEvidence

    reason: str