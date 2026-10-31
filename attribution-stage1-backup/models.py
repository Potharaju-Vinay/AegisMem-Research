from dataclasses import dataclass


@dataclass
class DetectionEvidence:

    integrity_compromised: bool

    provenance_suspicious: bool

    attack_detected: bool

    status_corrupted: bool
    
    authorization_valid: bool

    suspicion_score: float

    dependency_exposure: float

    dependency_contamination: bool

    content_changed: bool

    numeric_change_detected: bool

    numeric_changes: list


@dataclass
class DetectionResult:

    memory_id: str

    compromised: bool

    suspicion_score: float

    evidence: DetectionEvidence

    reason: str