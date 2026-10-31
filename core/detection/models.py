from dataclasses import dataclass, field


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

    integrity_anchor_status: str = "UNANCHORED"


@dataclass
class DetectionResult:

    memory_id: str

    compromised: bool

    suspicion_score: float

    evidence: DetectionEvidence

    reason: str

    attribution: str = "INCONCLUSIVE"
    attribution_evidence: list[str] = field(default_factory=list)
