from dataclasses import dataclass
from enum import Enum


class RecoveryAction(str, Enum):
    RETAIN = "RETAIN"
    ROLLBACK = "ROLLBACK"
    QUARANTINE = "QUARANTINE"
    DELETE = "DELETE"


@dataclass
class RecoveryDecision:
    memory_id: str
    action: RecoveryAction
    reason: str
    trust_score: float
    target_version: int | None = None


@dataclass
class RecoveryResult:
    memory_id: str
    action: RecoveryAction
    success: bool
    previous_version: int | None
    restored_version: int | None
    message: str