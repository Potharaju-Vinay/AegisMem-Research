
from unittest.mock import patch

from core.recovery.engine import SelfHealingRecoveryEngine
from core.recovery.models import RecoveryAction


def test_recovery_success_requires_verified_recovery_or_owner_authorization():
    engine = SelfHealingRecoveryEngine.__new__(SelfHealingRecoveryEngine)

    validation = {
        "valid": True,
        "content_valid": True,
        "authorization": False,
        "fully_verified": False,
        "recovery_provenance_verified": True,
        "integrity": True,
        "integrity_manifest": True,
        "recovery_attestation_valid": True,
        "provenance_verified": True,
        "trust": True,
        "status": True,
    }

    class FakeDecision:
        action = RecoveryAction.ROLLBACK
        target_version = 1
        reason = "Verified historical recovery point."
        trust_score = 0.5

    class FakeExecutorResult:
        success = True
        action = RecoveryAction.ROLLBACK
        previous_version = 2
        restored_version = 3
        message = "Restored."

    class FakeExecutor:
        def rollback(self, **kwargs):
            return FakeExecutorResult()

    class FakeValidator:
        def validate(self, memory_id):
            return validation

    engine.resolver = type(
        "FakeResolver",
        (),
        {"evaluate_candidates": lambda self, memory_id: {"selected_version": 1}},
    )()
    engine.plan_rollback = lambda *args: FakeDecision()
    engine.executor = FakeExecutor()
    engine.validator = FakeValidator()

    with patch("builtins.print"):
        result = engine.recover("TEST-RECOVERY", trust_score=0.5)

    assert result["content_valid"] is True
    assert result["authorization_valid"] is False
    assert result["recovery_verified"] is True
    assert result["fully_verified"] is False
    assert result["success"] is True

def test_recovery_fails_when_provenance_is_invalid():
    engine = SelfHealingRecoveryEngine.__new__(SelfHealingRecoveryEngine)

    validation = {
        "valid": True,
        "content_valid": True,
        "authorization": False,
        "fully_verified": False,
        "recovery_provenance_verified": False,
        "integrity": True,
        "integrity_manifest": True,
        "recovery_attestation_valid": False,
        "provenance_verified": True,
        "trust": True,
        "status": True,
    }

    class FakeDecision:
        action = RecoveryAction.ROLLBACK
        target_version = 1
        reason = "Test recovery."
        trust_score = 0.5

    class FakeExecutorResult:
        success = True
        action = RecoveryAction.ROLLBACK
        previous_version = 2
        restored_version = 3
        message = "Restored."

    class FakeExecutor:
        def rollback(self, **kwargs):
            return FakeExecutorResult()

    class FakeValidator:
        def validate(self, memory_id):
            return validation

    engine.resolver = type(
        "FakeResolver",
        (),
        {"evaluate_candidates": lambda self, memory_id: {}},
    )()
    engine.plan_rollback = lambda *args: FakeDecision()
    engine.executor = FakeExecutor()
    engine.validator = FakeValidator()

    with patch("builtins.print"):
        result = engine.recover("TEST-RECOVERY", trust_score=0.5)

    assert result["success"] is False
    assert result["recovery_verified"] is False
    assert result["fully_verified"] is False


def test_recovery_fails_when_content_is_invalid():
    engine = SelfHealingRecoveryEngine.__new__(SelfHealingRecoveryEngine)

    validation = {
        "valid": False,
        "content_valid": False,
        "authorization": True,
        "fully_verified": False,
        "recovery_provenance_verified": True,
        "integrity": False,
        "integrity_manifest": False,
        "recovery_attestation_valid": True,
        "provenance_verified": True,
        "trust": True,
        "status": True,
    }

    class FakeDecision:
        action = RecoveryAction.ROLLBACK
        target_version = 1
        reason = "Test recovery."
        trust_score = 0.5

    class FakeExecutorResult:
        success = True
        action = RecoveryAction.ROLLBACK
        previous_version = 2
        restored_version = 3
        message = "Restored."

    class FakeExecutor:
        def rollback(self, **kwargs):
            return FakeExecutorResult()

    class FakeValidator:
        def validate(self, memory_id):
            return validation

    engine.resolver = type(
        "FakeResolver",
        (),
        {"evaluate_candidates": lambda self, memory_id: {}},
    )()
    engine.plan_rollback = lambda *args: FakeDecision()
    engine.executor = FakeExecutor()
    engine.validator = FakeValidator()

    with patch("builtins.print"):
        result = engine.recover("TEST-RECOVERY", trust_score=0.5)

    assert result["success"] is False
    assert result["content_valid"] is False

