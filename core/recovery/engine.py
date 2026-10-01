from core.memory.repository import MemoryRepository

from core.recovery.executor import RecoveryExecutor
from core.recovery.models import (
    RecoveryAction,
    RecoveryDecision
)
from core.recovery.resolver import TrustedVersionResolver
from core.recovery.validator import RecoveryValidator


class SelfHealingRecoveryEngine:

    def __init__(
        self,
        repository: MemoryRepository
    ):
        self.repository = repository

        self.resolver = TrustedVersionResolver(
            repository
        )

        self.executor = RecoveryExecutor(
            repository
        )

        self.validator = RecoveryValidator(
            repository
        )

    def plan_rollback(
        self,
        memory_id: str,
        trust_score: float
    ) -> RecoveryDecision:

        trusted = self.resolver.find_trusted_version(
            memory_id
        )

        if trusted is None:

            return RecoveryDecision(
                memory_id=memory_id,
                action=RecoveryAction.QUARANTINE,
                reason=(
                    "No sufficiently trusted historical "
                    "version was found."
                ),
                trust_score=trust_score,
                target_version=None
            )

        return RecoveryDecision(
            memory_id=memory_id,
            action=RecoveryAction.ROLLBACK,
            reason=(
                "Compromised memory has a verified "
                "trusted historical version."
            ),
            trust_score=trust_score,
            target_version=trusted.version
        )

    def recover(
        self,
        memory_id: str,
        trust_score: float
    ) -> dict:

        decision = self.plan_rollback(
            memory_id,
            trust_score
        )

        print()
        print("==========================================")
        print("        AEGISMEM SELF-HEALING ENGINE")
        print("==========================================")

        print(
            f"Memory              : {memory_id}"
        )

        print(
            f"Trust Score         : {trust_score:.2f}"
        )

        print(
            f"Recovery Decision   : "
            f"{decision.action.value}"
        )

        print(
            f"Reason              : "
            f"{decision.reason}"
        )

        if decision.action == RecoveryAction.QUARANTINE:

            return {
                "success": False,
                "action": decision.action.value,
                "reason": decision.reason
            }

        if decision.action == RecoveryAction.ROLLBACK:

            print(
                f"Trusted Version     : "
                f"v{decision.target_version}"
            )

            print()
            print("[AegisMem] Executing rollback...")

            result = self.executor.rollback(
                compromised_memory_id=memory_id,
                trusted_version=decision.target_version
            )

            if not result.success:

                return {
                    "success": False,
                    "action": result.action.value,
                    "reason": result.message
                }

            print(
                "[AegisMem] Memory restored."
            )

            print()
            print("[AegisMem] Validating recovered state...")

            validation = self.validator.validate(
                memory_id
            )

            print(
                f"[AegisMem] Integrity       : "
                f"{'PASS' if validation['integrity'] else 'FAIL'}"
            )

            print(
                f"[AegisMem] Trust           : "
                f"{'PASS' if validation['trust'] else 'FAIL'}"
            )

            print(
                f"[AegisMem] Status          : "
                f"{'PASS' if validation['status'] else 'FAIL'}"
            )

            print()

            if validation["valid"]:

                print(
                    "✓ SELF-HEALING SUCCESSFUL"
                )

            else:

                print(
                    "✗ SELF-HEALING VALIDATION FAILED"
                )

            print("==========================================")

            return {
                "success": validation["valid"],
                "action": result.action.value,
                "previous_version": result.previous_version,
                "restored_version": result.restored_version,
                "validation": validation
            }

        return {
            "success": False,
            "action": decision.action.value,
            "reason": "Recovery action not implemented yet."
        }