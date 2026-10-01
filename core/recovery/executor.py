from core.memory.repository import MemoryRepository

from core.recovery.models import (
    RecoveryAction,
    RecoveryResult
)


class RecoveryExecutor:

    def __init__(self, repository: MemoryRepository):
        self.repository = repository

    def rollback(
        self,
        compromised_memory_id: str,
        trusted_version: int
    ) -> RecoveryResult:

        history = self.repository.get_history(
            compromised_memory_id
        )

        if not history:
            return RecoveryResult(
                memory_id=compromised_memory_id,
                action=RecoveryAction.ROLLBACK,
                success=False,
                previous_version=None,
                restored_version=None,
                message="Memory history not found."
            )

        current = history[-1]

        target = self.repository.get_version(
            compromised_memory_id,
            trusted_version
        )

        if target is None:
            return RecoveryResult(
                memory_id=compromised_memory_id,
                action=RecoveryAction.ROLLBACK,
                success=False,
                previous_version=current.version,
                restored_version=None,
                message="Trusted recovery version not found."
            )

        # Create a new version containing the trusted content.
        restored = self.repository.create(
            memory_id=compromised_memory_id,
            content=target.content,
            source=target.source,
            source_type=target.source_type
        )

        restored.trust_score = 1.0
        restored.suspicion_score = 0.0
        restored.status = "active"

        self.repository.session.commit()
        self.repository.session.refresh(restored)

        return RecoveryResult(
            memory_id=compromised_memory_id,
            action=RecoveryAction.ROLLBACK,
            success=True,
            previous_version=current.version,
            restored_version=restored.version,
            message=(
                f"Restored trusted content from version "
                f"{trusted_version}."
            )
        )