from core.integrity.hash import calculate_version_hash
from core.memory.repository import MemoryRepository


class RecoveryValidator:

    def __init__(self, repository: MemoryRepository):
        self.repository = repository

    def validate(
        self,
        memory_id: str
    ) -> dict:

        memory = self.repository.get_latest(memory_id)

        if memory is None:
            return {
                "valid": False,
                "reason": "Recovered memory not found."
            }

        expected_hash = calculate_version_hash(
            memory.content,
            memory.previous_hash
        )

        integrity_valid = (
            expected_hash == memory.content_hash
        )

        trust_valid = (
            memory.trust_score >= 0.8
            and memory.suspicion_score <= 0.2
        )

        status_valid = memory.status == "active"

        return {
            "valid": (
                integrity_valid
                and trust_valid
                and status_valid
            ),
            "integrity": integrity_valid,
            "trust": trust_valid,
            "status": status_valid,
            "version": memory.version,
            "content": memory.content
        }