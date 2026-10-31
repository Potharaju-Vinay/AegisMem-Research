from attack_lab.agent_attack import AttackPayload
from core.memory.repository import MemoryRepository


class MemoryPoisoningHandler:

    def __init__(self, repository: MemoryRepository):
        self.repository = repository

    def apply(
        self,
        payload: AttackPayload
    ):

        current = self.repository.get_latest(
            payload.target_memory_id
        )

        if current is None:
            raise ValueError(
                f"Memory {payload.target_memory_id} not found."
            )

        poisoned = self.repository.create(
            memory_id=payload.target_memory_id,
            content=payload.poisoned_content,
            source="prompt_injection_attack",
            source_type="memory_poisoning"
        )

        poisoned.trust_score = 0.0
        poisoned.suspicion_score = 1.0
        poisoned.status = "CORRUPTED"

        self.repository.session.commit()
        self.repository.session.refresh(poisoned)

        return poisoned