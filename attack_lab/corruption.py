import uuid

from sqlalchemy.orm import Session

from attack_lab.models import AttackEvent
from core.memory.repository import MemoryRepository
from core.integrity.hash import calculate_content_hash


class MemoryCorruptionAttack:

    def __init__(self, session: Session):
        self.session = session
        self.repository = MemoryRepository(session)

    def corrupt(
        self,
        memory_id: str,
        modified_content: str
    ) -> AttackEvent:

        memory = self.repository.get_latest(memory_id)

        if memory is None:
            raise ValueError(
                f"Memory not found: {memory_id}"
            )

        original_content = memory.content

        original_content_hash = calculate_content_hash(
            original_content
        )

        observed_content_hash = calculate_content_hash(
            modified_content
        )

        event = AttackEvent(
            attack_id=f"ATT-{uuid.uuid4().hex[:12].upper()}",
            memory_record_id=memory.id,
            memory_id=memory.memory_id,
            original_content=original_content,
            modified_content=modified_content,
            original_version=memory.version,
            target_version=memory.version,
            original_content_hash=original_content_hash,
            observed_content_hash=observed_content_hash,
            attack_type="content_tampering",
            mutation_description=(
                "Memory content modified by simulated corruption attack"
            ),
            attacker="attack_lab",
            integrity_compromised=(
                original_content_hash != observed_content_hash
            ),
            status="CORRUPTED"
        )

        self.session.add(event)
        self.session.commit()
        self.session.refresh(event)

        return event