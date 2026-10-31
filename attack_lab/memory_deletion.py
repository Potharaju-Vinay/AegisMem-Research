from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy.orm import Session

from attack_lab.models import AttackEvent
from core.memory.repository import MemoryRepository


class MemoryDeletionAttack:

    def __init__(self, session: Session):
        self.session = session
        self.repository = MemoryRepository(session)

    def delete_memory(
        self,
        memory_id: str
    ) -> AttackEvent:

        memory = self.repository.get_latest(memory_id)

        if memory is None:
            raise ValueError(
                f"Memory not found: {memory_id}"
            )

        if memory.status != "active":
            raise ValueError(
                "Only active memory can be deleted."
            )

        deleted = self.repository.create(
            memory_id=memory.memory_id,
            content=memory.content,
            source=memory.source,
            source_type=memory.source_type
        )

        deleted.trust_score = 0.0
        deleted.suspicion_score = 1.0
        deleted.status = "DELETED"

        attack_event = AttackEvent(
            attack_id=f"DEL-{uuid4().hex[:12].upper()}",
            memory_record_id=deleted.id,
            memory_id=deleted.memory_id,
            original_content=memory.content,
            modified_content="",
            original_version=memory.version,
            target_version=deleted.version,
            original_content_hash=memory.content_hash,
            observed_content_hash=deleted.content_hash,
            attack_type="memory_deletion",
            mutation_description=(
                "Persistent memory marked as deleted by "
                "controlled deletion attack"
            ),
            attacker="attack_lab",
            attack_time=datetime.now(timezone.utc),
            integrity_compromised=False,
            status="DETECTED"
        )

        self.session.add(attack_event)
        self.session.commit()
        self.session.refresh(deleted)
        self.session.refresh(attack_event)

        return attack_event