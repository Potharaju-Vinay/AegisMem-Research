from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy.orm import Session

from attack_lab.models import AttackEvent
from core.memory.models import MemoryRecord
from core.memory.repository import MemoryRepository


class MemoryAttacker:

    def __init__(self, session: Session):
        self.session = session
        self.repository = MemoryRepository(session)

    def corrupt_memory(
        self,
        memory: MemoryRecord,
        corrupted_content: str,
        attack_type: str = "content_tampering",
        mutation_description: str = "Controlled content mutation",
        attacker: str = "research-attacker"
    ) -> AttackEvent:

        if memory.status != "active":
            raise ValueError(
                "Only active memory can be attacked."
            )

        corrupted = self.repository.create(
            memory_id=memory.memory_id,
            content=corrupted_content,
            source=memory.source,
            source_type=memory.source_type
        )

        corrupted.trust_score = 0.0
        corrupted.suspicion_score = 1.0
        corrupted.status = "CORRUPTED"

        attack_event = AttackEvent(
            attack_id=f"ATK-{uuid4().hex[:12].upper()}",
            memory_record_id=corrupted.id,
            memory_id=corrupted.memory_id,
            original_content=memory.content,
            modified_content=corrupted.content,
            original_version=memory.version,
            target_version=corrupted.version,
            original_content_hash=memory.content_hash,
            observed_content_hash=corrupted.content_hash,
            attack_type=attack_type,
            mutation_description=mutation_description,
            attacker=attacker,
            attack_time=datetime.now(timezone.utc),
            integrity_compromised=True,
            status="DETECTED"
        )

        self.session.add(attack_event)
        self.session.commit()
        self.session.refresh(attack_event)
        self.session.refresh(corrupted)

        return attack_event