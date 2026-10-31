from datetime import datetime, timezone
from uuid import uuid4

from attack_lab.models import AttackEvent
from core.integrity.hash import calculate_content_hash
from core.memory.repository import MemoryRepository
from core.provenance.manager import ProvenanceManager
from core.soc.engine import create_alert_from_attack


class ExternalMemoryAttacker:

    def __init__(self, session):
        self.session = session
        self.repository = MemoryRepository(session)

    def modify_memory(
        self,
        memory_id: str,
        modified_content: str,
        attacker: str,
        attack_type: str = "content_tampering",
        session_id: str | None = None,
        source_ip: str | None = None,
        source_port: int | None = None,
        entry_point: str | None = None,
        access_method: str | None = None
    ):
        attack_start_time = datetime.now(timezone.utc)

        memory = self.repository.get_latest(memory_id)

        if memory is None:
            raise ValueError(
                f"Memory '{memory_id}' does not exist."
            )

        if memory.status != "active":
            raise ValueError(
                f"Memory '{memory_id}' is not active."
            )

        if not modified_content.strip():
            raise ValueError(
                "Modified content cannot be empty."
            )

        if modified_content == memory.content:
            raise ValueError(
                "Modified content must differ from original content."
            )

        original_content = memory.content
        original_version = memory.version

        modified = self.repository.create(
            memory_id=memory.memory_id,
            content=modified_content,
            source="external_memory_write",
            source_type="external_memory_write"
        )

        modified.trust_score = 0.0
        modified.suspicion_score = 1.0
        modified.status = "CORRUPTED"

        self.session.commit()
        self.session.refresh(modified)

        attack_end_time = datetime.now(timezone.utc)

        duration_ms = (
            attack_end_time - attack_start_time
        ).total_seconds() * 1000

        attack_id = f"ATK-{uuid4().hex[:12].upper()}"

        attack_event = AttackEvent(
            attack_id=attack_id,
            memory_record_id=modified.id,
            memory_id=modified.memory_id,
            original_content=original_content,
            modified_content=modified_content,
            original_version=original_version,
            target_version=modified.version,
            original_content_hash=calculate_content_hash(
                original_content
            ),
            observed_content_hash=calculate_content_hash(
                modified_content
            ),
            attack_type=attack_type,
            mutation_description=(
                "External actor modified persistent memory "
                "through an unauthorized memory write."
            ),
            attacker=attacker,
            attack_time=attack_end_time,
                        session_id=session_id,
            source_ip=source_ip,
            source_port=source_port,
            entry_point=entry_point,
            access_method=access_method,
            attack_start_time=attack_start_time,
            attack_end_time=attack_end_time,
            duration_ms=duration_ms,
            integrity_compromised=(
    calculate_content_hash(original_content)
    != calculate_content_hash(modified_content)
),
            status="OBSERVED"
        )

        self.session.add(attack_event)
        self.session.commit()
        self.session.refresh(attack_event)

        provenance_manager = ProvenanceManager(
            self.session
        )

        provenance_event = provenance_manager.record(
            memory_record_id=modified.id,
            memory_id=modified.memory_id,
            version=modified.version,
            actor=attacker,
            operation="MEMORY_WRITE",
            source="external_attack",
            source_type="external_memory_write",
            metadata={
                "attack_type": attack_type,
                "attack_id": attack_id,
                "original_version": original_version,
                "target_version": modified.version,
                "session_id": session_id,
                "source_ip": source_ip,
                "source_port": source_port,
                "entry_point": entry_point,
                "access_method": access_method,
                "attack_start_time": (
                    attack_start_time.isoformat()
                ),
                "attack_end_time": (
                    attack_end_time.isoformat()
                ),
                "duration_ms": duration_ms
            }
        )

        self.session.commit()
        
        create_alert_from_attack(self.session, attack_event)

        return {
            "attack_id": attack_id,
            "provenance_id": provenance_event.id,
            "memory_id": modified.memory_id,
            "original_version": original_version,
            "target_version": modified.version,
            "original_content": original_content,
            "modified_content": modified.content,
            "attacker": attacker,
            "attack_type": attack_type,
            "status": modified.status,
            "session_id": session_id,
            "source_ip": source_ip,
            "source_port": source_port,
            "entry_point": entry_point,
            "access_method": access_method,
            "attack_start_time": attack_start_time.isoformat(),
            "attack_end_time": attack_end_time.isoformat(),
            "duration_ms": duration_ms
        }