from sqlalchemy.orm import Session

from core.memory.repository import MemoryRepository
from core.provenance.manager import ProvenanceManager


class MemoryService:

    def __init__(self, session: Session):
        self.repository = MemoryRepository(session)
        self.provenance = ProvenanceManager(session)

    def create_memory(
        self,
        memory_id: str,
        content: str,
        source: str,
        source_type: str,
        actor: str = "system"
    ):

        memory = self.repository.create(
            memory_id=memory_id,
            content=content,
            source=source,
            source_type=source_type
        )

        self.provenance.record(
            memory_record_id=memory.id,
            memory_id=memory.memory_id,
            version=memory.version,
            actor=actor,
            operation="CREATE",
            source=memory.source,
            source_type=memory.source_type
        )

        return memory

    def get_memory(self, memory_id: str):

        return self.repository.get_latest(memory_id)

    def get_version(
        self,
        memory_id: str,
        version: int
    ):

        return self.repository.get_version(
            memory_id,
            version
        )

    def get_history(self, memory_id: str):

        return self.repository.get_history(memory_id)
