from sqlalchemy.orm import Session

from core.memory.service import MemoryService


class MemoryRetriever:

    def __init__(self, session: Session):
        self.memory = MemoryService(session)

    def retrieve(self, memory_id: str):

        memory = self.memory.get_memory(memory_id)

        if memory is None:
            raise LookupError(
                f"Memory '{memory_id}' does not exist."
            )

        if memory.status != "active":
            raise ValueError(
                f"Memory '{memory_id}' is not trusted for retrieval."
            )

        return memory
