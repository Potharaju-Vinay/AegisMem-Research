from sqlalchemy import select
from sqlalchemy.orm import Session

from core.integrity.hash import calculate_version_hash
from core.memory.models import MemoryRecord


class MemoryRepository:

    def __init__(self, session: Session):
        self.session = session

    def create(
        self,
        memory_id: str,
        content: str,
        source: str,
        source_type: str
    ) -> MemoryRecord:

        existing = self.get_latest(memory_id)

        version = 1
        previous_id = None
        previous_hash = None

        if existing:
            version = existing.version + 1
            previous_id = existing.id
            previous_hash = existing.content_hash

        content_hash = calculate_version_hash(
            content,
            previous_hash
        )

        record = MemoryRecord(
            memory_id=memory_id,
            version=version,
            content=content,
            source=source,
            source_type=source_type,
            previous_version_id=previous_id,
            content_hash=content_hash,
            previous_hash=previous_hash,
            trust_score=1.0,
            suspicion_score=0.0,
            status="active"
        )

        self.session.add(record)
        self.session.commit()
        self.session.refresh(record)

        return record

    def get_latest(
        self,
        memory_id: str
    ) -> MemoryRecord | None:

        statement = (
            select(MemoryRecord)
            .where(MemoryRecord.memory_id == memory_id)
            .order_by(MemoryRecord.version.desc())
        )

        return self.session.scalars(statement).first()

    def get_version(
        self,
        memory_id: str,
        version: int
    ) -> MemoryRecord | None:

        statement = (
            select(MemoryRecord)
            .where(
                MemoryRecord.memory_id == memory_id,
                MemoryRecord.version == version
            )
        )

        return self.session.scalars(statement).first()

    def get_history(
        self,
        memory_id: str
    ) -> list[MemoryRecord]:

        statement = (
            select(MemoryRecord)
            .where(MemoryRecord.memory_id == memory_id)
            .order_by(MemoryRecord.version.asc())
        )

        return list(self.session.scalars(statement).all())