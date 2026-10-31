from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from core.graph.dependency.models import MemoryDependency


class DependencyRepository:

    def __init__(self, session: Session):
        self.session = session

    def add_dependency(
        self,
        source_memory_id: str,
        target_memory_id: str,
        dependency_type: str,
        strength: float = 1.0,
        source_record_id: int | None = None,
        target_record_id: int | None = None,
        valid_from: datetime | None = None,
        valid_until: datetime | None = None,
        observed_at: datetime | None = None
    ) -> MemoryDependency:

        if not 0.0 <= strength <= 1.0:
            raise ValueError(
                "Dependency strength must be between 0 and 1."
            )

        if valid_from is not None and valid_until is not None:
            if valid_until < valid_from:
                raise ValueError(
                    "valid_until cannot be earlier than valid_from."
                )

        now = datetime.now(timezone.utc)

        dependency = MemoryDependency(
            source_memory_id=source_memory_id,
            target_memory_id=target_memory_id,
            dependency_type=dependency_type,
            strength=strength,
            source_record_id=source_record_id,
            target_record_id=target_record_id,
            valid_from=valid_from or now,
            valid_until=valid_until,
            observed_at=observed_at or now
        )

        self.session.add(dependency)
        self.session.commit()
        self.session.refresh(dependency)

        return dependency

    def get_dependencies(
        self,
        memory_id: str
    ) -> list[MemoryDependency]:

        statement = (
            select(MemoryDependency)
            .where(
                MemoryDependency.source_memory_id == memory_id
            )
        )

        return list(
            self.session.scalars(statement).all()
        )

    def get_dependents(
        self,
        memory_id: str
    ) -> list[MemoryDependency]:

        statement = (
            select(MemoryDependency)
            .where(
                MemoryDependency.target_memory_id == memory_id
            )
        )

        return list(
            self.session.scalars(statement).all()
        )

    def get_active_dependencies(
        self,
        memory_id: str,
        timestamp: datetime
    ) -> list[MemoryDependency]:

        statement = (
            select(MemoryDependency)
            .where(
                MemoryDependency.source_memory_id == memory_id,
                MemoryDependency.valid_from <= timestamp,
                (
                    MemoryDependency.valid_until.is_(None)
                    |
                    (MemoryDependency.valid_until >= timestamp)
                )
            )
        )

        return list(
            self.session.scalars(statement).all()
        )

    def get_all(self) -> list[MemoryDependency]:

        statement = select(MemoryDependency)

        return list(
            self.session.scalars(statement).all()
        )
