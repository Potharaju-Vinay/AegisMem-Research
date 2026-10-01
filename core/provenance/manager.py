
import json

from sqlalchemy import select
from sqlalchemy.orm import Session

from core.integrity.hash import calculate_version_hash
from core.provenance.models import ProvenanceEvent


class ProvenanceManager:

    def __init__(self, session: Session):
        self.session = session

    def _get_previous_event_hash(
        self,
        memory_id: str
    ) -> str | None:

        statement = (
            select(ProvenanceEvent)
            .where(
                ProvenanceEvent.memory_id == memory_id
            )
            .order_by(
                ProvenanceEvent.id.desc()
            )
            .limit(1)
        )

        previous_event = self.session.scalars(
            statement
        ).first()

        if previous_event is None:
            return None

        return previous_event.event_hash

    def record(
        self,
        memory_record_id: int,
        memory_id: str,
        version: int,
        actor: str,
        operation: str,
        source: str,
        source_type: str,
        metadata: dict | None = None
    ) -> ProvenanceEvent:

        metadata = metadata or {}

        previous_event_hash = self._get_previous_event_hash(
            memory_id
        )

        payload = {
            "memory_record_id": memory_record_id,
            "memory_id": memory_id,
            "version": version,
            "actor": actor,
            "operation": operation,
            "source": source,
            "source_type": source_type,
            "previous_event_hash": previous_event_hash,
            "metadata": metadata
        }

        event_hash = calculate_version_hash(
            json.dumps(
                payload,
                sort_keys=True
            ),
            None
        )

        event = ProvenanceEvent(
            memory_record_id=memory_record_id,
            memory_id=memory_id,
            version=version,
            actor=actor,
            operation=operation,
            source=source,
            source_type=source_type,
            previous_event_hash=previous_event_hash,
            event_hash=event_hash,
            event_metadata=json.dumps(
                metadata,
                sort_keys=True
            )
        )

        self.session.add(event)
        self.session.commit()
        self.session.refresh(event)

        return event

    def get_events(
        self,
        memory_id: str
    ) -> list[ProvenanceEvent]:

        statement = (
            select(ProvenanceEvent)
            .where(
                ProvenanceEvent.memory_id == memory_id
            )
            .order_by(
                ProvenanceEvent.version.asc()
            )
        )

        return list(
            self.session.scalars(statement).all()
        )
