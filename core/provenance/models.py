
from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from core.memory.database import Base


class ProvenanceEvent(Base):

    __tablename__ = "provenance_events"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True
    )

    memory_record_id: Mapped[int] = mapped_column(
        ForeignKey("memories.id"),
        index=True
    )

    memory_id: Mapped[str] = mapped_column(
        String(128),
        index=True
    )

    version: Mapped[int] = mapped_column(
        Integer
    )

    actor: Mapped[str] = mapped_column(
        String(128)
    )

    operation: Mapped[str] = mapped_column(
        String(64)
    )

    source: Mapped[str] = mapped_column(
        String(512)
    )

    source_type: Mapped[str] = mapped_column(
        String(128)
    )

    event_time: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc)
    )

    previous_event_hash: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True
    )

    event_hash: Mapped[str] = mapped_column(
        String(64)
    )

    event_metadata: Mapped[str | None] = mapped_column(
        Text,
        nullable=True
    )
