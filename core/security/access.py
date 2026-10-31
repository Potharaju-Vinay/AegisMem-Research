from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from core.memory.database import Base


class MemoryAccessEvent(Base):

    __tablename__ = "memory_access_events"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True
    )

    access_id: Mapped[str] = mapped_column(
        String(128),
        unique=True,
        index=True
    )

    memory_id: Mapped[str] = mapped_column(
        String(128),
        index=True
    )

    memory_version: Mapped[int] = mapped_column(
        Integer
    )

    actor: Mapped[str] = mapped_column(
        String(128)
    )

    session_id: Mapped[str | None] = mapped_column(
        String(128),
        index=True,
        nullable=True
    )

    source_ip: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True
    )

    source_port: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True
    )

    entry_point: Mapped[str | None] = mapped_column(
        String(256),
        nullable=True
    )

    access_method: Mapped[str | None] = mapped_column(
        String(32),
        nullable=True
    )

    authorization_state: Mapped[str] = mapped_column(
        String(32)
    )

    access_time: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc)
    )


class MemoryAccessLogger:

    def __init__(self, session):
        self.session = session

    def record(
        self,
        memory_id: str,
        memory_version: int,
        actor: str,
        session_id: str | None = None,
        source_ip: str | None = None,
        source_port: int | None = None,
        entry_point: str | None = None,
        access_method: str | None = None,
        authorization_state: str = "UNKNOWN"
    ):

        event = MemoryAccessEvent(
            access_id=f"access-{uuid4().hex}",
            memory_id=memory_id,
            memory_version=memory_version,
            actor=actor,
            session_id=session_id,
            source_ip=source_ip,
            source_port=source_port,
            entry_point=entry_point,
            access_method=access_method,
            authorization_state=authorization_state
        )

        self.session.add(event)
        self.session.flush()

        return event
