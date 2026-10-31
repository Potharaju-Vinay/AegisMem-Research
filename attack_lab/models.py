from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from core.memory.database import Base


class AttackEvent(Base):

    __tablename__ = "attack_events"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True
    )

    attack_id: Mapped[str] = mapped_column(
        String(128),
        unique=True,
        index=True
    )

    memory_record_id: Mapped[int] = mapped_column(
        Integer,
        index=True
    )

    memory_id: Mapped[str] = mapped_column(
        String(128),
        index=True
    )

    original_content: Mapped[str] = mapped_column(
        Text
    )

    modified_content: Mapped[str] = mapped_column(
        Text
    )

    original_version: Mapped[int] = mapped_column(
        Integer
    )

    target_version: Mapped[int] = mapped_column(
        Integer
    )

    original_content_hash: Mapped[str] = mapped_column(
        String(64)
    )

    observed_content_hash: Mapped[str] = mapped_column(
        String(64)
    )

    attack_type: Mapped[str] = mapped_column(
        String(128)
    )

    mutation_description: Mapped[str] = mapped_column(
        Text
    )

    attacker: Mapped[str] = mapped_column(
        String(128)
    )

    attack_time: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc)
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

    attack_start_time: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True
    )

    attack_end_time: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True
    )

    duration_ms: Mapped[float | None] = mapped_column(
        nullable=True
    )

    integrity_compromised: Mapped[bool] = mapped_column(
        Boolean,
        default=False
    )

    status: Mapped[str] = mapped_column(
        String(32),
        default="injected"
    )