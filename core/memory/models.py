from datetime import datetime, timezone

from sqlalchemy import (
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text
)
from sqlalchemy.orm import Mapped, mapped_column

from core.memory.database import Base


class MemoryRecord(Base):

    __tablename__ = "memories"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True
    )

    memory_id: Mapped[str] = mapped_column(
        String(128),
        index=True
    )

    version: Mapped[int] = mapped_column(
        Integer
    )

    content: Mapped[str] = mapped_column(
        Text
    )

    source: Mapped[str] = mapped_column(
        String(512)
    )

    source_type: Mapped[str] = mapped_column(
        String(128)
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc)
    )

    previous_version_id: Mapped[int | None] = mapped_column(
        ForeignKey("memories.id"),
        nullable=True
    )

    content_hash: Mapped[str] = mapped_column(
        String(64)
    )

    previous_hash: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True
    )

    trust_score: Mapped[float] = mapped_column(
        Float,
        default=1.0
    )

    suspicion_score: Mapped[float] = mapped_column(
        Float,
        default=0.0
    )

    status: Mapped[str] = mapped_column(
        String(32),
        default="active"
    )