from datetime import datetime, timezone

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from core.memory.database import Base


class MemoryDependency(Base):

    __tablename__ = "memory_dependencies"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True
    )

    source_memory_id: Mapped[str] = mapped_column(
        String(128),
        index=True
    )

    target_memory_id: Mapped[str] = mapped_column(
        String(128),
        index=True
    )

    dependency_type: Mapped[str] = mapped_column(
        String(64)
    )

    strength: Mapped[float] = mapped_column(
        Float,
        default=1.0
    )

    valid_from: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        index=True
    )

    valid_until: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        index=True
    )

    observed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        index=True
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc)
    )

    source_record_id: Mapped[int | None] = mapped_column(
        ForeignKey("memories.id"),
        nullable=True
    )

    target_record_id: Mapped[int | None] = mapped_column(
        ForeignKey("memories.id"),
        nullable=True
    )
