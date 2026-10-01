from datetime import datetime, timezone

from sqlalchemy import DateTime, Float, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from core.memory.database import Base


class RecoveryEvent(Base):
    __tablename__ = "recovery_events"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True
    )

    memory_id: Mapped[str] = mapped_column(
        String(128),
        index=True
    )

    event_type: Mapped[str] = mapped_column(
        String(64),
        index=True
    )

    action: Mapped[str] = mapped_column(
        String(32)
    )

    message: Mapped[str] = mapped_column(
        Text
    )

    status: Mapped[str] = mapped_column(
        String(32)
    )

    compromised_version: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True
    )

    restored_version: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True
    )

    trust_score: Mapped[float | None] = mapped_column(
        Float,
        nullable=True
    )

    suspicion_score: Mapped[float | None] = mapped_column(
        Float,
        nullable=True
    )

    validation_result: Mapped[str | None] = mapped_column(
        String(32),
        nullable=True
    )

    impact_score: Mapped[float | None] = mapped_column(
        Float,
        nullable=True
    )

    dependency_exposure: Mapped[float | None] = mapped_column(
        Float,
        nullable=True
    )

    selected_action_cost: Mapped[float | None] = mapped_column(
        Float,
        nullable=True
    )

    candidate_costs: Mapped[str | None] = mapped_column(
        Text,
        nullable=True
    )

    feasible_actions: Mapped[str | None] = mapped_column(
    Text,
    nullable=True
)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        index=True
    )