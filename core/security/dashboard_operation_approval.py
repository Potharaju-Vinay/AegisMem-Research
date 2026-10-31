from datetime import datetime, timezone

from sqlalchemy import DateTime, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from core.memory.database import Base


class DashboardOperationApproval(Base):
    __tablename__ = "dashboard_operation_approvals"

    authorization_id: Mapped[str] = mapped_column(
        String(64),
        primary_key=True,
    )

    session_ref: Mapped[str] = mapped_column(
        String(64),
        index=True,
        nullable=False,
    )

    operation: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )

    memory_id: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
    )

    consumed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    status: Mapped[str] = mapped_column(
        String(32),
        default="APPROVED",
        nullable=False,
    )