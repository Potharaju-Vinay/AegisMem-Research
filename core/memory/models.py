from datetime import datetime, timezone
from uuid import uuid4

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
    
    revision_id: Mapped[str] = mapped_column(
    String(36),
    unique=True,
    index=True,
    default=lambda: str(uuid4())
)
    parent_revision_id: Mapped[str | None] = mapped_column(
    String(36),
    nullable=True,
    index=True
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
    
    authorization_id: Mapped[str | None] = mapped_column(
        String(128),
        nullable=True,
        index=True
    )

    authorization_signature: Mapped[str | None] = mapped_column(
        Text,
        nullable=True
    )

    authorization_nonce: Mapped[str | None] = mapped_column(
        String(128),
        nullable=True,
        unique=True,
        index=True
    )

    authorization_state: Mapped[str] = mapped_column(
        String(32),
        default="UNAUTHORIZED"
    )

    status: Mapped[str] = mapped_column(
        String(32),
        default="active"
    )


class AuthorizationEvent(Base):
    __tablename__ = "authorization_events"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True
    )

    correlation_id: Mapped[str] = mapped_column(
        String(64),
        unique=True,
        index=True
    )

    memory_id: Mapped[str | None] = mapped_column(
        String(128),
        nullable=True,
        index=True
    )

    operation: Mapped[str] = mapped_column(
        String(32),
        default="OWNER_UPDATE"
    )

    outcome: Mapped[str] = mapped_column(
        String(32)
    )

    reason_code: Mapped[str] = mapped_column(
        String(64),
        index=True
    )

    client_ip: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True
    )

    client_port: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True
    )

    nonce: Mapped[str | None] = mapped_column(
        String(128),
        nullable=True
    )

    timestamp_val: Mapped[float | None] = mapped_column(
        Float,
        nullable=True
    )

    expected_version: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True
    )

    observed_version: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True
    )

    error_detail: Mapped[str | None] = mapped_column(
        Text,
        nullable=True
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc)
    )

    def to_dict(self):
        return {
            "id": self.id,
            "correlation_id": self.correlation_id,
            "memory_id": self.memory_id,
            "operation": self.operation,
            "outcome": self.outcome,
            "reason_code": self.reason_code,
            "client_ip": self.client_ip,
            "client_port": self.client_port,
            "nonce": self.nonce,
            "timestamp_val": self.timestamp_val,
            "expected_version": self.expected_version,
            "observed_version": self.observed_version,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class AuthorizationNonce(Base):
    __tablename__ = "authorization_nonces"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True
    )

    nonce: Mapped[str] = mapped_column(
        String(128),
        unique=True,
        index=True,
        nullable=False
    )

    authorization_id: Mapped[str] = mapped_column(
        String(128),
        nullable=False
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc)
    )

