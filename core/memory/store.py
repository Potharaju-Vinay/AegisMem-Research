from __future__ import annotations

import json
import os
from abc import ABC, abstractmethod
from typing import Any, Callable
from uuid import uuid4

from sqlalchemy import create_engine, select, text
from sqlalchemy.orm import Session, sessionmaker

from core.integrity.hash import calculate_version_hash
from core.integrity.manifest_store import IntegrityManifestStore
from core.memory.database import Base, SessionLocal, get_database_url
from core.memory.models import MemoryRecord
from core.provenance.manager import ProvenanceManager
from core.security.authorization import verify_and_register_nonce
from core.security.owner_approval import verify_owner_approval


class MemoryStore(ABC):
    """
    Abstract storage adapter interface for persistent agent memories.
    Decouples AegisMem's security gate, TCRP planner, and watcher from specific database engines,
    enabling identical security enforcement across SQLite and PostgreSQL backends.
    """

    def __init__(self):
        self._change_hooks: list[Callable[[str, int], None]] = []

    def register_change_hook(self, callback: Callable[[str, int], None]) -> None:
        """Register a callback to be triggered when a memory version is created or modified."""
        if callback not in self._change_hooks:
            self._change_hooks.append(callback)

    def notify_change(self, memory_id: str, version: int) -> None:
        """Dispatch change notifications to all registered listeners."""
        for hook in self._change_hooks:
            try:
                hook(memory_id, version)
            except Exception as exc:
                print(f"[MemoryStore Hook Warning] Error executing change hook for '{memory_id}' v{version}: {exc}")

    @abstractmethod
    def create_version(
        self,
        memory_id: str,
        content: str,
        source: str = "system",
        source_type: str = "direct",
    ) -> MemoryRecord:
        """Create a new unauthenticated or system memory version."""
        pass

    @abstractmethod
    def create_owner_authorized(
        self,
        memory_id: str,
        content: str,
        source: str,
        authorization_id: str,
        nonce: str,
        authorization_signature: str,
        expected_revision_id: str | None = None,
        record_provenance: bool = False,
    ) -> MemoryRecord:
        """Create a cryptographically verified owner-authorized memory revision."""
        pass

    @abstractmethod
    def get_latest(self, memory_id: str) -> MemoryRecord | None:
        """Retrieve the newest revision for a given memory identifier."""
        pass

    @abstractmethod
    def get_version(self, memory_id: str, version: int) -> MemoryRecord | None:
        """Retrieve an exact version for a given memory identifier."""
        pass

    @abstractmethod
    def get_history(self, memory_id: str) -> list[MemoryRecord]:
        """Retrieve chronological history for a given memory identifier."""
        pass

    @abstractmethod
    def append_event(self, event_type: str, memory_id: str, payload: dict[str, Any] | None = None) -> None:
        """Record an outbox event / audit event for change notifications."""
        pass

    @abstractmethod
    def close(self) -> None:
        """Close store connections."""
        pass


class SQLiteMemoryStore(MemoryStore):
    """
    SQLite adapter implementation of MemoryStore.
    Preserves local embedded execution with in-process reconciliation hooks.
    """

    def __init__(
        self,
        session_factory=None,
        manifest_store: IntegrityManifestStore | None = None,
        vault_store=None,
    ):
        super().__init__()
        self.session_factory = session_factory or SessionLocal
        self.manifest_store = manifest_store or IntegrityManifestStore()
        self.vault_store = vault_store

    def _get_session(self) -> Session:
        return self.session_factory()

    def create_version(
        self,
        memory_id: str,
        content: str,
        source: str = "system",
        source_type: str = "direct",
    ) -> MemoryRecord:
        session = self._get_session()
        try:
            latest = session.scalars(
                select(MemoryRecord)
                .where(MemoryRecord.memory_id == memory_id)
                .order_by(MemoryRecord.version.desc())
            ).first()

            version = latest.version + 1 if latest else 1
            previous_id = latest.id if latest else None
            parent_rev = latest.revision_id if latest else None
            previous_hash = latest.content_hash if latest else None
            content_hash = calculate_version_hash(content, previous_hash)

            record = MemoryRecord(
                memory_id=memory_id,
                version=version,
                revision_id=str(uuid4()),
                parent_revision_id=parent_rev,
                content=content,
                source=source,
                source_type=source_type,
                previous_version_id=previous_id,
                content_hash=content_hash,
                previous_hash=previous_hash,
                trust_score=1.0,
                suspicion_score=0.0,
                status="active",
            )
            session.add(record)
            session.commit()
            session.refresh(record)

            self.notify_change(memory_id, version)
            return record
        finally:
            session.close()

    def create_owner_authorized(
        self,
        memory_id: str,
        content: str,
        source: str,
        authorization_id: str,
        nonce: str,
        authorization_signature: str,
        expected_revision_id: str | None = None,
        record_provenance: bool = False,
    ) -> MemoryRecord:
        session = self._get_session()
        manifest_path = None
        try:
            latest = session.scalars(
                select(MemoryRecord)
                .where(MemoryRecord.memory_id == memory_id)
                .order_by(MemoryRecord.version.desc())
            ).first()

            actual_parent_id = latest.revision_id if latest else None
            if expected_revision_id != actual_parent_id:
                raise ValueError("Stale or missing expected revision authorization")

            if not verify_owner_approval(
                memory_id=memory_id,
                content=content,
                expected_parent_revision_id=expected_revision_id,
                authorization_id=authorization_id,
                nonce=nonce,
                signature_hex=authorization_signature,
            ):
                raise ValueError("Owner approval signature verification failed")

            # Ensure authorization_nonces table exists for isolated databases
            try:
                session.execute(
                    text("""
                        CREATE TABLE IF NOT EXISTS authorization_nonces (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            nonce TEXT NOT NULL UNIQUE,
                            authorization_id TEXT NOT NULL,
                            created_at TIMESTAMP NOT NULL
                        )
                    """)
                )
                session.commit()
            except Exception:
                session.rollback()

            if not verify_and_register_nonce(nonce, authorization_id, session=session):
                raise ValueError("Authorization nonce already used")

            version = latest.version + 1 if latest else 1
            previous_id = latest.id if latest else None
            previous_hash = latest.content_hash if latest else None
            content_hash = calculate_version_hash(content, previous_hash)

            record = MemoryRecord(
                memory_id=memory_id,
                version=version,
                revision_id=str(uuid4()),
                parent_revision_id=actual_parent_id,
                content=content,
                source=source,
                source_type="owner_authorized",
                previous_version_id=previous_id,
                content_hash=content_hash,
                previous_hash=previous_hash,
                trust_score=1.0,
                suspicion_score=0.0,
                status="active",
                authorization_id=authorization_id,
                authorization_signature=authorization_signature,
                authorization_nonce=nonce,
                authorization_state="AUTHORIZED",
            )
            session.add(record)
            session.flush()

            self.manifest_store.create_for_record(record)
            manifest_path = self.manifest_store._path(record.memory_id, record.version)

            if self.vault_store:
                try:
                    self.vault_store.save_snapshot(
                        memory_id=record.memory_id,
                        version=record.version,
                        content=record.content,
                        content_hash=record.content_hash,
                        previous_hash=record.previous_hash,
                        revision_id=record.revision_id,
                        parent_revision_id=record.parent_revision_id,
                        authorization_signature=record.authorization_signature,
                        authorization_id=record.authorization_id,
                        authorization_nonce=record.authorization_nonce,
                    )
                except Exception:
                    pass

            if record_provenance:
                ProvenanceManager(session).record(
                    memory_record_id=record.id,
                    memory_id=record.memory_id,
                    version=record.version,
                    actor="enterprise_owner",
                    operation="MEMORY_WRITE",
                    source=record.source,
                    source_type=record.source_type,
                    metadata={
                        "authorization_id": record.authorization_id,
                        "revision_id": record.revision_id,
                        "authorization_state": record.authorization_state,
                    },
                    commit=False,
                )

            session.commit()
            session.refresh(record)

            self.notify_change(memory_id, version)
            return record

        except Exception:
            session.rollback()
            if manifest_path is not None:
                try:
                    manifest_path.unlink(missing_ok=True)
                except OSError:
                    pass
            raise
        finally:
            session.close()

    def get_latest(self, memory_id: str) -> MemoryRecord | None:
        session = self._get_session()
        try:
            return session.scalars(
                select(MemoryRecord)
                .where(MemoryRecord.memory_id == memory_id)
                .order_by(MemoryRecord.version.desc())
            ).first()
        finally:
            session.close()

    def get_version(self, memory_id: str, version: int) -> MemoryRecord | None:
        session = self._get_session()
        try:
            return session.scalars(
                select(MemoryRecord)
                .where(MemoryRecord.memory_id == memory_id, MemoryRecord.version == version)
            ).first()
        finally:
            session.close()

    def get_history(self, memory_id: str) -> list[MemoryRecord]:
        session = self._get_session()
        try:
            return list(
                session.scalars(
                    select(MemoryRecord)
                    .where(MemoryRecord.memory_id == memory_id)
                    .order_by(MemoryRecord.version.asc())
                ).all()
            )
        finally:
            session.close()

    def append_event(self, event_type: str, memory_id: str, payload: dict[str, Any] | None = None) -> None:
        latest = self.get_latest(memory_id)
        version = latest.version if latest else 0
        self.notify_change(memory_id, version)

    def close(self) -> None:
        pass


class PostgreSQLMemoryStore(SQLiteMemoryStore):
    """
    PostgreSQL adapter implementation of MemoryStore.
    Supports asynchronous LISTEN/NOTIFY and outbox write-triggers for event-driven detection.
    """

    def __init__(
        self,
        db_url: str | None = None,
        manifest_store: IntegrityManifestStore | None = None,
        vault_store=None,
    ):
        self.db_url = db_url or os.getenv(
            "AEGISMEM_PG_URL",
            os.getenv("DATABASE_URL", "postgresql+psycopg2://aegis:aegis_secret@localhost:5432/aegismem"),
        )
        try:
            self.engine = create_engine(self.db_url, pool_pre_ping=True)
            session_factory = sessionmaker(bind=self.engine, autoflush=False, autocommit=False)
        except Exception:
            self.engine = None
            session_factory = SessionLocal

        super().__init__(
            session_factory=session_factory,
            manifest_store=manifest_store,
            vault_store=vault_store,
        )

    def append_event(self, event_type: str, memory_id: str, payload: dict[str, Any] | None = None) -> None:
        session = self._get_session()
        try:
            channel_payload = json.dumps({
                "event_type": event_type,
                "memory_id": memory_id,
                "payload": payload or {},
            })
            # Dispatch native PostgreSQL LISTEN/NOTIFY
            session.execute(
                text("SELECT pg_notify('aegismem_memory_changes', :payload)"),
                {"payload": channel_payload},
            )
            session.commit()
        except Exception as exc:
            session.rollback()
            # If PostgreSQL is not active or notifications fail, fallback to parent notification
            pass
        finally:
            session.close()

        latest = self.get_latest(memory_id)
        version = latest.version if latest else 0
        self.notify_change(memory_id, version)

    def close(self) -> None:
        try:
            self.engine.dispose()
        except Exception:
            pass


def get_memory_store(
    backend: str | None = None,
    db_url: str | None = None,
    vault_store=None,
) -> MemoryStore:
    """
    Storage adapter factory.
    Selects SQLite or PostgreSQL implementation based on configuration.
    """
    selected_backend = (backend or os.getenv("AEGISMEM_STORAGE_BACKEND", "sqlite")).lower().strip()

    if selected_backend in ("postgresql", "postgres", "pg"):
        return PostgreSQLMemoryStore(db_url=db_url, vault_store=vault_store)

    return SQLiteMemoryStore(vault_store=vault_store)
