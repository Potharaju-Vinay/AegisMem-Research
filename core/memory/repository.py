from sqlalchemy import select
from sqlalchemy.orm import Session
from uuid import uuid4

from core.integrity.hash import calculate_version_hash
from core.memory.models import MemoryRecord
from core.security.authorization import verify_and_register_nonce
from core.security.owner_approval import verify_owner_approval
from core.integrity.manifest_store import IntegrityManifestStore
from core.provenance.manager import ProvenanceManager

class MemoryRepository:

    def __init__(
        self,
        session: Session,
        manifest_store: IntegrityManifestStore | None = None,
        vault_store=None,
    ):
        self.session = session
        self.manifest_store = manifest_store or IntegrityManifestStore()
        self.vault_store = vault_store

    def create(
        self,
        memory_id: str,
        content: str,
        source: str,
        source_type: str
    ) -> MemoryRecord:

        existing = self.get_latest(memory_id)

        version = 1
        previous_id = None
        parent_revision_id = None
        previous_hash = None

        if existing:
            version = existing.version + 1
            previous_id = existing.id
            parent_revision_id = existing.revision_id
            previous_hash = existing.content_hash

        content_hash = calculate_version_hash(
            content,
            previous_hash
        )

        record = MemoryRecord(
            memory_id=memory_id,
            version=version,
            revision_id=str(uuid4()),
            parent_revision_id=parent_revision_id,
            content=content,
            source=source,
            source_type=source_type,
            previous_version_id=previous_id,
            content_hash=content_hash,
            previous_hash=previous_hash,
            trust_score=1.0,
            suspicion_score=0.0,
            status="active"
        )

        self.session.add(record)
        self.session.commit()
        self.session.refresh(record)

        return record

    
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
        existing = self.get_latest(memory_id)

        actual_parent_revision_id = (
            existing.revision_id if existing else None
        )

        if expected_revision_id != actual_parent_revision_id:
            raise ValueError(
                "Stale or missing expected revision authorization"
            )

        if not verify_owner_approval(
            memory_id=memory_id,
            content=content,
            expected_parent_revision_id=expected_revision_id,
            authorization_id=authorization_id,
            nonce=nonce,
            signature_hex=authorization_signature,
        ):
            raise ValueError("Owner approval signature verification failed")

        version = existing.version + 1 if existing else 1
        previous_id = existing.id if existing else None
        previous_hash = existing.content_hash if existing else None

        content_hash = calculate_version_hash(content, previous_hash)

        record = MemoryRecord(
            memory_id=memory_id,
            version=version,
            revision_id=str(uuid4()),
            parent_revision_id=actual_parent_revision_id,
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
        
        manifest_path = None

        try:
            if not verify_and_register_nonce(
                nonce,
                authorization_id,
                session=self.session,
            ):
                raise ValueError("Authorization nonce already used")

            self.session.add(record)
            self.session.flush()

            self.manifest_store.create_for_record(record)
            manifest_path = self.manifest_store._path(
                record.memory_id, record.version
            )

            if getattr(self, "vault_store", None):
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
                    )
                except Exception:
                    pass

            if record_provenance:
                ProvenanceManager(self.session).record(
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

            self.session.commit()
            self.session.refresh(record)
            return record

        except Exception:
            self.session.rollback()

            if manifest_path is not None:
                try:
                    manifest_path.unlink(missing_ok=True)
                except OSError:
                    pass

            raise

    def get_latest(
        self,
        memory_id: str
    ) -> MemoryRecord | None:

        statement = (
            select(MemoryRecord)
            .where(MemoryRecord.memory_id == memory_id)
            .order_by(MemoryRecord.version.desc())
        )

        return self.session.scalars(statement).first()

    def get_version(
        self,
        memory_id: str,
        version: int
    ) -> MemoryRecord | None:

        statement = (
            select(MemoryRecord)
            .where(
                MemoryRecord.memory_id == memory_id,
                MemoryRecord.version == version
            )
        )

        return self.session.scalars(statement).first()

    def get_history(
        self,
        memory_id: str
    ) -> list[MemoryRecord]:

        statement = (
            select(MemoryRecord)
            .where(MemoryRecord.memory_id == memory_id)
            .order_by(MemoryRecord.version.asc())
        )

        return list(self.session.scalars(statement).all())

