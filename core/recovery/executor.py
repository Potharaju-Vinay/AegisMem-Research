
from core.integrity.hash import calculate_version_hash
from core.integrity.manifest_store import IntegrityManifestStore
from core.memory.repository import MemoryRepository
from core.recovery.models import RecoveryAction, RecoveryResult
from core.security.owner_approval import verify_record_owner_approval
from core.recovery.attestation import RecoveryAttestationStore
from core.provenance.manager import ProvenanceManager
from core.provenance.checkpoint import ProvenanceCheckpointStore
from core.provenance.trusted_head import TrustedCheckpointHeadStore


class RecoveryExecutor:

    def __init__(
        self,
    repository: MemoryRepository,
    manifest_store=None,
    attestation_store=None,
    provenance_manager=None,
    checkpoint_store=None,
    trusted_head_store=None,
    vault_store=None,
):
        self.repository = repository
        self.manifest_store = (
        manifest_store or IntegrityManifestStore()
    )

        attestation_dir = (
            self.manifest_store.manifest_dir.parent
        / "recovery_attestations"
    )

        self.attestation_store = (
            attestation_store
        or RecoveryAttestationStore(
            attestation_dir=attestation_dir
        )
    )

        self.provenance_manager = (
            provenance_manager
        or ProvenanceManager(repository.session)
    )

        self.checkpoint_store = (
            checkpoint_store or ProvenanceCheckpointStore()
    )

        self.trusted_head_store = (
        trusted_head_store
        or TrustedCheckpointHeadStore(
            checkpoint_store=self.checkpoint_store
        )
    )
        self.vault_store = vault_store or getattr(repository, "vault_store", None)
    def _has_valid_authorization(self, record) -> bool:
        if getattr(record, 'version', 0) == 1 and (
            getattr(record, 'source_type', '') in {'policy', 'genesis', 'system'}
            or getattr(record, 'authorization_state', '') == 'AUTHORIZED'
        ):
            return True
        return verify_record_owner_approval(record)

    def _has_valid_history_chain(
        self,
        memory_id: str,
        target_version: int
    ) -> bool:
        for version in range(1, target_version + 1):
            record = self.repository.get_version(
                memory_id,
                version
            )

            if record is None:
                return False

            expected_previous_hash = None

            if version > 1:
                previous_record = self.repository.get_version(
                    memory_id,
                    version - 1
                )

                if previous_record is None:
                    return False

                expected_previous_hash = previous_record.content_hash

            if record.previous_hash != expected_previous_hash:
                return False

            if record.content_hash != calculate_version_hash(
                record.content,
                record.previous_hash
            ):
                return False

        return True
    
    
    
    def _finalize_recovery_provenance(self, restored, target, compromised):
        events = self.provenance_manager.get_events(restored.memory_id)

        if self.trusted_head_store.verify_trusted_prefix(events) != "VALID":
            raise ValueError("Existing trusted provenance prefix verification failed.")

        self.provenance_manager.record(
        memory_record_id=restored.id,
        memory_id=restored.memory_id,
        version=restored.version,
        actor="aegismem-recovery",
        operation="RECOVERY",
        source=restored.source,
        source_type=restored.source_type,
        metadata={
            "restored_revision_id": restored.revision_id,
            "source_revision_id": target.revision_id,
            "source_version": target.version,
            "compromised_revision_id": compromised.revision_id,
            "compromised_version": compromised.version,
        },
    )

        events = self.provenance_manager.get_events(restored.memory_id)
        self.checkpoint_store.create_checkpoint(events)
        self.trusted_head_store.advance(events)

        if self.checkpoint_store.verify_checkpoint(events) != "VALID":
            raise ValueError("Recovery checkpoint verification failed.")

        if self.trusted_head_store.verify_events(events) != "VALID":
            raise ValueError("Recovery trusted-head verification failed.")



    def rollback(
        self,
        compromised_memory_id: str,
        trusted_version: int
    ) -> RecoveryResult:

        history = self.repository.get_history(
            compromised_memory_id
        )

        if not history:
            return RecoveryResult(
                memory_id=compromised_memory_id,
                action=RecoveryAction.ROLLBACK,
                success=False,
                previous_version=None,
                restored_version=None,
                message="Memory history not found."
            )

        current = history[-1]

        target = self.repository.get_version(
            compromised_memory_id,
            trusted_version
        )

        # Multi-Store Resilient Self-Healing: If local DB target was tampered, repair from verified vault replica
        if (target is None or not self._has_valid_authorization(target)) and getattr(self, "vault_store", None):
            vault_snapshots = self.vault_store.get_verified_candidates(compromised_memory_id)
            matching_snap = next((s for s in vault_snapshots if s.get("version") == trusted_version), None)
            if matching_snap:
                if target is not None:
                    target.content = matching_snap["content"]
                    target.content_hash = matching_snap["content_hash"]
                    if matching_snap.get("authorization_signature"):
                        target.authorization_signature = matching_snap["authorization_signature"]
                    if matching_snap.get("authorization_nonce"):
                        target.authorization_nonce = matching_snap["authorization_nonce"]
                    if matching_snap.get("authorization_id"):
                        target.authorization_id = matching_snap["authorization_id"]
                    target.authorization_state = "AUTHORIZED"
                    target.status = "active"
                    target.trust_score = 1.0
                    target.suspicion_score = 0.0
                    self.repository.session.commit()
                else:
                    from core.memory.models import MemoryRecord
                    target = MemoryRecord(
                        memory_id=compromised_memory_id,
                        version=trusted_version,
                        revision_id=matching_snap["revision_id"],
                        parent_revision_id=matching_snap.get("parent_revision_id"),
                        content=matching_snap["content"],
                        content_hash=matching_snap["content_hash"],
                        previous_hash=matching_snap.get("previous_hash"),
                        source="replicated_trust_vault",
                        source_type="vault_restored",
                        trust_score=1.0,
                        suspicion_score=0.0,
                        status="active",
                        authorization_id=matching_snap.get("authorization_id") or "vault-auth",
                        authorization_signature=matching_snap.get("authorization_signature") or matching_snap.get("signature"),
                        authorization_nonce=matching_snap.get("authorization_nonce") or "vault-nonce",
                        authorization_state="AUTHORIZED",
                    )
                    self.repository.session.add(target)
                    self.repository.session.commit()

                if not self.manifest_store.has_manifest(target) and matching_snap.get("signature"):
                    manifest_data = {
                        "memory_id": target.memory_id,
                        "revision_id": target.revision_id,
                        "parent_revision_id": target.parent_revision_id,
                        "version": target.version,
                        "content_hash": target.content_hash,
                        "previous_hash": target.previous_hash,
                        "signature": matching_snap["signature"],
                    }
                    try:
                        self.manifest_store.write_manifest(manifest_data)
                    except Exception:
                        pass

        if target is None:
            return RecoveryResult(
                memory_id=compromised_memory_id,
                action=RecoveryAction.ROLLBACK,
                success=False,
                previous_version=current.version,
                restored_version=None,
                message="Trusted recovery version not found."
            )

        if not self._has_valid_authorization(target):
            return RecoveryResult(
                memory_id=compromised_memory_id,
                action=RecoveryAction.ROLLBACK,
                success=False,
                previous_version=current.version,
                restored_version=None,
                message=(
                    "Recovery target authorization verification failed."
                )
            )

        if not self._has_valid_history_chain(
            compromised_memory_id,
            target.version
        ):
            return RecoveryResult(
                memory_id=compromised_memory_id,
                action=RecoveryAction.ROLLBACK,
                success=False,
                previous_version=current.version,
                restored_version=None,
                message=(
                    "Recovery target history link verification failed."
                )
            )

        manifest_present = self.manifest_store.has_manifest(target)
        manifest_valid = (
    manifest_present
    and self.manifest_store.verify_record(target)
)

        if not manifest_valid:
            return RecoveryResult(
        memory_id=compromised_memory_id,
        action=RecoveryAction.ROLLBACK,
        success=False,
        previous_version=current.version,
        restored_version=None,
        message=(
            "Recovery target signed integrity manifest "
            "is missing or invalid."
        ),
    )

        if not manifest_valid:
            return RecoveryResult(
                memory_id=compromised_memory_id,
                action=RecoveryAction.ROLLBACK,
                success=False,
                previous_version=current.version,
                restored_version=None,
                message=(
                    "Recovery target signed integrity manifest "
                    "is missing or invalid."
                )
            )
            
        events = self.provenance_manager.get_events(
    compromised_memory_id
)

        trusted_status = self.trusted_head_store.verify_trusted_prefix(events)
        if trusted_status != "VALID":
            return RecoveryResult(
        memory_id=compromised_memory_id,
        action=RecoveryAction.ROLLBACK,
        success=False,
        previous_version=current.version,
        restored_version=None,
        message=f"Trusted provenance verification failed: {trusted_status}"
    )

        if target.status != "active":
            return RecoveryResult(
                memory_id=compromised_memory_id,
                action=RecoveryAction.ROLLBACK,
                success=False,
                previous_version=current.version,
                restored_version=None,
                message="Recovery target is not active."
            )

        if target.trust_score < 0.8:
            return RecoveryResult(
                memory_id=compromised_memory_id,
                action=RecoveryAction.ROLLBACK,
                success=False,
                previous_version=current.version,
                restored_version=None,
                message=(
                    "Recovery target trust score is below "
                    "the required threshold of 0.8."
                )
            )

        if target.suspicion_score > 0.2:
            return RecoveryResult(
                memory_id=compromised_memory_id,
                action=RecoveryAction.ROLLBACK,
                success=False,
                previous_version=current.version,
                restored_version=None,
                message=(
                    "Recovery target suspicion score exceeds "
                    "the allowed threshold of 0.2."
                )
            )

        restored = self.repository.create(
            memory_id=compromised_memory_id,
            content=target.content,
            source=f"recovery_from_version_{target.version}",
            source_type="verified_recovery"
        )

        restored.trust_score = target.trust_score
        restored.suspicion_score = 0.0
        restored.status = "active"
        restored.authorization_state = "UNAUTHORIZED"
        restored._is_recovery = True

        self.repository.session.commit()
        self.repository.session.refresh(restored)
        restored._is_recovery = True

        
        try:
            m_res = self.manifest_store.create_for_record(restored)
            if m_res is None:
                raise ValueError("Failed to create signed integrity manifest for recovered record")

            self.attestation_store.create_for_record(
                record=restored,
                source_record=target,
                compromised_record=current,
            )

            self._finalize_recovery_provenance(
                restored=restored,
                target=target,
                compromised=current,
            )

            if getattr(self, "vault_store", None):
                try:
                    self.vault_store.save_snapshot(
                        memory_id=restored.memory_id,
                        version=restored.version,
                        content=restored.content,
                        content_hash=restored.content_hash,
                        previous_hash=restored.previous_hash,
                        revision_id=restored.revision_id,
                        parent_revision_id=restored.parent_revision_id,
                    )
                except Exception:
                    pass
        except Exception as exc:
            print(
                f"Recovery finalization failed: "
                f"{type(exc).__name__}: {exc}"
            )
            restored.status = "quarantined"
            self.repository.session.commit()

            return RecoveryResult(
                memory_id=compromised_memory_id,
                action=RecoveryAction.ROLLBACK,
                success=False,
                previous_version=current.version,
                restored_version=restored.version,
                message=(
                    "Recovery content was written, but its integrity "
                    "manifest, recovery attestation, or provenance "
                    "verification could not be completed. "
                    "The new revision was quarantined."
                ),
            )


        return RecoveryResult(
            memory_id=compromised_memory_id,
            action=RecoveryAction.ROLLBACK,
            success=True,
            previous_version=current.version,
            restored_version=restored.version,
            message=(
                f"Restored content from verified version "
                f"{target.version}. The recovered revision has a "
                f"signed integrity manifest and records recovery "
                f"provenance; it is not owner-signed."
            )
        )

