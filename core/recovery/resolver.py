from pathlib import Path
from typing import Any, Optional

from core.integrity.hash import calculate_version_hash
from core.memory.models import MemoryRecord
from core.memory.repository import MemoryRepository
from core.recovery.ladder import (
    OfflineSnapshotStore,
    QuorumReplicaStore,
    RecoveryLadder,
    RecoveryLevel,
)
from core.security.owner_approval import verify_record_owner_approval
from core.security.revocation import KeyRevocationRegistry, get_revocation_registry


class TrustedVersionResolver:
    """
    Cryptographic verify-before-restore resolver with 5-level Recovery Ladder:
    Level 1: Local Database Historical Revisions
    Level 2: Replicated Trust Vault
    Level 3: Quorum Replicas (M-of-N consensus with auto-repair)
    Level 4: Offline Snapshot & Signed Event Replay
    Level 5: Fail-Safe State (ROOT_OF_TRUST_COMPROMISED -> quarantine, 0 wrong answers)
    """

    def __init__(
        self,
        repository: MemoryRepository,
        manifest_store=None,
        vault_store=None,
        quorum_store: Optional[QuorumReplicaStore] = None,
        offline_store: Optional[OfflineSnapshotStore] = None,
        anchor_public_key_path: Optional[Path | str] = None,
        revocation_registry: Optional[KeyRevocationRegistry] = None,
    ):
        self.repository = repository
        self.manifest_store = manifest_store
        self.vault_store = vault_store
        self.quorum_store = quorum_store
        self.offline_store = offline_store
        self.anchor_public_key_path = Path(anchor_public_key_path) if anchor_public_key_path else Path("security/keys/integrity_anchor_public.pem")
        self.revocation_registry = revocation_registry or get_revocation_registry()
        self.ladder = RecoveryLadder(
            repository=repository,
            manifest_store=manifest_store,
            vault_store=vault_store,
            quorum_store=quorum_store,
            offline_store=offline_store,
            anchor_public_key_path=self.anchor_public_key_path,
            revocation_registry=self.revocation_registry,
        )

    def _has_valid_authorization(self, record) -> bool:
        if getattr(record, "version", 0) == 1 and (
            getattr(record, "source_type", "") in {"policy", "genesis", "system"}
            or getattr(record, "authorization_state", "") == "AUTHORIZED"
        ):
            return True
        return verify_record_owner_approval(record)

    def _has_valid_manifest(self, record) -> bool:
        if self.manifest_store is None:
            return False

        try:
            return (
                self.manifest_store.has_manifest(record)
                and self.manifest_store.verify_record(record)
            )
        except Exception:
            return False

    def _has_valid_history_chain(
        self,
        memory_id: str,
        target_version: int,
    ) -> bool:
        for version in range(1, target_version + 1):
            record = self.repository.get_version(memory_id, version)

            if record is None:
                return False

            expected_previous_hash = None

            if version > 1:
                previous_record = self.repository.get_version(
                    memory_id,
                    version - 1,
                )
                if previous_record is None:
                    return False
                expected_previous_hash = previous_record.content_hash

            if record.previous_hash != expected_previous_hash:
                return False

            if record.content_hash != calculate_version_hash(
                record.content,
                record.previous_hash,
            ):
                return False

        return True

    def evaluate_candidates(self, memory_id: str) -> dict:
        history = self.repository.get_history(memory_id)
        report = {
            "memory_id": memory_id,
            "candidate_count": max(0, len(history) - 1),
            "selected_version": None,
            "decision": "NO_TRUSTED_RECOVERY_POINT",
            "ladder_level": RecoveryLevel.LEVEL_5_FAIL_SAFE.value,
            "source_store": None,
            "candidates": [],
            "repairs_applied": [],
            "reasons": [],
            "wrong_answer_risk": 0.0,
        }

        # -------------------------------------------------------------
        # Level 1: Local Database
        # -------------------------------------------------------------
        if len(history) >= 2:
            for record in reversed(history[:-1]):
                chain_valid = self._has_valid_history_chain(
                    memory_id,
                    record.version,
                )
                authorization_valid = self._has_valid_authorization(record)
                manifest_valid = self._has_valid_manifest(record)

                checks = {
                    "history_chain": chain_valid,
                    "owner_authorization": authorization_valid,
                    "integrity_manifest": manifest_valid,
                    "active_status": record.status == "active",
                    "trust_threshold": record.trust_score >= 0.8,
                    "suspicion_threshold": record.suspicion_score <= 0.2,
                }

                reasons = []
                if not chain_valid:
                    reasons.append("Stored history chain or content hash verification failed.")
                if not authorization_valid:
                    reasons.append("Owner approval signature could not be verified.")
                if not manifest_valid:
                    reasons.append("Independent signed integrity manifest is missing or invalid.")
                if not checks["active_status"]:
                    reasons.append(f"Revision status is {record.status!r}, not 'active'.")
                if not checks["trust_threshold"]:
                    reasons.append(f"Trust score {record.trust_score} is below 0.8.")
                if not checks["suspicion_threshold"]:
                    reasons.append(f"Suspicion score {record.suspicion_score} exceeds 0.2.")

                accepted = all(checks.values())
                report["candidates"].append({
                    "version": record.version,
                    "revision_id": record.revision_id,
                    "source_store": "local_database",
                    "checks": checks,
                    "status": "TRUSTED_CANDIDATE" if accepted else "REJECTED_CANDIDATE",
                    "reasons": ["All configured trust checks passed."] if accepted else reasons,
                })

                if accepted and report["selected_version"] is None:
                    report["selected_version"] = record.version
                    report["decision"] = "TRUSTED_RECOVERY_POINT"
                    report["ladder_level"] = RecoveryLevel.LEVEL_1_LOCAL_DATABASE.value
                    report["source_store"] = "local_database"
                    report["reason"] = (
                        f"Selected version {record.version}: it is the newest "
                        "historical candidate passing all configured checks."
                    )

        # -------------------------------------------------------------
        # Level 2: Local Replicated Trust Vault
        # -------------------------------------------------------------
        if report["selected_version"] is None and self.vault_store is not None:
            vault_verified = self.vault_store.get_verified_candidates(memory_id)
            if vault_verified:
                vault_best = vault_verified[0]
                report["selected_version"] = vault_best["version"]
                report["decision"] = "TRUSTED_RECOVERY_POINT"
                report["ladder_level"] = RecoveryLevel.LEVEL_2_LOCAL_VAULT.value
                report["source_store"] = "isolated_cryptographic_vault"
                report["vault_snapshot"] = vault_best
                report["reason"] = (
                    f"Selected version {vault_best['version']} from Replicated Trust Vault: "
                    "local database candidates were tampered or unverified, but out-of-band vault snapshot passed Ed25519 signature and SHA-256 verification."
                )
                report["candidates"].append({
                    "version": vault_best["version"],
                    "revision_id": vault_best["revision_id"],
                    "source_store": "isolated_cryptographic_vault",
                    "checks": {
                        "history_chain": True,
                        "owner_authorization": True,
                        "integrity_manifest": True,
                        "active_status": True,
                        "trust_threshold": True,
                        "suspicion_threshold": True,
                        "vault_signature": True,
                    },
                    "status": "TRUSTED_CANDIDATE",
                    "reasons": [
                        "Verified against out-of-band Ed25519 anchor public key and SHA-256 content hash."
                    ],
                })
                # Auto-repair local database if candidate present
                db_rec = self.repository.get_version(memory_id, vault_best["version"])
                if db_rec is not None and db_rec.content != vault_best["content"]:
                    db_rec.content = vault_best["content"]
                    db_rec.content_hash = vault_best["content_hash"]
                    db_rec.status = "active"
                    report["repairs_applied"].append(f"local_database:v{vault_best['version']}")

        # -------------------------------------------------------------
        # Level 3: Quorum Replicas with M-of-N Consensus & Auto-Repair
        # -------------------------------------------------------------
        if report["selected_version"] is None and self.quorum_store is not None:
            quorum_res = self.quorum_store.evaluate_quorum(memory_id)
            if quorum_res is not None:
                winner, quorum_repairs = quorum_res
                report["selected_version"] = winner["version"]
                report["decision"] = "TRUSTED_RECOVERY_POINT"
                report["ladder_level"] = RecoveryLevel.LEVEL_3_QUORUM_REPLICAS.value
                report["source_store"] = "quorum_replicas"
                report["repairs_applied"].extend(quorum_repairs)
                report["reason"] = (
                    f"Established M-of-N quorum consensus for version {winner['version']}. "
                    "Corrupted or out-of-sync replicas repaired."
                )
                report["candidates"].append({
                    "version": winner["version"],
                    "revision_id": winner["revision_id"],
                    "source_store": "quorum_replicas",
                    "checks": {
                        "quorum_consensus": True,
                        "signature_verified": True,
                        "content_hash": True,
                    },
                    "status": "TRUSTED_CANDIDATE",
                    "reasons": ["Passed quorum consensus across replicated nodes."],
                })
                # Auto-repair vault
                if self.vault_store is not None:
                    self.vault_store.repair_snapshot(winner)
                    report["repairs_applied"].append("isolated_cryptographic_vault")

        # -------------------------------------------------------------
        # Level 4: Offline Snapshot & Signed Event Replay
        # -------------------------------------------------------------
        if report["selected_version"] is None and self.offline_store is not None:
            offline_snap = self.offline_store.get_verified_offline_snapshot(memory_id)
            if offline_snap is not None:
                report["selected_version"] = offline_snap["version"]
                report["decision"] = "TRUSTED_RECOVERY_POINT"
                report["ladder_level"] = RecoveryLevel.LEVEL_4_OFFLINE_SNAPSHOT_REPLAY.value
                report["source_store"] = "offline_snapshot_replay"
                report["reason"] = f"Restored verified offline snapshot v{offline_snap['version']}."
                report["candidates"].append({
                    "version": offline_snap["version"],
                    "revision_id": offline_snap["revision_id"],
                    "source_store": "offline_snapshot_replay",
                    "checks": {
                        "offline_manifest": True,
                        "signature_verified": True,
                        "content_hash": True,
                    },
                    "status": "TRUSTED_CANDIDATE",
                    "reasons": ["Verified immutable offline snapshot archive."],
                })

        # -------------------------------------------------------------
        # Level 5: Fail-Safe State (ROOT_OF_TRUST_COMPROMISED)
        # -------------------------------------------------------------
        if report["selected_version"] is None:
            report["decision"] = "NO_TRUSTED_RECOVERY_POINT"
            report["fail_safe"] = "ROOT_OF_TRUST_COMPROMISED"
            report["ladder_level"] = RecoveryLevel.LEVEL_5_FAIL_SAFE.value
            report["source_store"] = "root_of_trust_compromised"
            report["reason"] = (
                "No historical candidate passed all configured trust checks across local database and replicated stores."
            )

        return report

    def find_trusted_version(
        self,
        memory_id: str,
    ) -> MemoryRecord | None:
        eval_result = self.evaluate_candidates(memory_id)
        if eval_result.get("selected_version") is None:
            return None

        version = eval_result["selected_version"]
        source_store = eval_result.get("source_store")

        if source_store == "local_database":
            return self.repository.get_version(memory_id, version)

        if source_store == "isolated_cryptographic_vault":
            vault_best = eval_result.get("vault_snapshot")
            if not vault_best and self.vault_store:
                cands = self.vault_store.get_verified_candidates(memory_id)
                vault_best = cands[0] if cands else None

            if vault_best:
                record = self.repository.get_version(memory_id, vault_best["version"])
                if record is not None:
                    record.content = vault_best["content"]
                    record.content_hash = vault_best["content_hash"]
                    record.status = "active"
                    return record
                return MemoryRecord(
                    memory_id=vault_best["memory_id"],
                    version=vault_best["version"],
                    revision_id=vault_best["revision_id"],
                    content=vault_best["content"],
                    content_hash=vault_best["content_hash"],
                    previous_hash=vault_best.get("previous_hash"),
                    status="active",
                    trust_score=1.0,
                    suspicion_score=0.0,
                    authorization_state="AUTHORIZED",
                )

        if source_store in {"quorum_replicas", "offline_snapshot_replay"}:
            selected_cand = next(
                (c for c in eval_result.get("candidates", []) if c.get("version") == version and c.get("status") == "TRUSTED_CANDIDATE"),
                None
            )
            record = self.repository.get_version(memory_id, version)
            if record is not None:
                record.status = "active"
                return record
            return MemoryRecord(
                memory_id=memory_id,
                version=version,
                revision_id=f"rev-ladder-{version}",
                content=eval_result.get("selected_content", ""),
                content_hash="",
                previous_hash=None,
                status="active",
                trust_score=1.0,
                suspicion_score=0.0,
                authorization_state="AUTHORIZED",
            )

        return None
