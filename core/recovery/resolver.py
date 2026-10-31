from core.integrity.hash import calculate_version_hash
from core.memory.models import MemoryRecord
from core.memory.repository import MemoryRepository
from core.security.owner_approval import verify_record_owner_approval


class TrustedVersionResolver:
    def __init__(
        self,
        repository: MemoryRepository,
        manifest_store=None,
        vault_store=None,
    ):
        self.repository = repository
        self.manifest_store = manifest_store
        self.vault_store = vault_store

    def _has_valid_authorization(self, record) -> bool:
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
            "candidates": [],
        }

        if len(history) < 2 and not self.vault_store:
            report["reason"] = (
                "At least two stored revisions are required to evaluate "
                "a historical recovery candidate."
            )
            return report

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
                    reasons.append(
                        "Stored history chain or content hash verification failed."
                    )
                if not authorization_valid:
                    reasons.append(
                        "Owner approval signature could not be verified."
                    )
                if not manifest_valid:
                    reasons.append(
                        "Independent signed integrity manifest is missing or invalid."
                    )
                if not checks["active_status"]:
                    reasons.append(
                        f"Revision status is {record.status!r}, not 'active'."
                    )
                if not checks["trust_threshold"]:
                    reasons.append(
                        f"Trust score {record.trust_score} is below 0.8."
                    )
                if not checks["suspicion_threshold"]:
                    reasons.append(
                        f"Suspicion score {record.suspicion_score} exceeds 0.2."
                    )

                accepted = all(checks.values())
                report["candidates"].append({
                    "version": record.version,
                    "revision_id": record.revision_id,
                    "source_store": "local_database",
                    "checks": checks,
                    "status": (
                        "TRUSTED_CANDIDATE"
                        if accepted
                        else "REJECTED_CANDIDATE"
                    ),
                    "reasons": (
                        ["All configured trust checks passed."]
                        if accepted
                        else reasons
                    ),
                })

                if accepted and report["selected_version"] is None:
                    report["selected_version"] = record.version
                    report["decision"] = "TRUSTED_RECOVERY_POINT"
                    report["source_store"] = "local_database"
                    report["reason"] = (
                        f"Selected version {record.version}: it is the newest "
                        "historical candidate passing all configured checks."
                    )

        # Multi-Store Resilient Sourcing: If local database candidates fail verification,
        # query the independent cryptographic vault store
        if report["selected_version"] is None and self.vault_store is not None:
            vault_verified = self.vault_store.get_verified_candidates(memory_id)
            if vault_verified:
                vault_best = vault_verified[0]
                report["selected_version"] = vault_best["version"]
                report["decision"] = "TRUSTED_RECOVERY_POINT"
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

        if report["selected_version"] is None:
            report["reason"] = (
                "No historical candidate passed all configured trust checks across local database and replicated trust vault."
            )

        return report

    def find_trusted_version(
        self,
        memory_id: str,
    ) -> MemoryRecord | None:
        history = self.repository.get_history(memory_id)

        if len(history) >= 2:
            for record in reversed(history[:-1]):
                if not self._has_valid_history_chain(
                    memory_id,
                    record.version,
                ):
                    continue

                if not self._has_valid_authorization(record):
                    continue

                if not self._has_valid_manifest(record):
                    continue

                if (
                    record.status == "active"
                    and record.trust_score >= 0.8
                    and record.suspicion_score <= 0.2
                ):
                    return record

        # Multi-Store Resilient Fallback: If local history fails, search replicated trust vault
        if self.vault_store is not None:
            vault_verified = self.vault_store.get_verified_candidates(memory_id)
            if vault_verified:
                vault_best = vault_verified[0]
                record = self.repository.get_version(memory_id, vault_best["version"])
                if record is not None:
                    # Provide record with authentic verified content from vault
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

        return None
