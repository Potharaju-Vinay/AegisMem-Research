import base64
import json
import hashlib
from pathlib import Path
from typing import Any, Optional
from core.integrity.anchor import verify_revision, sign_revision
from core.integrity.hash import calculate_version_hash
from core.security.revocation import KeyRevocationRegistry, get_revocation_registry


class ReplicatedTrustVault:
    """
    Independent, append-only out-of-band cryptographic trust vault.
    Stores cryptographically signed memory snapshots across separate trust domains,
    enabling provable self-healing even if primary database historical records are tampered.
    """

    def __init__(
        self,
        vault_dir: str | Path = "security/trust_vault",
        public_key_path: str | Path = "security/keys/integrity_anchor_public.pem",
        private_key_path: str | Path = "security/keys/integrity_anchor_private.pem",
        vault_token: Optional[str] = None,
        revocation_registry: Optional[KeyRevocationRegistry] = None,
    ):
        self.vault_dir = Path(vault_dir)
        self.public_key_path = Path(public_key_path)
        self.private_key_path = Path(private_key_path)
        self.vault_token = vault_token
        self.revocation_registry = revocation_registry

    def _safe_id(self, memory_id: str) -> str:
        return hashlib.sha256(memory_id.encode("utf-8")).hexdigest()

    def _snapshot_path(self, memory_id: str, version: int) -> Path:
        safe_id = self._safe_id(memory_id)
        return self.vault_dir / f"{safe_id}.v{version}.vault.json"

    def save_snapshot(
        self,
        memory_id: str,
        version: int,
        content: str,
        content_hash: str,
        previous_hash: str | None,
        revision_id: str,
        parent_revision_id: str | None = None,
        authorization_signature: str | None = None,
        authorization_id: str | None = None,
        authorization_nonce: str | None = None,
        manifest_signature: str | None = None,
        provided_token: Optional[str] = None,
    ) -> Path:
        """
        Append-only snapshot storage with credential separation and integrity enforcement.
        """
        if self.vault_token and provided_token != self.vault_token:
            raise PermissionError("Invalid vault authorization token: access denied")

        self.vault_dir.mkdir(parents=True, exist_ok=True)
        path = self._snapshot_path(memory_id, version)

        # Append-only check: prevent overwriting verified snapshots with conflicting content
        if path.exists():
            try:
                existing = json.loads(path.read_text(encoding="utf-8"))
                if existing.get("content_hash") != content_hash:
                    raise PermissionError(
                        f"Append-only vault conflict: Version {version} for {memory_id} already exists with different content hash"
                    )
            except PermissionError:
                raise
            except Exception:
                pass

        signature = manifest_signature
        if not signature:
            safe_id = hashlib.sha256(memory_id.encode("utf-8")).hexdigest()
            manifest_file = Path("security/integrity_manifests") / f"{safe_id}.{version}.json"
            if manifest_file.exists():
                try:
                    m_data = json.loads(manifest_file.read_text(encoding="utf-8"))
                    signature = m_data.get("signature")
                except Exception:
                    pass

        if not signature and self.private_key_path.exists():
            signed_manifest = sign_revision(
                memory_id=memory_id,
                version=version,
                content_hash=content_hash,
                previous_hash=previous_hash,
                private_key_path=self.private_key_path,
                revision_id=revision_id,
                parent_revision_id=parent_revision_id,
            )
            signature = signed_manifest.get("signature")

        snapshot = {
            "store_domain": "isolated_cryptographic_vault",
            "memory_id": memory_id,
            "version": version,
            "revision_id": revision_id,
            "parent_revision_id": parent_revision_id,
            "content": content,
            "content_hash": content_hash,
            "previous_hash": previous_hash,
            "signature": signature,
            "authorization_signature": authorization_signature,
            "authorization_id": authorization_id,
            "authorization_nonce": authorization_nonce,
        }

        temp_path = path.with_suffix(".tmp")
        temp_path.write_text(json.dumps(snapshot, indent=2), encoding="utf-8")
        temp_path.replace(path)
        return path

    def get_candidates(self, memory_id: str) -> list[dict[str, Any]]:
        if not self.vault_dir.exists():
            return []

        safe_id = self._safe_id(memory_id)
        candidates = []
        for file_path in self.vault_dir.glob(f"{safe_id}.v*.vault.json"):
            try:
                data = json.loads(file_path.read_text(encoding="utf-8"))
                if data.get("memory_id") == memory_id:
                    candidates.append(data)
            except Exception:
                continue

        candidates.sort(key=lambda c: int(c.get("version", 0)), reverse=True)
        return candidates

    def verify_snapshot(self, snapshot: dict[str, Any]) -> bool:
        """
        Cryptographically verifies the vault snapshot:
        1. Confirms SHA-256 hash matches the stored content and previous hash.
        2. Validates the Ed25519 signature against the anchor public key.
        3. Validates that the signing key is not revoked in the revocation registry.
        """
        try:
            content = snapshot.get("content", "")
            content_hash = snapshot.get("content_hash", "")
            previous_hash = snapshot.get("previous_hash")

            expected_hash = calculate_version_hash(content, previous_hash)
            if content_hash != expected_hash:
                return False

            manifest = {
                "memory_id": snapshot["memory_id"],
                "revision_id": snapshot["revision_id"],
                "parent_revision_id": snapshot.get("parent_revision_id"),
                "version": snapshot["version"],
                "content_hash": content_hash,
                "previous_hash": previous_hash,
                "signature": snapshot.get("signature"),
            }

            if not manifest.get("signature") or not self.public_key_path.exists():
                return False

            registry = self.revocation_registry or get_revocation_registry()
            return verify_revision(
                manifest,
                self.public_key_path,
                revocation_registry=registry,
            )
        except Exception:
            return False

    def get_verified_candidates(self, memory_id: str) -> list[dict[str, Any]]:
        candidates = self.get_candidates(memory_id)
        return [c for c in candidates if self.verify_snapshot(c)]

    def repair_snapshot(self, snapshot: dict[str, Any]) -> Path:
        """
        Repairs or synchronizes an invalid vault snapshot with a verified snapshot.
        """
        self.vault_dir.mkdir(parents=True, exist_ok=True)
        path = self._snapshot_path(snapshot["memory_id"], snapshot["version"])
        temp_path = path.with_suffix(".tmp")
        temp_path.write_text(json.dumps(snapshot, indent=2), encoding="utf-8")
        temp_path.replace(path)
        return path
