import json
import os
import tempfile
from pathlib import Path

from core.integrity.anchor import sign_revision, verify_revision


class IntegrityManifestStore:
    def __init__(
        self,
        manifest_dir: str | Path = "security/integrity_manifests",
        private_key_path: str | Path = "security/keys/integrity_anchor_private.pem",
        public_key_path: str | Path = "security/keys/integrity_anchor_public.pem",
    ):
        self.manifest_dir = Path(manifest_dir)
        self.private_key_path = Path(private_key_path)
        self.public_key_path = Path(public_key_path)

    def _path(self, memory_id: str, version: int) -> Path:
        import hashlib
        safe_id = hashlib.sha256(memory_id.encode("utf-8")).hexdigest()
        return self.manifest_dir / f"{safe_id}.{version}.json"

    def create_for_record(self, record) -> dict:
        anchor_url = os.getenv("ANCHOR_URL", "http://anchor:8000")
        internal_token = os.getenv("AEGISMEM_INTERNAL_TOKEN", "")
        manifest = None
        # Attempt to sign via authoritative Anchor Witness microservice
        try:
            import urllib.request
            headers = {"Content-Type": "application/json"}
            if internal_token:
                headers["X-Anchor-Token"] = internal_token

            is_seed = (record.version == 1 and not getattr(record, "authorization_signature", None))
            is_rec = (
                getattr(record, "_is_recovery", False)
                or getattr(record, "source_type", "") == "verified_recovery"
                or str(getattr(record, "source", "")).startswith("recovery")
            )
            role = "seed_initializer" if is_seed else ("recovery_service" if is_rec else "gateway")

            payload = json.dumps({
                "memory_id": record.memory_id,
                "version": record.version,
                "content_hash": record.content_hash,
                "previous_hash": record.previous_hash,
                "revision_id": record.revision_id,
                "parent_revision_id": record.parent_revision_id,
                "owner_signature": getattr(record, "authorization_signature", None),
                "authorization_id": getattr(record, "authorization_id", None),
                "nonce": getattr(record, "authorization_nonce", None),
                "timestamp": getattr(record, "authorization_timestamp", None),
                "content": getattr(record, "content", None),
                "caller_role": role,
            }).encode("utf-8")
            req = urllib.request.Request(
                f"{anchor_url}/manifest/sign",
                data=payload,
                headers=headers,
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=3) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                manifest = data.get("manifest")
        except Exception:
            pass

        if manifest is None and self.private_key_path.exists():
            # Fallback to local anchor key only if witness microservice is unavailable and key exists locally
            manifest = sign_revision(
                memory_id=record.memory_id,
                version=record.version,
                content_hash=record.content_hash,
                previous_hash=record.previous_hash,
                private_key_path=self.private_key_path,
                revision_id=record.revision_id,
                parent_revision_id=record.parent_revision_id,
            )
        if manifest:
            try:
                self.write_manifest(manifest)
            except OSError:
                # Manifest directory is read-only on gateway (Hardened F4)
                pass
        return manifest

    def write_manifest(self, manifest: dict, overwrite: bool = True) -> Path:
        self.manifest_dir.mkdir(parents=True, exist_ok=True)
        destination = self._path(
            manifest["memory_id"], manifest["version"]
        )
        if destination.exists() and not overwrite:
            raise FileExistsError(
                f"Manifest already exists for version {manifest['version']}"
            )

        fd, temporary_name = tempfile.mkstemp(
            prefix=".manifest-", suffix=".tmp", dir=self.manifest_dir
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(manifest, handle, sort_keys=True, indent=2)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary_name, destination)
        except Exception:
            try:
                os.unlink(temporary_name)
            except FileNotFoundError:
                pass
            raise
        return destination

    def has_manifest(self, record) -> bool:
        return self._path(record.memory_id, record.version).is_file()

    def verify_record(self, record) -> bool:
        path = self._path(record.memory_id, record.version)

        try:
            manifest = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return False

        if not verify_revision(manifest, self.public_key_path):
            return False

        try:
            from core.integrity.hash import calculate_version_hash

            calculated_hash = calculate_version_hash(
                record.content,
                record.previous_hash,
            )
        except Exception:
            return False

        return (
            manifest.get("memory_id") == record.memory_id
            and manifest.get("version") == record.version
            and manifest.get("revision_id") == record.revision_id
            and manifest.get("parent_revision_id") == record.parent_revision_id
            and manifest.get("content_hash") == record.content_hash
            and manifest.get("previous_hash") == record.previous_hash
            and calculated_hash == record.content_hash
        )
