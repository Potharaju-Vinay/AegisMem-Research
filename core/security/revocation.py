import hashlib
import json
import time
from pathlib import Path
from typing import Any, Dict, Optional


def get_key_fingerprint(key_bytes_or_pem: bytes | str) -> str:
    """
    Computes a deterministic SHA-256 fingerprint for a PEM or raw public key.
    Normalizes whitespace and standardizes header/footer for string PEMs.
    """
    if isinstance(key_bytes_or_pem, str):
        normalized = key_bytes_or_pem.strip().replace("\r\n", "\n")
        data = normalized.encode("utf-8")
    else:
        data = key_bytes_or_pem
    return hashlib.sha256(data).hexdigest()


class KeyRevocationRegistry:
    """
    Cryptographic Key Revocation Registry with Compromise Epoch.
    Tracks compromised key fingerprints and the epoch (timestamp) at which
    the key was compromised.
    
    Any signature produced at or after compromise_epoch is strictly untrusted.
    Signatures produced before compromise_epoch can still be trusted if verified.
    """

    def __init__(self, registry_path: Optional[Path | str] = None):
        self.registry_path = Path(registry_path) if registry_path else None
        self._revoked_keys: Dict[str, Dict[str, Any]] = {}
        if self.registry_path and self.registry_path.exists():
            self.load()

    def revoke_key(
        self,
        key_fingerprint: str,
        compromise_epoch: int,
        reason: str = "Key compromised",
    ) -> Dict[str, Any]:
        """
        Registers a key as revoked starting from compromise_epoch.
        """
        entry = {
            "fingerprint": key_fingerprint,
            "compromise_epoch": int(compromise_epoch),
            "revoked_at": int(time.time()),
            "reason": reason,
        }
        self._revoked_keys[key_fingerprint] = entry
        if self.registry_path:
            self.save()
        return entry

    def is_revoked(
        self,
        key_fingerprint: str,
        timestamp: Optional[int] = None,
    ) -> bool:
        """
        Checks whether a key is revoked at a specific timestamp.
        If timestamp is None, returns True if the key is in the registry at all.
        If timestamp is provided, returns True only if timestamp >= compromise_epoch.
        """
        entry = self._revoked_keys.get(key_fingerprint)
        if not entry:
            return False

        if timestamp is None:
            return True

        return int(timestamp) >= entry["compromise_epoch"]

    def get_revocation_info(self, key_fingerprint: str) -> Optional[Dict[str, Any]]:
        return self._revoked_keys.get(key_fingerprint)

    def list_revocations(self) -> list[Dict[str, Any]]:
        return list(self._revoked_keys.values())

    def clear(self) -> None:
        self._revoked_keys.clear()
        if self.registry_path and self.registry_path.exists():
            self.save()

    def save(self) -> None:
        if not self.registry_path:
            return
        self.registry_path.parent.mkdir(parents=True, exist_ok=True)
        self.registry_path.write_text(
            json.dumps(self._revoked_keys, indent=2, sort_keys=True),
            encoding="utf-8",
        )

    def load(self) -> None:
        if not self.registry_path or not self.registry_path.exists():
            return
        try:
            data = json.loads(self.registry_path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                self._revoked_keys = data
        except Exception:
            self._revoked_keys = {}


_GLOBAL_REGISTRY: Optional[KeyRevocationRegistry] = None


def get_revocation_registry(registry_path: Optional[Path | str] = None) -> KeyRevocationRegistry:
    global _GLOBAL_REGISTRY
    if _GLOBAL_REGISTRY is None:
        default_path = registry_path or Path("security/revocation_registry.json")
        _GLOBAL_REGISTRY = KeyRevocationRegistry(default_path)
    return _GLOBAL_REGISTRY

