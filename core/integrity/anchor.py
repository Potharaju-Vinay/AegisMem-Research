import base64
import json
import time
from pathlib import Path
from typing import Any, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from core.security.revocation import get_key_fingerprint


def _canonical_payload(manifest: dict) -> bytes:
    fields = {
        "memory_id": manifest["memory_id"],
        "revision_id": manifest["revision_id"],
        "parent_revision_id": manifest.get("parent_revision_id"),
        "version": manifest["version"],
        "content_hash": manifest["content_hash"],
        "previous_hash": manifest.get("previous_hash"),
    }
    return json.dumps(
        fields, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def sign_revision(
    memory_id: str,
    version: int,
    content_hash: str,
    previous_hash: str | None,
    private_key_path: str | Path,
    revision_id: str | None = None,
    parent_revision_id: str | None = None,
) -> dict:
    if not revision_id:
        raise ValueError("revision_id is required")

    payload = {
        "memory_id": memory_id,
        "revision_id": revision_id,
        "parent_revision_id": parent_revision_id,
        "version": version,
        "content_hash": content_hash,
        "previous_hash": previous_hash,
    }

    private_key = serialization.load_pem_private_key(
        Path(private_key_path).read_bytes(),
        password=None,
    )
    signature = private_key.sign(_canonical_payload(payload))
    payload["signature"] = base64.b64encode(signature).decode("ascii")
    return payload


def verify_revision(
    manifest: dict,
    public_key_path: str | Path,
    revocation_registry: Optional[Any] = None,
    timestamp: Optional[int] = None,
) -> bool:
    try:
        if not manifest.get("revision_id"):
            return False

        key_bytes = Path(public_key_path).read_bytes()
        if revocation_registry:
            fingerprint = get_key_fingerprint(key_bytes)
            if revocation_registry.is_revoked(fingerprint, timestamp=timestamp):
                return False

        public_key = serialization.load_pem_public_key(key_bytes)
        signature = base64.b64decode(
            manifest["signature"], validate=True
        )
        public_key.verify(signature, _canonical_payload(manifest))
        return True
    except (
        InvalidSignature,
        KeyError,
        TypeError,
        ValueError,
        OSError,
    ):
        return False


def _canonical_chain_head_payload(head_data: dict) -> bytes:
    fields = {
        "epoch": int(head_data["epoch"]),
        "head_hash": head_data["head_hash"],
        "memory_id": head_data["memory_id"],
        "previous_hash": head_data.get("previous_hash"),
        "version": int(head_data["version"]),
    }
    return json.dumps(
        fields, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def anchor_chain_head(
    memory_id: str,
    version: int,
    head_hash: str,
    previous_hash: str | None,
    epoch: int,
    private_key_path: str | Path,
    anchor_id: Optional[str] = None,
) -> dict:
    """
    Produces a cryptographic anchor receipt countersigning the latest chain head.
    An independent witness or anchor service signs this receipt.
    """
    payload = {
        "anchor_id": anchor_id or f"ANCHOR-{memory_id}-v{version}-{epoch}",
        "memory_id": memory_id,
        "version": int(version),
        "head_hash": head_hash,
        "previous_hash": previous_hash,
        "epoch": int(epoch),
    }

    private_key = serialization.load_pem_private_key(
        Path(private_key_path).read_bytes(),
        password=None,
    )
    signature = private_key.sign(_canonical_chain_head_payload(payload))
    payload["signature"] = base64.b64encode(signature).decode("ascii")
    return payload


def verify_chain_head_anchor(
    anchor_receipt: dict,
    public_key_path: str | Path,
    revocation_registry: Optional[Any] = None,
    max_age_seconds: Optional[int] = None,
) -> bool:
    """
    Verifies the anchor receipt signature countersigning the chain head.
    Validates signature, checks anchor key revocation at the receipt's epoch,
    and optionally validates receipt age.
    """
    try:
        if not all(k in anchor_receipt for k in ("memory_id", "version", "head_hash", "epoch", "signature")):
            return False

        epoch = int(anchor_receipt["epoch"])
        if max_age_seconds is not None:
            now = int(time.time())
            if abs(now - epoch) > max_age_seconds:
                return False

        key_bytes = Path(public_key_path).read_bytes()
        if revocation_registry:
            fingerprint = get_key_fingerprint(key_bytes)
            if revocation_registry.is_revoked(fingerprint, timestamp=epoch):
                return False

        public_key = serialization.load_pem_public_key(key_bytes)
        signature = base64.b64decode(anchor_receipt["signature"], validate=True)
        public_key.verify(signature, _canonical_chain_head_payload(anchor_receipt))
        return True
    except (
        InvalidSignature,
        KeyError,
        TypeError,
        ValueError,
        OSError,
    ):
        return False
