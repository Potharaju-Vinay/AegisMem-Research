import hashlib
import json
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization

BASE_DIR = Path(__file__).resolve().parents[2]
OWNER_APPROVAL_PUBLIC_KEY_PATH = (
    BASE_DIR / "security" / "keys" / "owner_public_key.pem"
)
PROTOCOL_VERSION = "aegismem-owner-approval-v1"


def canonical_owner_approval(
    memory_id: str,
    content: str,
    expected_parent_revision_id: str | None,
    authorization_id: str,
    nonce: str,
    timestamp: int | None = None,
    expected_version: int | None = None,
) -> bytes:
    payload = {
        "protocol": PROTOCOL_VERSION,
        "operation": "memory.write",
        "memory_id": memory_id,
        "content_sha256": hashlib.sha256(
            content.encode("utf-8")
        ).hexdigest(),
        "expected_parent_revision_id": expected_parent_revision_id,
        "authorization_id": authorization_id,
        "nonce": nonce,
    }
    if timestamp is not None:
        payload["timestamp"] = timestamp
    if expected_version is not None:
        payload["expected_version"] = expected_version
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def verify_owner_approval(
    memory_id: str,
    content: str,
    expected_parent_revision_id: str | None,
    authorization_id: str,
    nonce: str,
    signature_hex: str | None,
    timestamp: int | None = None,
    expected_version: int | None = None,
    max_age_seconds: int = 300,
) -> bool:
    if not all((memory_id, authorization_id, nonce, signature_hex)):
        return False

    if len(nonce) > 100 or not nonce.strip():
        return False

    try:
        public_key = serialization.load_pem_public_key(
            OWNER_APPROVAL_PUBLIC_KEY_PATH.read_bytes()
        )
        signature = bytes.fromhex(signature_hex)
        if timestamp is not None:
            import time
            if abs(int(time.time()) - int(timestamp)) > max_age_seconds:
                return False
        payload = canonical_owner_approval(
            memory_id,
            content,
            expected_parent_revision_id,
            authorization_id,
            nonce,
            timestamp=timestamp,
            expected_version=expected_version,
        )
        public_key.verify(signature, payload)
        return True
    except (
        InvalidSignature,
        ValueError,
        TypeError,
        UnicodeEncodeError,
    ):
        return False
    except OSError as err:
        print(f"[AegisMem Security] Key or file system error: {err}")
        return False

def verify_record_owner_approval(record) -> bool:
    if (
        getattr(record, "authorization_state", None) != "AUTHORIZED"
        or not getattr(record, "authorization_signature", None)
        or not getattr(record, "authorization_nonce", None)
        or not getattr(record, "authorization_id", None)
    ):
        return False

    return verify_owner_approval(
        memory_id=record.memory_id,
        content=record.content,
        expected_parent_revision_id=record.parent_revision_id,
        authorization_id=record.authorization_id,
        nonce=record.authorization_nonce,
        signature_hex=record.authorization_signature,
    )