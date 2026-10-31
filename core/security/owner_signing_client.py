import hashlib
import json
import time
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

from core.security.owner_approval import canonical_owner_approval
from core.security.request_signatures import canonical_request


def load_signing_key(private_key_path: str | Path) -> Ed25519PrivateKey:
    key_path = Path(private_key_path)
    private_key = serialization.load_pem_private_key(
        key_path.read_bytes(),
        password=None,
    )
    if not isinstance(private_key, Ed25519PrivateKey):
        raise ValueError("The supplied private key must use Ed25519.")
    return private_key


def _require_ed25519_key(private_key) -> None:
    if not isinstance(private_key, Ed25519PrivateKey):
        raise TypeError("An Ed25519 private key is required.")


def sign_owner_approval(
    private_key: Ed25519PrivateKey,
    memory_id: str,
    content: str,
    authorization_id: str,
    nonce: str,
    expected_parent_revision_id: str | None = None,
    timestamp: int | None = None,
    expected_version: int | None = None,
) -> str:
    _require_ed25519_key(private_key)
    if not all(isinstance(value, str) and value.strip() for value in (
        memory_id, content, authorization_id, nonce
    )):
        raise ValueError(
            "Memory ID, content, authorization ID, and nonce are required."
        )
    if len(nonce) > 100:
        raise ValueError("Nonce must not exceed 100 characters.")
    payload = canonical_owner_approval(
        memory_id=memory_id,
        content=content,
        expected_parent_revision_id=expected_parent_revision_id,
        authorization_id=authorization_id,
        nonce=nonce,
        timestamp=timestamp,
        expected_version=expected_version,
    )
    return private_key.sign(payload).hex()


def sign_http_request(
    private_key: Ed25519PrivateKey,
    method: str,
    path: str,
    body: bytes,
    nonce: str,
    timestamp: int | None = None,
) -> dict[str, str]:
    _require_ed25519_key(private_key)
    if not isinstance(method, str) or not method.strip():
        raise ValueError("HTTP method is required.")
    if method != method.strip() or any(char.isspace() for char in method):
        raise ValueError("HTTP method must not contain whitespace.")
    if not isinstance(path, str) or not path.startswith("/") or "\n" in path or "\r" in path:
        raise ValueError("A valid absolute URL path is required.")
    if "://" in path or "?" in path or "#" in path:
        raise ValueError("Sign the URL path only, without origin, query, or fragment.")
    if not isinstance(nonce, str) or not nonce.strip() or len(nonce) > 100:
        raise ValueError("A non-empty nonce of at most 100 characters is required.")
    if not isinstance(body, bytes):
        raise TypeError("The request body must be bytes.")
    body.decode("utf-8")
    if timestamp is None:
        timestamp_value = int(time.time())
    elif isinstance(timestamp, bool) or not isinstance(timestamp, int):
        raise TypeError("Timestamp must be an integer Unix timestamp.")
    else:
        timestamp_value = timestamp
    if timestamp_value <= 0:
        raise ValueError("Timestamp must be a positive Unix timestamp.")

    timestamp_text = str(timestamp_value)
    payload = canonical_request(
        method=method,
        path=path,
        timestamp=timestamp_text,
        nonce=nonce,
        body=body,
    )
    signature = private_key.sign(payload).hex()
    return {
        "X-Owner-Timestamp": timestamp_text,
        "X-Owner-Nonce": nonce,
        "X-Owner-Signature": signature,
    }


def encode_json_body(payload: dict) -> bytes:
    if not isinstance(payload, dict):
        raise TypeError("JSON request payload must be a dictionary.")
    return json.dumps(
        payload,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def sha256_content(content: str) -> str:
    if not isinstance(content, str):
        raise TypeError("Content must be a string.")
    return hashlib.sha256(content.encode("utf-8")).hexdigest()
