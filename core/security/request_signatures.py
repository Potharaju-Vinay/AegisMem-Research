import time
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization

from core.security.authorization import verify_and_register_nonce

BASE_DIR = Path(__file__).resolve().parents[2]
OWNER_REQUEST_PUBLIC_KEY_PATH = (
    BASE_DIR / "security" / "keys" / "owner_request_public_key.pem"
)
MAX_CLOCK_SKEW_SECONDS = 300


def canonical_request(
    method: str,
    path: str,
    timestamp: str,
    nonce: str,
    body: bytes,
) -> bytes:
    if not isinstance(body, bytes):
        raise TypeError("Request body must be bytes.")
    fields = (
        method.upper(),
        path,
        timestamp,
        nonce,
        body.decode("utf-8"),
    )
    return "\n".join(fields).encode("utf-8")


def verify_owner_request_signature(
    method: str,
    path: str,
    timestamp: str | None,
    nonce: str | None,
    signature_hex: str | None,
    body: bytes,
) -> bool:
    if not all(
        isinstance(value, str) and value.strip()
        for value in (method, path, timestamp, nonce, signature_hex)
    ):
        return False

    if len(nonce) > 100 or not isinstance(body, bytes):
        return False

    try:
        timestamp_value = int(timestamp)
        if abs(int(time.time()) - timestamp_value) > MAX_CLOCK_SKEW_SECONDS:
            return False

        public_key = serialization.load_pem_public_key(
            OWNER_REQUEST_PUBLIC_KEY_PATH.read_bytes()
        )
        signature = bytes.fromhex(signature_hex)
        payload = canonical_request(method, path, timestamp, nonce, body)
        public_key.verify(signature, payload)
    except (
        OSError,
        ValueError,
        TypeError,
        InvalidSignature,
        UnicodeDecodeError,
        AttributeError,
    ):
        return False
    except Exception:
        return False

    try:
        return bool(
            verify_and_register_nonce(
                f"owner-request:{nonce}",
                f"request:{method.upper()}:{path}",
            )
        )
    except Exception:
        return False
