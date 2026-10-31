import hmac
import os
from pathlib import Path

ENV_FILE = Path(__file__).resolve().parents[2] / ".env"


def load_owner_token() -> str | None:
    token = os.environ.get("AEGISMEM_OWNER_TOKEN")
    if token:
        return token

    if not ENV_FILE.is_file():
        return None

    for line in ENV_FILE.read_text(encoding="utf-8").splitlines():
        key, separator, value = line.partition("=")
        if separator and key.strip() == "AEGISMEM_OWNER_TOKEN":
            token = value.strip().strip('"').strip("'")
            if token:
                return token

    return None


def verify_owner_token(authorization_header: str | None) -> bool:
    expected = load_owner_token()
    if not expected or not authorization_header:
        return False

    scheme, separator, supplied = authorization_header.partition(" ")
    if not separator or scheme.lower() != "bearer" or not supplied.strip():
        return False

    return hmac.compare_digest(expected, supplied.strip())

def attack_lab_enabled() -> bool:
    value = os.environ.get("AEGISMEM_ENABLE_ATTACK_LAB", "").strip().lower()
    return value in {"1", "true", "yes", "on"}
