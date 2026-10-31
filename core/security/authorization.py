from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from core.memory.database import SessionLocal


BASE_DIR = Path(__file__).resolve().parents[2]

PRIVATE_KEY_PATH = BASE_DIR / "security" / "keys" / "owner_private_key.pem"
PUBLIC_KEY_PATH = BASE_DIR / "security" / "keys" / "owner_public_key.pem"


def load_private_key():
    with open(PRIVATE_KEY_PATH, "rb") as f:
        return serialization.load_pem_private_key(
            f.read(),
            password=None
        )


def load_public_key():
    with open(PUBLIC_KEY_PATH, "rb") as f:
        return serialization.load_pem_public_key(f.read())


def sign_authorization(payload: str) -> str:
    key = load_private_key()
    return key.sign(payload.encode()).hex()


def verify_authorization(payload: str, signature: str) -> bool:
    try:
        key = load_public_key()
        key.verify(
            bytes.fromhex(signature),
            payload.encode()
        )
        return True
    except Exception:
        return False



def register_nonce(
    nonce: str,
    authorization_id: str
) -> bool:
    session = None

    try:
        session = SessionLocal()

        session.execute(
            text("""
                INSERT INTO authorization_nonces
                (nonce, authorization_id, created_at)
                VALUES (:nonce, :authorization_id, :created_at)
            """),
            {
                "nonce": nonce,
                "authorization_id": authorization_id,
                "created_at": datetime.now(timezone.utc)
            }
        )

        session.commit()
        return True

    except Exception:
        if session is not None:
            try:
                session.rollback()
            except Exception:
                pass
        return False

    finally:
        if session is not None:
            try:
                session.close()
            except Exception:
                pass

def nonce_exists(nonce: str) -> bool:

    session = SessionLocal()

    try:
        result = session.execute(
            text("""
                SELECT 1
                FROM authorization_nonces
                WHERE nonce = :nonce
                LIMIT 1
            """),
            {"nonce": nonce}
        )

        return result.first() is not None

    finally:
        session.close()



def verify_and_register_nonce(
    nonce: str,
    authorization_id: str,
    session=None,
) -> bool:
    if not nonce or not authorization_id:
        return False

    if len(nonce) > 128 or len(authorization_id) > 128:
        return False

    if session is None:
        return register_nonce(nonce, authorization_id)

    try:
        session.execute(
            text("""
                INSERT INTO authorization_nonces
                (nonce, authorization_id, created_at)
                VALUES (:nonce, :authorization_id, :created_at)
            """),
            {
                "nonce": nonce,
                "authorization_id": authorization_id,
                "created_at": datetime.now(timezone.utc),
            },
        )
        return True
    except IntegrityError:
        return False
