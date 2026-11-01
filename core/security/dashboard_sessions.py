import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from core.memory.database import SessionLocal
from core.security.dashboard_session import DashboardSession

SESSION_COOKIE_NAME = "aegismem_session"
SESSION_DURATION_HOURS = 8
password_hasher = PasswordHasher()


def verify_dashboard_password(password: str) -> bool:
    from pathlib import Path
    import os

    password_hash = os.environ.get("AEGISMEM_DASHBOARD_PASSWORD_HASH")
    if not password_hash:
        env_file = Path(__file__).resolve().parents[2] / ".env"
        if env_file.is_file():
            for line in env_file.read_text(encoding="utf-8").splitlines():
                key, separator, value = line.partition("=")
                if separator and key.strip() == "AEGISMEM_DASHBOARD_PASSWORD_HASH":
                    password_hash = value.strip().strip('"').strip("'")
                    break

    if not password_hash:
        return False

    if "$$" in password_hash:
        password_hash = password_hash.replace("$$", "$")

    try:
        return password_hasher.verify(password_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError, ValueError):
        return False


def create_dashboard_session() -> str:
    raw_id = secrets.token_urlsafe(32)
    session_id = hashlib.sha256(raw_id.encode("utf-8")).hexdigest()
    now = datetime.now(timezone.utc)

    with SessionLocal() as db:
        db.add(
            DashboardSession(
                id=session_id,
                created_at=now,
                expires_at=now + timedelta(hours=SESSION_DURATION_HOURS),
            )
        )
        db.commit()

    return raw_id


def validate_dashboard_session(raw_id: str | None) -> bool:
    if not raw_id:
        return False

    session_id = hashlib.sha256(raw_id.encode("utf-8")).hexdigest()
    now = datetime.now(timezone.utc)

    with SessionLocal() as db:
        session = db.get(DashboardSession, session_id)
        if not session:
            return False

        expires_at = session.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)

        if expires_at <= now:
            db.delete(session)
            db.commit()
            return False

        return True


def revoke_dashboard_session(raw_id: str | None) -> None:
    if not raw_id:
        return

    session_id = hashlib.sha256(raw_id.encode("utf-8")).hexdigest()

    with SessionLocal() as db:
        session = db.get(DashboardSession, session_id)
        if session:
            db.delete(session)
            db.commit()

def record_session_audit(
    event_type: str,
    outcome: str,
    source_ip: str | None = None,
    user_agent: str | None = None,
    raw_session_id: str | None = None,
    detail: str = "",
) -> None:
    from core.soc.session_audit import SessionAuditEvent

    session_ref = (
        hashlib.sha256(raw_session_id.encode("utf-8")).hexdigest()
        if raw_session_id
        else None
    )

    with SessionLocal() as db:
        db.add(
            SessionAuditEvent(
                session_ref=session_ref,
                event_type=event_type[:32],
                outcome=outcome[:32],
                source_ip=source_ip[:64] if source_ip else None,
                user_agent=user_agent[:512] if user_agent else None,
                detail=detail[:2000],
            )
        )
        db.commit()
