import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from sqlalchemy import exists, select, update

from core.memory.database import SessionLocal
from core.security.dashboard_session import DashboardSession
from core.security.dashboard_operation_approval import (
    DashboardOperationApproval,
)
from core.security.dashboard_sessions import record_session_audit


ALLOWED_OPERATIONS = {
    "attack.poison",
    "attack.tamper",
    "attack.delete",
    "memory.detect",
    "memory.recover",
}

APPROVAL_DURATION_SECONDS = 120


class DashboardOperationAuthorizationError(Exception):
    pass


def _session_reference(raw_session_id: str) -> str:
    return hashlib.sha256(
        raw_session_id.encode("utf-8")
    ).hexdigest()


def _validate_session(db, session_ref: str, now: datetime):
    session = db.get(DashboardSession, session_ref)

    if session is None:
        raise DashboardOperationAuthorizationError(
            "Dashboard session is invalid."
        )

    expires_at = session.expires_at

    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    if expires_at <= now:
        raise DashboardOperationAuthorizationError(
            "Dashboard session has expired."
        )

    return session


def authorize_dashboard_operation(
    operation: str,
    memory_id: str,
    confirmed: bool,
    raw_session_id: str,
) -> dict:

    if not isinstance(operation, str) or operation not in ALLOWED_OPERATIONS:
        raise DashboardOperationAuthorizationError(
            "Operation is not permitted."
        )

    if (
        not isinstance(memory_id, str)
        or not memory_id.strip()
        or memory_id != memory_id.strip()
        or len(memory_id) > 255
    ):
        raise DashboardOperationAuthorizationError(
            "A valid memory ID is required."
        )

    if confirmed is not True:
        raise DashboardOperationAuthorizationError(
            "Explicit operation confirmation is required."
        )

    if not isinstance(raw_session_id, str) or not raw_session_id:
        raise DashboardOperationAuthorizationError(
            "A valid dashboard session is required."
        )

    now = datetime.now(timezone.utc)
    session_ref = _session_reference(raw_session_id)
    authorization_id = secrets.token_urlsafe(32)
    expires_at = now + timedelta(
        seconds=APPROVAL_DURATION_SECONDS
    )

    with SessionLocal() as db:
        _validate_session(db, session_ref, now)

        approval = DashboardOperationApproval(
            authorization_id=authorization_id,
            session_ref=session_ref,
            operation=operation,
            memory_id=memory_id,
            created_at=now,
            expires_at=expires_at,
            status="APPROVED",
        )

        db.add(approval)
        db.commit()

    record_session_audit(
        event_type="OPERATION_APPROVAL",
        outcome="SUCCESS",
        raw_session_id=raw_session_id,
        detail=(
            f"Approved operation={operation}, "
            f"memory_id={memory_id}, "
            f"authorization_id={authorization_id}"
        ),
    )

    return {
        "authorized": True,
        "operation": operation,
        "memory_id": memory_id,
        "authorization_id": authorization_id,
        "session_ref": session_ref,
        "approved_at": now.isoformat(),
        "expires_at": expires_at.isoformat(),
        "single_use": True,
    }


def consume_dashboard_operation(
    authorization_id: str,
    operation: str,
    memory_id: str,
    raw_session_id: str,
) -> dict:

    if (
        not isinstance(authorization_id, str)
        or not authorization_id.strip()
    ):
        raise DashboardOperationAuthorizationError(
            "A valid authorization ID is required."
        )

    if not isinstance(operation, str) or operation not in ALLOWED_OPERATIONS:
        raise DashboardOperationAuthorizationError(
            "Operation is not permitted."
        )

    if (
        not isinstance(memory_id, str)
        or not memory_id.strip()
        or memory_id != memory_id.strip()
        or len(memory_id) > 255
    ):
        raise DashboardOperationAuthorizationError(
            "A valid memory ID is required."
        )

    if not isinstance(raw_session_id, str) or not raw_session_id:
        raise DashboardOperationAuthorizationError(
            "A valid dashboard session is required."
        )

    now = datetime.now(timezone.utc)
    session_ref = _session_reference(raw_session_id)

    with SessionLocal() as db:
        _validate_session(db, session_ref, now)

        active_session = exists(
    select(1).where(
        DashboardSession.id == session_ref,
        DashboardSession.expires_at > now,
    )
)

        statement = (
    update(DashboardOperationApproval)
    .where(
        DashboardOperationApproval.authorization_id
        == authorization_id,
        DashboardOperationApproval.session_ref
        == session_ref,
        DashboardOperationApproval.operation
        == operation,
        DashboardOperationApproval.memory_id
        == memory_id,
        DashboardOperationApproval.status
        == "APPROVED",
        DashboardOperationApproval.consumed_at.is_(None),
        DashboardOperationApproval.expires_at > now,
        active_session,
    )
    .values(
        status="CONSUMED",
        consumed_at=now,
    )
)

        result = db.execute(statement)

        if result.rowcount != 1:
            db.rollback()
            raise DashboardOperationAuthorizationError(
                "Approval is invalid, expired, or already consumed."
            )

        db.commit()

    record_session_audit(
        event_type="OPERATION_CONSUMED",
        outcome="SUCCESS",
        raw_session_id=raw_session_id,
        detail=(
            f"Consumed operation={operation}, "
            f"memory_id={memory_id}, "
            f"authorization_id={authorization_id}"
        ),
    )

    return {
        "authorized": True,
        "consumed": True,
        "operation": operation,
        "memory_id": memory_id,
        "authorization_id": authorization_id,
        "consumed_at": now.isoformat(),
    }