"""
AegisMem Authoritative Owner Authorization Evaluator (Task F6)
Evaluates owner requests with distinct, fine-grained reason codes:
- ACCEPTED: Digital signature, nonce freshness, and revision continuity verified.
- SIGNATURE_INVALID: Cryptographic Ed25519 signature mismatch or tampered payload.
- NONCE_REPLAYED: Replay attack detected; nonce has already been registered and consumed.
- TIMESTAMP_STALE: Clock skew exceeded MAX_CLOCK_SKEW_SECONDS (300 seconds).
- VERSION_MISMATCH: Stale parent revision ID or expected version mismatch.
- KEY_UNKNOWN: Required public key not found or unrecognized key identifier.
- INTERNAL_ERROR: Database connectivity or storage engine exception.

Records every evaluation into the authorization_events audit table.
External clients receive only a generic message + correlation_id to prevent oracle leaks.
"""

import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from sqlalchemy.exc import SQLAlchemyError

from core.memory.models import AuthorizationEvent, MemoryRecord
from core.security.request_signatures import canonical_request, MAX_CLOCK_SKEW_SECONDS
from core.security.owner_approval import (
    canonical_owner_approval,
    verify_owner_approval,
    OWNER_APPROVAL_PUBLIC_KEY_PATH,
)

BASE_DIR = Path(__file__).resolve().parents[2]
OWNER_REQUEST_PUBLIC_KEY_PATH = (
    BASE_DIR / "security" / "keys" / "owner_request_public_key.pem"
)


def record_authorization_event(
    session,
    correlation_id: str,
    outcome: str,
    reason_code: str,
    memory_id: str | None,
    operation: str = "OWNER_UPDATE",
    client_ip: str | None = None,
    client_port: int | None = None,
    nonce: str | None = None,
    timestamp_val: float | None = None,
    expected_version: int | None = None,
    observed_version: int | None = None,
    error_detail: str | None = None,
) -> AuthorizationEvent:
    event = AuthorizationEvent(
        correlation_id=correlation_id,
        memory_id=memory_id,
        operation=operation,
        outcome=outcome,
        reason_code=reason_code,
        client_ip=client_ip,
        client_port=client_port,
        nonce=nonce,
        timestamp_val=timestamp_val,
        expected_version=expected_version,
        observed_version=observed_version,
        error_detail=error_detail,
        created_at=datetime.now(timezone.utc),
    )
    try:
        session.add(event)
        session.commit()
    except Exception as exc:
        session.rollback()
        print(f"[Warning] Failed to persist AuthorizationEvent: {exc}")
    return event


def evaluate_owner_request(
    session,
    method: str,
    path: str,
    timestamp_str: str | None,
    nonce_str: str | None,
    signature_hex: str | None,
    raw_body: bytes,
    client_ip: str | None = None,
    client_port: int | None = None,
    memory_id: str | None = None,
    expected_revision_id: str | None = None,
    expected_version: int | None = None,
    authorization_signature: str | None = None,
    authorization_id: str | None = None,
    authorization_nonce: str | None = None,
    content: str | None = None,
) -> Tuple[bool, str, str, str]:
    """
    Evaluates owner authorization and returns:
    (is_accepted: bool, reason_code: str, correlation_id: str, error_detail: str)
    """
    correlation_id = f"auth-{uuid.uuid4().hex[:16]}"
    ts_val: float | None = None

    # 1. Validate Timestamp Freshness
    if not timestamp_str or not str(timestamp_str).strip():
        detail = "Missing or empty X-Owner-Timestamp header"
        record_authorization_event(
            session=session,
            correlation_id=correlation_id,
            outcome="REJECTED",
            reason_code="TIMESTAMP_STALE",
            memory_id=memory_id,
            client_ip=client_ip,
            client_port=client_port,
            nonce=nonce_str,
            error_detail=detail,
        )
        return False, "TIMESTAMP_STALE", correlation_id, detail

    try:
        ts_val = float(timestamp_str)
    except (ValueError, TypeError):
        detail = f"Unparseable timestamp: '{timestamp_str}'"
        record_authorization_event(
            session=session,
            correlation_id=correlation_id,
            outcome="REJECTED",
            reason_code="TIMESTAMP_STALE",
            memory_id=memory_id,
            client_ip=client_ip,
            client_port=client_port,
            nonce=nonce_str,
            error_detail=detail,
        )
        return False, "TIMESTAMP_STALE", correlation_id, detail

    now_ts = time.time()
    skew = abs(now_ts - ts_val)
    if skew > MAX_CLOCK_SKEW_SECONDS:
        detail = f"Clock skew {skew:.1f}s exceeds maximum allowed {MAX_CLOCK_SKEW_SECONDS}s"
        record_authorization_event(
            session=session,
            correlation_id=correlation_id,
            outcome="REJECTED",
            reason_code="TIMESTAMP_STALE",
            memory_id=memory_id,
            client_ip=client_ip,
            client_port=client_port,
            nonce=nonce_str,
            timestamp_val=ts_val,
            error_detail=detail,
        )
        return False, "TIMESTAMP_STALE", correlation_id, detail

    # 2. Validate Owner Request Public Key Existence
    if not OWNER_REQUEST_PUBLIC_KEY_PATH.is_file():
        detail = f"Owner request public key file not found: {OWNER_REQUEST_PUBLIC_KEY_PATH}"
        record_authorization_event(
            session=session,
            correlation_id=correlation_id,
            outcome="REJECTED",
            reason_code="KEY_UNKNOWN",
            memory_id=memory_id,
            client_ip=client_ip,
            client_port=client_port,
            nonce=nonce_str,
            timestamp_val=ts_val,
            error_detail=detail,
        )
        return False, "KEY_UNKNOWN", correlation_id, detail

    try:
        request_pubkey = serialization.load_pem_public_key(
            OWNER_REQUEST_PUBLIC_KEY_PATH.read_bytes()
        )
    except Exception as exc:
        detail = f"Failed to load owner request public key: {exc}"
        record_authorization_event(
            session=session,
            correlation_id=correlation_id,
            outcome="REJECTED",
            reason_code="KEY_UNKNOWN",
            memory_id=memory_id,
            client_ip=client_ip,
            client_port=client_port,
            nonce=nonce_str,
            timestamp_val=ts_val,
            error_detail=detail,
        )
        return False, "KEY_UNKNOWN", correlation_id, detail

    # 3. Validate Digital Signature on HTTP Request
    if not signature_hex or not str(signature_hex).strip():
        detail = "Missing or empty X-Owner-Signature header"
        record_authorization_event(
            session=session,
            correlation_id=correlation_id,
            outcome="REJECTED",
            reason_code="SIGNATURE_INVALID",
            memory_id=memory_id,
            client_ip=client_ip,
            client_port=client_port,
            nonce=nonce_str,
            timestamp_val=ts_val,
            error_detail=detail,
        )
        return False, "SIGNATURE_INVALID", correlation_id, detail

    try:
        sig_bytes = bytes.fromhex(signature_hex)
        req_payload = canonical_request(
            method=method,
            path=path,
            timestamp=str(int(ts_val)),
            nonce=str(nonce_str or ""),
            body=raw_body,
        )
        request_pubkey.verify(sig_bytes, req_payload)
    except (ValueError, TypeError, InvalidSignature) as exc:
        detail = f"Request signature verification failed: {exc}"
        record_authorization_event(
            session=session,
            correlation_id=correlation_id,
            outcome="REJECTED",
            reason_code="SIGNATURE_INVALID",
            memory_id=memory_id,
            client_ip=client_ip,
            client_port=client_port,
            nonce=nonce_str,
            timestamp_val=ts_val,
            error_detail=detail,
        )
        return False, "SIGNATURE_INVALID", correlation_id, detail
    except Exception as exc:
        detail = f"Unexpected error during signature verification: {exc}"
        record_authorization_event(
            session=session,
            correlation_id=correlation_id,
            outcome="REJECTED",
            reason_code="INTERNAL_ERROR",
            memory_id=memory_id,
            client_ip=client_ip,
            client_port=client_port,
            nonce=nonce_str,
            timestamp_val=ts_val,
            error_detail=detail,
        )
        return False, "INTERNAL_ERROR", correlation_id, detail

    # 4. Validate Nonce Freshness (Detect Replay)
    if not nonce_str or not str(nonce_str).strip() or len(nonce_str) > 128:
        detail = "Invalid or empty X-Owner-Nonce header"
        record_authorization_event(
            session=session,
            correlation_id=correlation_id,
            outcome="REJECTED",
            reason_code="SIGNATURE_INVALID",
            memory_id=memory_id,
            client_ip=client_ip,
            client_port=client_port,
            nonce=nonce_str,
            timestamp_val=ts_val,
            error_detail=detail,
        )
        return False, "SIGNATURE_INVALID", correlation_id, detail

    from core.security.authorization import verify_and_register_nonce
    try:
        registered = verify_and_register_nonce(
            f"owner-request:{nonce_str}",
            f"request:{method.upper()}:{path}",
        )
        if not registered:
            detail = f"Nonce '{nonce_str}' was already registered (replay detected)"
            record_authorization_event(
                session=session,
                correlation_id=correlation_id,
                outcome="REJECTED",
                reason_code="NONCE_REPLAYED",
                memory_id=memory_id,
                client_ip=client_ip,
                client_port=client_port,
                nonce=nonce_str,
                timestamp_val=ts_val,
                error_detail=detail,
            )
            return False, "NONCE_REPLAYED", correlation_id, detail
    except SQLAlchemyError as exc:
        detail = f"Database error during nonce registration: {exc}"
        record_authorization_event(
            session=session,
            correlation_id=correlation_id,
            outcome="REJECTED",
            reason_code="INTERNAL_ERROR",
            memory_id=memory_id,
            client_ip=client_ip,
            client_port=client_port,
            nonce=nonce_str,
            timestamp_val=ts_val,
            error_detail=detail,
        )
        return False, "INTERNAL_ERROR", correlation_id, detail

    # 5. Validate Owner Policy Approval Signature (if provided in payload)
    if authorization_signature and content is not None:
        if not OWNER_APPROVAL_PUBLIC_KEY_PATH.is_file():
            detail = f"Owner approval public key file not found: {OWNER_APPROVAL_PUBLIC_KEY_PATH}"
            record_authorization_event(
                session=session,
                correlation_id=correlation_id,
                outcome="REJECTED",
                reason_code="KEY_UNKNOWN",
                memory_id=memory_id,
                client_ip=client_ip,
                client_port=client_port,
                nonce=nonce_str,
                timestamp_val=ts_val,
                error_detail=detail,
            )
            return False, "KEY_UNKNOWN", correlation_id, detail

        is_approval_valid = False
        try_timestamps = [None]
        if ts_val is not None:
            try_timestamps.append(int(ts_val))

        for try_ts in try_timestamps:
            try:
                if verify_owner_approval(
                    memory_id=memory_id or "",
                    content=content,
                    expected_parent_revision_id=expected_revision_id,
                    authorization_id=authorization_id or "",
                    nonce=authorization_nonce or nonce_str or "",
                    signature_hex=authorization_signature,
                    timestamp=try_ts,
                    expected_version=expected_version,
                ):
                    is_approval_valid = True
                    break
            except Exception:
                pass

        if not is_approval_valid:
            detail = "Owner approval signature verification failed"
            record_authorization_event(
                session=session,
                correlation_id=correlation_id,
                outcome="REJECTED",
                reason_code="SIGNATURE_INVALID",
                memory_id=memory_id,
                client_ip=client_ip,
                client_port=client_port,
                nonce=nonce_str,
                timestamp_val=ts_val,
                error_detail=detail,
            )
            return False, "SIGNATURE_INVALID", correlation_id, detail

    # 6. Validate Version and Parent Revision Continuity
    obs_version = None
    if memory_id:
        try:
            latest = (
                session.query(MemoryRecord)
                .filter(MemoryRecord.memory_id == memory_id, MemoryRecord.status == "active")
                .order_by(MemoryRecord.version.desc())
                .first()
            )
            if latest:
                obs_version = latest.version
                if expected_revision_id and latest.revision_id != expected_revision_id:
                    detail = (
                        f"Parent revision mismatch for {memory_id}: expected "
                        f"'{expected_revision_id}', observed head '{latest.revision_id}'"
                    )
                    record_authorization_event(
                        session=session,
                        correlation_id=correlation_id,
                        outcome="REJECTED",
                        reason_code="VERSION_MISMATCH",
                        memory_id=memory_id,
                        client_ip=client_ip,
                        client_port=client_port,
                        nonce=nonce_str,
                        timestamp_val=ts_val,
                        expected_version=expected_version,
                        observed_version=obs_version,
                        error_detail=detail,
                    )
                    return False, "VERSION_MISMATCH", correlation_id, detail

                if expected_version is not None and latest.version != expected_version:
                    detail = (
                        f"Version mismatch for {memory_id}: expected v{expected_version}, "
                        f"observed head v{latest.version}"
                    )
                    record_authorization_event(
                        session=session,
                        correlation_id=correlation_id,
                        outcome="REJECTED",
                        reason_code="VERSION_MISMATCH",
                        memory_id=memory_id,
                        client_ip=client_ip,
                        client_port=client_port,
                        nonce=nonce_str,
                        timestamp_val=ts_val,
                        expected_version=expected_version,
                        observed_version=obs_version,
                        error_detail=detail,
                    )
                    return False, "VERSION_MISMATCH", correlation_id, detail
        except SQLAlchemyError as exc:
            detail = f"Database error during version check: {exc}"
            record_authorization_event(
                session=session,
                correlation_id=correlation_id,
                outcome="REJECTED",
                reason_code="INTERNAL_ERROR",
                memory_id=memory_id,
                client_ip=client_ip,
                client_port=client_port,
                nonce=nonce_str,
                timestamp_val=ts_val,
                error_detail=detail,
            )
            return False, "INTERNAL_ERROR", correlation_id, detail

    # 7. All Assertions Passed: Record ACCEPTED
    detail = "Legitimate owner digital signature, nonce, and revision continuity verified."
    record_authorization_event(
        session=session,
        correlation_id=correlation_id,
        outcome="ACCEPTED",
        reason_code="ACCEPTED",
        memory_id=memory_id,
        client_ip=client_ip,
        client_port=client_port,
        nonce=nonce_str,
        timestamp_val=ts_val,
        expected_version=expected_version,
        observed_version=obs_version,
        error_detail=detail,
    )
    return True, "ACCEPTED", correlation_id, detail
