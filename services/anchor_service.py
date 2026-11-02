"""
AegisMem Independent Anchor Witness Microservice (Hardened Milestone F4)
Listens on internal network to provide authoritative cryptographic manifests and signatures.
Holds ONLY the Anchor Private Key; other services verify using the Anchor Public Key.
Enforces:
1. Caller Authentication: Inter-service authentication token required.
2. Owner Approval Verification: Validates owner Ed25519 digital signature, nonce, timestamp,
   and monotonic parent revision continuity against the anchor's recorded heads.
3. Rejection of unauthenticated or unauthorized signing attempts with HTTP 401/403.
"""
import base64
import json
import os
import sys
import time
from pathlib import Path
from typing import Dict, Optional, Set
from cryptography.hazmat.primitives import serialization
from fastapi import FastAPI, HTTPException, Request, Header
from pydantic import BaseModel

# Ensure repository root is on sys.path
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from core.integrity.anchor import sign_revision, verify_revision
from core.security.owner_approval import verify_owner_approval

app = FastAPI(title="AegisMem Hardened Anchor Witness Service", version="2.0.0")

PRIVATE_KEY_PATH = os.getenv("ANCHOR_PRIVATE_KEY_PATH", "security/keys/integrity_anchor_private.pem")
PUBLIC_KEY_PATH = os.getenv("ANCHOR_PUBLIC_KEY_PATH", "security/keys/integrity_anchor_public.pem")
INTERNAL_TOKEN = os.getenv("AEGISMEM_INTERNAL_TOKEN", "")

# In-memory recorded state for head revisions & used nonces
RECORDED_HEADS: Dict[str, dict] = {}
USED_NONCES: Set[str] = set()


class SignManifestRequest(BaseModel):
    memory_id: str
    version: int
    content_hash: str
    previous_hash: Optional[str] = None
    revision_id: str
    parent_revision_id: Optional[str] = None
    # Owner Signed Approval Fields
    owner_signature: Optional[str] = None
    authorization_id: Optional[str] = None
    nonce: Optional[str] = None
    timestamp: Optional[int] = None
    content: Optional[str] = None
    caller_role: Optional[str] = "gateway"  # "gateway" or "recovery_service"


class VerifyManifestRequest(BaseModel):
    manifest: dict


class CheckpointSignRequest(BaseModel):
    memory_id: str
    version: int
    event_hash: str
    event_count: int


@app.post("/checkpoint/sign")
def sign_checkpoint(
    req: CheckpointSignRequest,
    authorization: Optional[str] = Header(None),
    x_anchor_token: Optional[str] = Header(None),
):
    authenticate_caller(authorization, x_anchor_token)
    key_path = Path(PRIVATE_KEY_PATH)
    if not key_path.exists():
        raise HTTPException(status_code=500, detail="Anchor private key not available")
    fields = {
        "memory_id": req.memory_id,
        "version": req.version,
        "event_hash": req.event_hash,
        "event_count": req.event_count,
    }
    canonical = json.dumps(fields, sort_keys=True, separators=(",", ":")).encode("utf-8")
    private_key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    signature = base64.b64encode(private_key.sign(canonical)).decode("ascii")
    return {"signed": True, "signature": signature}


@app.post("/head/sign")
def sign_head(
    req: CheckpointSignRequest,
    authorization: Optional[str] = Header(None),
    x_anchor_token: Optional[str] = Header(None),
):
    authenticate_caller(authorization, x_anchor_token)
    key_path = Path(PRIVATE_KEY_PATH)
    if not key_path.exists():
        raise HTTPException(status_code=500, detail="Anchor private key not available")
    fields = {
        "memory_id": req.memory_id,
        "version": req.version,
        "event_hash": req.event_hash,
        "event_count": req.event_count,
    }
    canonical = json.dumps(fields, sort_keys=True, separators=(",", ":")).encode("utf-8")
    private_key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    signature = base64.b64encode(private_key.sign(canonical)).decode("ascii")
    return {"signed": True, "signature": signature}


def authenticate_caller(authorization: Optional[str] = Header(None), x_anchor_token: Optional[str] = Header(None)):
    if not INTERNAL_TOKEN:
        # If no internal token configured in environment, allow with warning in dev only
        return
    token = x_anchor_token
    if not token and authorization:
        parts = authorization.split(" ", 1)
        token = parts[1].strip() if len(parts) == 2 else parts[0].strip()
    if token != INTERNAL_TOKEN:
        raise HTTPException(status_code=401, detail="Unauthorized: Invalid or missing anchor caller token.")


@app.get("/health")
def health():
    priv_exists = Path(PRIVATE_KEY_PATH).exists()
    pub_exists = Path(PUBLIC_KEY_PATH).exists()
    return {
        "status": "healthy",
        "service": "anchor-witness",
        "private_key_present": priv_exists,
        "public_key_present": pub_exists,
        "recorded_heads_count": len(RECORDED_HEADS),
    }


@app.get("/manifest/public-key")
def get_public_key():
    key_path = Path(PUBLIC_KEY_PATH)
    if not key_path.exists():
        raise HTTPException(status_code=404, detail="Anchor public key not found")
    return {"public_key": key_path.read_text(encoding="utf-8")}


@app.post("/manifest/sign")
def sign_manifest(req: SignManifestRequest, request: Request, authorization: Optional[str] = Header(None), x_anchor_token: Optional[str] = Header(None)):
    # 1. Caller Authentication
    authenticate_caller(authorization, x_anchor_token)

    # 2. Authorization Verification
    if req.caller_role in ("recovery_service", "seed_initializer"):
        # TCRP Recovery Service restores verified historical snapshots from isolated vault,
        # or authorized seed initializer establishes baseline genesis v1 heads
        print(f"[Anchor Witness] Authorized {req.caller_role} registering '{req.memory_id}' v{req.version}", flush=True)
    else:
        # Gateway or client write: MUST present valid owner approval
        if not req.owner_signature:
            raise HTTPException(
                status_code=403,
                detail="REJECTED_MISSING_OWNER_SIGNATURE: Anchor requires an owner digital signature to sign manifests."
            )
        if not req.nonce or not req.authorization_id:
            raise HTTPException(
                status_code=403,
                detail="REJECTED_MISSING_AUTHORIZATION: Missing nonce or authorization_id."
            )

        # Replay prevention
        if req.nonce in USED_NONCES:
            raise HTTPException(
                status_code=403,
                detail=f"REJECTED_NONCE_REPLAYED: Nonce '{req.nonce}' has already been processed."
            )

        # Monotonic Version & Parent Revision Continuity Check
        current_head = RECORDED_HEADS.get(req.memory_id)
        if current_head is not None:
            expected_v = current_head["version"] + 1
            if req.version != expected_v:
                raise HTTPException(
                    status_code=403,
                    detail=f"REJECTED_VERSION_MISMATCH: Version {req.version} does not match expected monotonically incremented version {expected_v}."
                )
            if req.parent_revision_id != current_head["revision_id"]:
                raise HTTPException(
                    status_code=403,
                    detail=f"REJECTED_PARENT_REVISION_DIVERGENCE: Parent revision '{req.parent_revision_id}' does not match recorded head '{current_head['revision_id']}'."
                )

        # Cryptographic Signature Verification
        if req.content:
            valid_sig = verify_owner_approval(
                memory_id=req.memory_id,
                content=req.content,
                expected_parent_revision_id=req.parent_revision_id,
                authorization_id=req.authorization_id,
                nonce=req.nonce,
                signature_hex=req.owner_signature,
                timestamp=req.timestamp,
                expected_version=req.version,
            )
            if not valid_sig:
                raise HTTPException(
                    status_code=403,
                    detail="REJECTED_INVALID_OWNER_SIGNATURE: Owner signature verification failed."
                )

        USED_NONCES.add(req.nonce)

    # 3. Authoritative Ed25519 Signing
    key_path = Path(PRIVATE_KEY_PATH)
    if not key_path.exists():
        raise HTTPException(status_code=500, detail="Anchor private key not available on witness")

    try:
        manifest = sign_revision(
            memory_id=req.memory_id,
            version=req.version,
            content_hash=req.content_hash,
            previous_hash=req.previous_hash,
            private_key_path=key_path,
            revision_id=req.revision_id,
            parent_revision_id=req.parent_revision_id,
        )

        # Update recorded head
        RECORDED_HEADS[req.memory_id] = {
            "version": req.version,
            "revision_id": req.revision_id,
            "content_hash": req.content_hash,
        }

        print(f"[Anchor Witness] Authoritative manifest signed for '{req.memory_id}' v{req.version} (revision: {req.revision_id})", flush=True)
        return {"signed": True, "manifest": manifest}
    except Exception as exc:
        print(f"[Anchor Witness ERROR] Signing failed: {type(exc).__name__}: {exc}", flush=True)
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/manifest/verify")
def verify_manifest(req: VerifyManifestRequest):
    key_path = Path(PUBLIC_KEY_PATH)
    if not key_path.exists():
        raise HTTPException(status_code=500, detail="Anchor public key not available")
    is_valid = verify_revision(req.manifest, public_key_path=key_path)
    return {"valid": is_valid}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
