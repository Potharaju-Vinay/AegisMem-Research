"""
AegisMem Independent Anchor Witness Microservice
Listens on internal network to provide authoritative cryptographic manifests and signatures.
Holds the Anchor Private Key; other services verify using the Anchor Public Key.
"""
import os
import sys
from pathlib import Path
from typing import Optional
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

# Ensure repository root is on sys.path
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from core.integrity.anchor import sign_revision, verify_revision

app = FastAPI(title="AegisMem Anchor Witness Service", version="1.0.0")

PRIVATE_KEY_PATH = os.getenv("ANCHOR_PRIVATE_KEY_PATH", "security/keys/integrity_anchor_private.pem")
PUBLIC_KEY_PATH = os.getenv("ANCHOR_PUBLIC_KEY_PATH", "security/keys/integrity_anchor_public.pem")


class SignManifestRequest(BaseModel):
    memory_id: str
    version: int
    content_hash: str
    previous_hash: Optional[str] = None
    revision_id: str
    parent_revision_id: Optional[str] = None


class VerifyManifestRequest(BaseModel):
    manifest: dict


@app.get("/health")
def health():
    priv_exists = Path(PRIVATE_KEY_PATH).exists()
    pub_exists = Path(PUBLIC_KEY_PATH).exists()
    return {
        "status": "healthy",
        "service": "anchor-witness",
        "private_key_present": priv_exists,
        "public_key_present": pub_exists,
    }


@app.get("/manifest/public-key")
def get_public_key():
    key_path = Path(PUBLIC_KEY_PATH)
    if not key_path.exists():
        raise HTTPException(status_code=404, detail="Anchor public key not found")
    return {"public_key": key_path.read_text(encoding="utf-8")}


@app.post("/manifest/sign")
def sign_manifest(req: SignManifestRequest):
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

