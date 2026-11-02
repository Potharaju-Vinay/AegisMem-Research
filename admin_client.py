#!/usr/bin/env python3
"""
AegisMem Admin Client
CLI utility for authorized enterprise staff to sign and submit authenticated memory updates.
Enforces Ed25519 cryptographic signatures, single-use nonces, and timestamp bounded windows.
"""

import argparse
import json
import os
import secrets
import sys
import time
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from core.security.owner_approval import (
    canonical_owner_approval,
    verify_owner_approval,
)
from core.security.owner_signing_client import (
    encode_json_body,
    load_signing_key,
    sign_http_request,
    sign_owner_approval,
)


def generate_keys(output_dir: str = "security/keys") -> tuple[Path, Path]:
    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    priv_path = out_path / "owner_private_key.pem"
    pub_path = out_path / "owner_public_key.pem"

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    priv_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    priv_path.write_bytes(priv_bytes)
    pub_path.write_bytes(pub_bytes)
    print(f"Generated Ed25519 keypair:\n  Private key: {priv_path}\n  Public key:  {pub_path}")
    return priv_path, pub_path


def sign_update(
    memory_id: str,
    content: str,
    expected_parent_revision_id: str | None = None,
    private_key_path: str = "security/keys/owner_private_key.pem",
    authorization_id: str | None = None,
    nonce: str | None = None,
    timestamp: int | None = None,
) -> dict:
    key = load_signing_key(private_key_path)
    auth_id = authorization_id or f"AUTH-STAFF-{secrets.token_hex(6).upper()}"
    auth_nonce = nonce or secrets.token_hex(16)
    ts = timestamp or int(time.time())

    signature = sign_owner_approval(
        private_key=key,
        memory_id=memory_id,
        content=content,
        authorization_id=auth_id,
        nonce=auth_nonce,
        expected_parent_revision_id=expected_parent_revision_id,
        timestamp=timestamp,
    )

    payload = {
        "memory_id": memory_id,
        "content": content,
        "expected_revision_id": expected_parent_revision_id,
        "authorization_id": auth_id,
        "nonce": auth_nonce,
        "timestamp": ts,
        "authorization_signature": signature,
    }
    return payload


def submit_update(
    url: str,
    memory_id: str,
    content: str,
    expected_parent_revision_id: str | None = None,
    private_key_path: str = "security/keys/owner_private_key.pem",
    request_key_path: str = "security/keys/owner_request_private_key.pem",
    owner_token: str | None = None,
) -> dict:
    import httpx

    if expected_parent_revision_id is None:
        try:
            with httpx.Client(timeout=5.0) as client:
                mem_resp = client.get(f"{url.rstrip('/')}/api/memories/{memory_id}")
                if mem_resp.status_code == 200:
                    expected_parent_revision_id = mem_resp.json().get("revision_id")
        except Exception as e:
            print(f"[Admin Client] Could not auto-fetch parent revision: {e}")

    # 1. Sign owner approval payload
    approval_payload = sign_update(
        memory_id=memory_id,
        content=content,
        expected_parent_revision_id=expected_parent_revision_id,
        private_key_path=private_key_path,
    )

    body_bytes = encode_json_body(approval_payload)
    path = "/owner/memory/write"

    # 2. Sign HTTP request
    req_key_file = Path(request_key_path) if Path(request_key_path).exists() else Path(private_key_path)
    req_key = load_signing_key(req_key_file)
    http_nonce = secrets.token_hex(16)
    auth_headers = sign_http_request(
        private_key=req_key,
        method="POST",
        path=path,
        body=body_bytes,
        nonce=http_nonce,
    )

    from core.security.owner_auth import load_owner_token
    token = owner_token or load_owner_token() or os.getenv("OWNER_BEARER_TOKEN") or "aegismem-owner-secret"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}",
        **auth_headers,
    }

    target_url = f"{url.rstrip('/')}{path}"
    with httpx.Client(timeout=10.0) as client:
        response = client.post(target_url, content=body_bytes, headers=headers)
        if response.status_code != 200:
            raise RuntimeError(f"Server rejected update ({response.status_code}): {response.text}")
        return response.json()


def main():
    parser = argparse.ArgumentParser(description="AegisMem Enterprise Admin Client")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # generate-keys
    gen_p = subparsers.add_parser("generate-keys", help="Generate Ed25519 keypair")
    gen_p.add_argument("--output-dir", default="security/keys")

    # sign
    sign_p = subparsers.add_parser("sign", help="Sign memory update payload")
    sign_p.add_argument("--memory-id", required=True)
    sign_p.add_argument("--content", required=True)
    sign_p.add_argument("--parent-revision", default=None)
    sign_p.add_argument("--key", default="security/keys/owner_private_key.pem")

    # submit
    sub_p = subparsers.add_parser("submit", help="Sign and submit update to gateway API")
    sub_p.add_argument("--url", default="http://localhost:8000")
    sub_p.add_argument("--memory-id", required=True)
    sub_p.add_argument("--content", required=True)
    sub_p.add_argument("--parent-revision", default=None)
    sub_p.add_argument("--key", default="security/keys/owner_private_key.pem")
    sub_p.add_argument("--request-key", default="security/keys/owner_request_private_key.pem")
    sub_p.add_argument("--token", default=None)

    args = parser.parse_args()

    if args.command == "generate-keys":
        generate_keys(args.output_dir)
    elif args.command == "sign":
        res = sign_update(
            memory_id=args.memory_id,
            content=args.content,
            expected_parent_revision_id=args.parent_revision,
            private_key_path=args.key,
        )
        print(json.dumps(res, indent=2))
    elif args.command == "submit":
        res = submit_update(
            url=args.url,
            memory_id=args.memory_id,
            content=args.content,
            expected_parent_revision_id=args.parent_revision,
            private_key_path=args.key,
            request_key_path=args.request_key,
            owner_token=args.token,
        )
        print("Update succeeded:\n", json.dumps(res, indent=2))


if __name__ == "__main__":
    main()
