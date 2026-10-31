import json
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import core.security.request_signatures as request_signatures
from core.security.owner_signing_client import (
    encode_json_body,
    sign_http_request,
    sign_owner_approval,
)


def test_owner_approval_signature_matches_server_verifier(monkeypatch, tmp_path):
    import core.security.owner_approval as owner_approval

    private_key = Ed25519PrivateKey.generate()
    public_key_path = tmp_path / "owner-public.pem"
    from cryptography.hazmat.primitives import serialization

    public_key_path.write_bytes(
        private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    monkeypatch.setattr(
        owner_approval, "OWNER_APPROVAL_PUBLIC_KEY_PATH", public_key_path
    )

    signature = sign_owner_approval(
        private_key,
        memory_id="CLIENT-TEST-001",
        content="Approved content",
        authorization_id="AUTH-001",
        nonce="NONCE-001",
    )

    assert owner_approval.verify_owner_approval(
        memory_id="CLIENT-TEST-001",
        content="Approved content",
        expected_parent_revision_id=None,
        authorization_id="AUTH-001",
        nonce="NONCE-001",
        signature_hex=signature,
    )


def test_http_signature_matches_server_verifier(monkeypatch, tmp_path):
    private_key = Ed25519PrivateKey.generate()
    public_key_path = tmp_path / "request-public.pem"
    from cryptography.hazmat.primitives import serialization

    public_key_path.write_bytes(
        private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    monkeypatch.setattr(
        request_signatures, "OWNER_REQUEST_PUBLIC_KEY_PATH", public_key_path
    )
    monkeypatch.setattr(
        request_signatures, "verify_and_register_nonce", lambda *args, **kwargs: True
    )

    body = encode_json_body({"memory_id": "CLIENT-TEST-001", "content": "Hello"})
    headers = sign_http_request(
        private_key,
        method="POST",
        path="/owner/memory/write",
        body=body,
        nonce="REQUEST-NONCE-001",
        timestamp=int(time.time()),
    )

    assert request_signatures.verify_owner_request_signature(
        "POST",
        "/owner/memory/write",
        headers["X-Owner-Timestamp"],
        headers["X-Owner-Nonce"],
        headers["X-Owner-Signature"],
        body,
    )


def test_json_body_encoding_is_utf8_and_compact():
    body = encode_json_body({"message": "café", "count": 2})
    assert body == json.dumps(
        {"message": "café", "count": 2},
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def test_http_signing_rejects_invalid_inputs():
    private_key = Ed25519PrivateKey.generate()

    try:
        sign_http_request(
            private_key, "POST", "/test", b"{}", "", timestamp=1
        )
        assert False, "Empty nonce should be rejected"
    except ValueError:
        pass

    try:
        sign_http_request(
            private_key, "POST", "/test", "not-bytes", "nonce", timestamp=1
        )
        assert False, "Non-byte body should be rejected"
    except TypeError:
        pass

def test_signing_rejects_non_ed25519_key():
    from cryptography.hazmat.primitives.asymmetric.rsa import (
        generate_private_key,
    )
    from core.security.owner_signing_client import sign_owner_approval

    rsa_key = generate_private_key(public_exponent=65537, key_size=2048)

    try:
        sign_owner_approval(
            rsa_key,
            memory_id="M-1",
            content="content",
            authorization_id="A-1",
            nonce="N-1",
        )
        assert False, "Non-Ed25519 key should be rejected"
    except TypeError:
        pass


def test_http_signing_rejects_invalid_paths_and_methods():
    private_key = Ed25519PrivateKey.generate()

    invalid_inputs = [
        ("", "/test"),
        ("POST", "https://example.com/test"),
        ("POST", "/test?admin=true"),
        ("POST", "/test#fragment"),
        ("POST", "/test\nforged"),
    ]

    for method, path in invalid_inputs:
        try:
            sign_http_request(
                private_key,
                method=method,
                path=path,
                body=b"{}",
                nonce="NONCE-1",
                timestamp=100,
            )
            assert False, f"Invalid method/path accepted: {method!r}, {path!r}"
        except ValueError:
            pass


def test_http_signing_rejects_invalid_timestamp_types():
    private_key = Ed25519PrivateKey.generate()

    for timestamp in (True, 1.5, "123"):
        try:
            sign_http_request(
                private_key,
                method="POST",
                path="/test",
                body=b"{}",
                nonce="NONCE-1",
                timestamp=timestamp,
            )
            assert False, f"Invalid timestamp accepted: {timestamp!r}"
        except TypeError:
            pass
