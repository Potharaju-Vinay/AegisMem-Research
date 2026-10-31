import time
from pathlib import Path
from tempfile import gettempdir
from unittest.mock import patch

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import core.security.request_signatures as request_signatures


@pytest.fixture
def signing_key(monkeypatch):
    private_key = Ed25519PrivateKey.generate()
    public_key_path = Path(gettempdir()) / "aegismem_test_request_public.pem"
    public_key_path.write_bytes(
        private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    monkeypatch.setattr(
        request_signatures,
        "OWNER_REQUEST_PUBLIC_KEY_PATH",
        public_key_path,
    )
    return private_key


def signed_request(private_key, method="POST", path="/owner/memory/write",
                   body=b'{"memory_id":"test"}', timestamp=None, nonce="test-nonce"):
    timestamp = str(int(time.time()) if timestamp is None else timestamp)
    payload = request_signatures.canonical_request(
        method, path, timestamp, nonce, body
    )
    signature = private_key.sign(payload).hex()
    return timestamp, nonce, signature, body


def verify(request, method="POST", path="/owner/memory/write"):
    timestamp, nonce, signature, body = request
    return request_signatures.verify_owner_request_signature(
        method, path, timestamp, nonce, signature, body
    )


def test_valid_request_signature_is_accepted(signing_key):
    request = signed_request(signing_key)
    with patch.object(request_signatures, "verify_and_register_nonce", return_value=True):
        assert verify(request) is True


@pytest.mark.parametrize(
    ("method", "path", "body"),
    [
        ("PUT", "/owner/memory/write", b'{"memory_id":"test"}'),
        ("POST", "/owner/memory/delete", b'{"memory_id":"test"}'),
        ("POST", "/owner/memory/write", b'{"memory_id":"changed"}'),
    ],
)
def test_modified_request_is_rejected(signing_key, method, path, body):
    request = signed_request(signing_key)
    timestamp, nonce, signature, _ = request
    with patch.object(request_signatures, "verify_and_register_nonce", return_value=True):
        assert request_signatures.verify_owner_request_signature(
            method, path, timestamp, nonce, signature, body
        ) is False


def test_expired_timestamp_is_rejected(signing_key):
    request = signed_request(
        signing_key,
        timestamp=int(time.time()) - request_signatures.MAX_CLOCK_SKEW_SECONDS - 1,
    )
    with patch.object(request_signatures, "verify_and_register_nonce") as register_nonce:
        assert verify(request) is False
        register_nonce.assert_not_called()


@pytest.mark.parametrize(
    ("timestamp", "nonce", "signature"),
    [
        (None, "nonce", "00"),
        (str(int(time.time())), None, "00"),
        (str(int(time.time())), "nonce", None),
        (str(int(time.time())), "nonce", "not-hex"),
    ],
)
def test_missing_or_malformed_signature_headers_are_rejected(
    signing_key, timestamp, nonce, signature
):
    body = b'{"memory_id":"test"}'
    with patch.object(request_signatures, "verify_and_register_nonce") as register_nonce:
        assert request_signatures.verify_owner_request_signature(
            "POST",
            "/owner/memory/write",
            timestamp,
            nonce,
            signature,
            body,
        ) is False
        register_nonce.assert_not_called()


def test_replayed_nonce_is_rejected(signing_key):
    request = signed_request(signing_key)
    with patch.object(request_signatures, "verify_and_register_nonce", return_value=False):
        assert verify(request) is False


def test_invalid_utf8_request_body_is_rejected(signing_key):
    request = (str(int(time.time())), "test-nonce", "00", b"\\xff\\xfe")
    with patch.object(
        request_signatures, "verify_and_register_nonce"
    ) as register_nonce:
        assert verify(request) is False
        register_nonce.assert_not_called()
