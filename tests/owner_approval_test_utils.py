from pathlib import Path
from tempfile import gettempdir

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from core.security.owner_approval import canonical_owner_approval

TEST_PRIVATE_KEY = Ed25519PrivateKey.generate()
TEST_PUBLIC_KEY_PATH = Path(gettempdir()) / "aegismem_test_owner_approval_public.pem"

TEST_PUBLIC_KEY_PATH.write_bytes(
    TEST_PRIVATE_KEY.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
)


def sign_test_approval(
    memory_id,
    content,
    authorization_id,
    nonce,
    expected_parent_revision_id=None,
):
    payload = canonical_owner_approval(
        memory_id=memory_id,
        content=content,
        expected_parent_revision_id=expected_parent_revision_id,
        authorization_id=authorization_id,
        nonce=nonce,
    )
    return TEST_PRIVATE_KEY.sign(payload).hex()

import core.security.owner_approval as _owner_approval
_owner_approval.OWNER_APPROVAL_PUBLIC_KEY_PATH = TEST_PUBLIC_KEY_PATH

