
from core.integrity.hasher import MemoryHasher
from core.integrity.verifier import IntegrityVerifier


def test_memory_integrity():

    memory_id = "M001"
    content = "Refunds are allowed within 30 days."
    source = "finance_policy"
    source_type = "enterprise_policy"

    original_hash = MemoryHasher.hash_memory(
        memory_id,
        content,
        source,
        source_type
    )

    verifier = IntegrityVerifier()

    result = verifier.verify(
        memory_id,
        content,
        source,
        source_type,
        original_hash
    )

    assert result.valid is True
    assert result.expected_hash == result.observed_hash


def test_tampered_memory_is_detected():

    memory_id = "M001"
    original_content = "Refunds are allowed within 30 days."

    original_hash = MemoryHasher.hash_memory(
        memory_id,
        original_content,
        "finance_policy",
        "enterprise_policy"
    )

    tampered_content = (
        "Refunds are allowed within 90 days."
    )

    verifier = IntegrityVerifier()

    result = verifier.verify(
        memory_id,
        tampered_content,
        "finance_policy",
        "enterprise_policy",
        original_hash
    )

    assert result.valid is False
    assert result.expected_hash != result.observed_hash
