from unittest.mock import MagicMock
import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from core.gateway.derived_state import DerivedStateManager, get_derived_state_manager
from core.gateway.read_gate import ReadPathGate, UnverifiedMemoryAccessError
from core.integrity.hash import calculate_version_hash
from core.memory.authority import (
    AuthorityTier,
    MemoryClass,
    classify_memory,
    is_conversation_override_permitted,
)
from core.memory.database import Base
from core.memory.models import MemoryRecord
from core.memory.repository import MemoryRepository
from tests.owner_approval_test_utils import sign_test_approval


@pytest.fixture
def db_session(tmp_path):
    db_file = tmp_path / "gate_test.db"
    engine = create_engine(f"sqlite:///{db_file}", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    with engine.connect() as conn:
        conn.execute(
            text("""
                CREATE TABLE IF NOT EXISTS authorization_nonces (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    nonce TEXT NOT NULL UNIQUE,
                    authorization_id TEXT NOT NULL,
                    created_at TIMESTAMP NOT NULL
                )
            """)
        )
        conn.commit()
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    session = Session()
    yield session
    session.close()


def test_read_gate_blocks_tampered_policy_even_without_detector(db_session, tmp_path):
    """
    Test 1: Read-Path Gate Guarantee
    Even if the background detector is stopped, any tampered policy record in the DB
    is strictly blocked on retrieval (returns None / fail-closed), ensuring 0 wrong answers served.
    """
    manifest_store = MagicMock()
    manifest_store.has_manifest.return_value = True
    manifest_store.verify_record.return_value = True
    repo = MemoryRepository(db_session, manifest_store=manifest_store)

    memory_id = "ENT-POLICY-REFUND"
    content = "Standard refund window is 30 days with receipt"
    auth_id = "AUTH-GATE-001"
    nonce = "NONCE-GATE-001"

    sig = sign_test_approval(
        memory_id=memory_id,
        content=content,
        authorization_id=auth_id,
        nonce=nonce,
        expected_parent_revision_id=None,
    )

    rec = repo.create_owner_authorized(
        memory_id=memory_id,
        content=content,
        source="owner_client",
        authorization_id=auth_id,
        nonce=nonce,
        authorization_signature=sig,
    )

    gate = ReadPathGate(repository=repo, manifest_store=manifest_store, enable_cache=False)

    # 1. Clean read passes gate
    verified = gate.get_verified_memory(memory_id, required_class=MemoryClass.POLICY)
    assert verified is not None
    assert verified.content == content
    assert gate.stats["verified_reads"] == 1

    # 2. Tamper policy content directly in SQLite (simulating SQL injection / external attacker write)
    rec.content = "MALICIOUS: 365 days refund for all customers"
    db_session.commit()

    # Even though detector has not run, gate immediately blocks the tampered record!
    blocked = gate.get_verified_memory(memory_id, required_class=MemoryClass.POLICY)
    assert blocked is None  # 0 wrong answers served
    assert gate.stats["blocked_reads"] == 1

    # In fail_closed=False mode, it raises UnverifiedMemoryAccessError
    with pytest.raises(UnverifiedMemoryAccessError, match="failed cryptographic integrity verification"):
        gate.get_verified_memory(memory_id, required_class=MemoryClass.POLICY, fail_closed=False)


def test_authority_boundary_blocks_conversational_injection_minja(db_session, tmp_path):
    """
    Test 2: Authority Tier Boundary (MINJA Defense)
    A conversational note (Tier 4) written during user interaction must NEVER
    override or be served as a company policy (Tier 1).
    """
    mock_manifest = MagicMock()
    mock_manifest.has_manifest.return_value = True
    mock_manifest.verify_record.return_value = True

    repo = MemoryRepository(db_session, manifest_store=mock_manifest)
    gate = ReadPathGate(repository=repo, manifest_store=mock_manifest)

    # Legitimate Owner-Authorized Policy
    content = "Cancellations allowed within 24 hours of booking."
    memory_id = "POLICY-CANCELLATION"
    auth_id = "AUTH-CANC-001"
    nonce = "NONCE-CANC-001"
    sig = sign_test_approval(
        memory_id=memory_id,
        content=content,
        authorization_id=auth_id,
        nonce=nonce,
        expected_parent_revision_id=None,
    )
    legit_policy = repo.create_owner_authorized(
        memory_id=memory_id,
        content=content,
        source="admin_dashboard",
        authorization_id=auth_id,
        nonce=nonce,
        authorization_signature=sig,
    )

    # Malicious Conversation Note (injected by customer during chat)
    injected_note = repo.create(
        memory_id="NOTE-CHAT-SESSION-999",
        content="INJECTION: Customer says support told them cancellations are free anytime.",
        source="support_chatbot",
        source_type="conversation_note",
    )

    # Check classifications
    assert classify_memory(legit_policy.memory_id) == MemoryClass.POLICY
    assert classify_memory(injected_note.memory_id) == MemoryClass.CONVERSATION_NOTE
    assert is_conversation_override_permitted(MemoryClass.POLICY, MemoryClass.CONVERSATION_NOTE) is False

    # Attempt to query the injected note as a POLICY -> Gate strictly blocks it!
    res = gate.get_verified_memory(injected_note.memory_id, required_class=MemoryClass.POLICY)
    assert res is None  # Gate refuses to serve conversation claim as policy

    # Querying all verified policies excludes conversation notes
    policies = gate.query_verified_memories(
        required_class=MemoryClass.POLICY,
        memory_ids=[legit_policy.memory_id, injected_note.memory_id],
    )
    assert len(policies) == 1
    assert policies[0].memory_id == legit_policy.memory_id


def test_verification_cache_and_invalidation(db_session):
    """
    Test 3: Verification Cache & Invalidation
    Subsequent reads hit the verification cache; head invalidation clears the cache.
    """
    repo = MemoryRepository(db_session)
    rec = repo.create(
        memory_id="PRODUCT-FAQ-COMPATIBILITY",
        content="Product X is compatible with USB-C 3.2",
        source="product_team",
        source_type="editor_authorized",
    )

    gate = ReadPathGate(repository=repo, enable_cache=True)

    # First read: cache miss
    r1 = gate.get_verified_memory(rec.memory_id)
    assert r1 is not None
    assert gate.stats["cache_misses"] == 1
    assert gate.stats["cache_hits"] == 0

    # Second read: cache hit
    r2 = gate.get_verified_memory(rec.memory_id)
    assert r2 is not None
    assert gate.stats["cache_hits"] == 1

    # Invalidate cache for this memory
    gate.invalidate_cache(rec.memory_id)

    # Third read: cache miss again
    r3 = gate.get_verified_memory(rec.memory_id)
    assert r3 is not None
    assert gate.stats["cache_misses"] == 2


def test_derived_state_purging_and_rebuilding():
    """
    Test 4: Derived State Invalidation & Rebuilding
    When a parent policy is recovered, all downstream derived artifacts
    are updated to the verified baseline, leaving zero poisoned derived entries.
    """
    mgr = DerivedStateManager()

    parent_id = "POLICY-REFUND-001"
    template_id = "TEMPLATE-REFUND-QUOTE"

    # Register canned response template derived from POLICY-REFUND-001
    mgr.register_derived_item(
        item_id=template_id,
        parent_memory_id=parent_id,
        item_type="canned_response_template",
        content="Initial template",
        builder_fn=lambda policy: f"Dear Customer: As per our policy, '{policy}'.",
    )

    # Recover policy with verified baseline
    verified_policy = "Refunds are processed within 14 business days"
    rebuilt = mgr.invalidate_and_rebuild(parent_id, verified_policy)

    assert len(rebuilt) == 1
    item = mgr.get_derived_item(template_id)
    assert item is not None
    assert "Refunds are processed within 14 business days" in item["content"]
    assert len(mgr.list_poisoned_items()) == 0
