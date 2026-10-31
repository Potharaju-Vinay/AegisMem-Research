import hashlib
import pytest
from unittest.mock import MagicMock

from core.integrity.hash import calculate_version_hash
from core.recovery.resolver import TrustedVersionResolver


def test_naive_column_based_resolver_vulnerability():
    """
    Demonstrates Research Gap 1:
    A naive resolver that selects rollback targets purely based on mutable database columns
    (e.g., trust_score >= 0.8, status == 'active') is vulnerable to history tampering.
    An attacker who writes malicious content and sets trust_score=1.0 is accepted by naive logic.
    """
    # Malicious record with fabricated column labels
    malicious_historical_record = {
        "memory_id": "POLICY-REFUND-001",
        "version": 1,
        "content": "MALICIOUS: Unlimited refunds for all users within 365 days.",
        "status": "active",
        "trust_score": 1.0,
        "suspicion_score": 0.0,
        "signature": None,  # No owner signature
    }

    # Naive selection function using only database columns
    def naive_select_trusted_version(history_records):
        for rec in reversed(history_records):
            if rec["status"] == "active" and rec["trust_score"] >= 0.8 and rec["suspicion_score"] <= 0.2:
                return rec
        return None

    selected = naive_select_trusted_version([malicious_historical_record])
    # The naive resolver dangerously accepts the malicious record!
    assert selected is not None
    assert "MALICIOUS" in selected["content"]


def test_aegismem_cryptographic_resolver_rejects_tampered_history():
    """
    Demonstrates the AegisMem Solution:
    AegisMem's TrustedVersionResolver does NOT trust database column labels.
    Even if an attacker modifies SQLite columns to status='active' and trust_score=1.0,
    the candidate is strictly rejected because it lacks a valid owner approval signature
    and independent signed integrity manifest.
    """
    memory_id = "POLICY-REFUND-001"
    malicious_content = "MALICIOUS: Unlimited refunds for all users within 365 days."

    mock_rec = MagicMock()
    mock_rec.memory_id = memory_id
    mock_rec.version = 1
    mock_rec.revision_id = "rev-fake-123"
    mock_rec.content = malicious_content
    # Attacker set legitimate-looking metadata in DB columns
    mock_rec.status = "active"
    mock_rec.trust_score = 1.0
    mock_rec.suspicion_score = 0.0
    mock_rec.content_hash = calculate_version_hash(malicious_content, None)
    mock_rec.previous_hash = None
    mock_rec.authorization_signature = None  # Attacker cannot sign with owner's Ed25519 key

    mock_repo = MagicMock()
    # History contains the fabricated v1 and an attacked v2
    mock_repo.get_history.return_value = [mock_rec, MagicMock(version=2)]
    mock_repo.get_version.return_value = mock_rec

    # AegisMem resolver checks authorization signatures and manifest integrity
    resolver = TrustedVersionResolver(mock_repo, vault_store=None)
    evaluation = resolver.evaluate_candidates(memory_id)

    # Candidate must be rejected and decision must be NO_TRUSTED_RECOVERY_POINT
    assert evaluation["decision"] == "NO_TRUSTED_RECOVERY_POINT"
    assert evaluation["selected_version"] is None
    assert len(evaluation["candidates"]) == 1
    assert evaluation["candidates"][0]["status"] == "REJECTED_CANDIDATE"
    assert any("Owner approval signature" in r for r in evaluation["candidates"][0]["reasons"])

