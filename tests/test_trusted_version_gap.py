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
    malicious_historical_record = {
        "memory_id": "POLICY-REFUND-001",
        "version": 1,
        "content": "MALICIOUS: Unlimited refunds for all users within 365 days.",
        "status": "active",
        "trust_score": 1.0,
        "suspicion_score": 0.0,
        "signature": None,
    }

    def naive_select_trusted_version(history_records):
        for rec in reversed(history_records):
            if rec["status"] == "active" and rec["trust_score"] >= 0.8 and rec["suspicion_score"] <= 0.2:
                return rec
        return None

    selected = naive_select_trusted_version([malicious_historical_record])
    assert selected is not None
    assert "MALICIOUS" in selected["content"]


def test_attack_a_undetected_malicious_ancestor_rejected():
    """
    Attack A: Undetected Malicious Ancestor
    An attacker with direct database access injects an illegitimate ancestor v1
    with fabricated active labels (trust_score=1.0, status='active').
    AegisMem's verify-before-restore strictly rejects this candidate because it lacks
    a valid cryptographic owner approval signature.
    """
    memory_id = "POLICY-REFUND-001"
    malicious_content = "MALICIOUS: Unlimited refunds for all users within 365 days."

    mock_rec = MagicMock()
    mock_rec.memory_id = memory_id
    mock_rec.version = 1
    mock_rec.revision_id = "rev-attack-a"
    mock_rec.content = malicious_content
    mock_rec.status = "active"
    mock_rec.trust_score = 1.0
    mock_rec.suspicion_score = 0.0
    mock_rec.content_hash = calculate_version_hash(malicious_content, None)
    mock_rec.previous_hash = None
    mock_rec.authorization_signature = None

    mock_repo = MagicMock()
    mock_repo.get_history.return_value = [mock_rec, MagicMock(version=2)]
    mock_repo.get_version.return_value = mock_rec

    resolver = TrustedVersionResolver(mock_repo, vault_store=None)
    evaluation = resolver.evaluate_candidates(memory_id)

    assert evaluation["decision"] == "NO_TRUSTED_RECOVERY_POINT"
    assert evaluation["selected_version"] is None
    assert len(evaluation["candidates"]) == 1
    assert evaluation["candidates"][0]["status"] == "REJECTED_CANDIDATE"
    assert any("Owner approval signature" in r for r in evaluation["candidates"][0]["reasons"])


def test_attack_b_rewritten_history_with_recomputed_hashes_rejected():
    """
    Attack B: History Rewrite with Recomputed Hashes
    An attacker modifies historical v1 content and recomputes the SHA-256 hash chain
    for subsequent revisions so that unkeyed hash chaining appears internally consistent.
    AegisMem's resolver verifies each candidate against out-of-band signed integrity manifests
    and anchor attestations. Because the attacker cannot forge the anchor's Ed25519 signature
    over the recomputed hash, the rewrite is detected and rejected.
    """
    memory_id = "POLICY-RETURNS-001"

    # Attacker modified v1 content and recomputed hashes
    tampered_v1_content = "MALICIOUS: Returns accepted for 365 days without receipt"
    v1_hash = calculate_version_hash(tampered_v1_content, None)

    v1_rec = MagicMock()
    v1_rec.memory_id = memory_id
    v1_rec.version = 1
    v1_rec.revision_id = "rev-v1"
    v1_rec.content = tampered_v1_content
    v1_rec.content_hash = v1_hash
    v1_rec.previous_hash = None
    v1_rec.status = "active"
    v1_rec.trust_score = 1.0
    v1_rec.suspicion_score = 0.0

    v2_content = "Follow up revision"
    v2_hash = calculate_version_hash(v2_content, v1_hash)
    v2_rec = MagicMock()
    v2_rec.memory_id = memory_id
    v2_rec.version = 2
    v2_rec.revision_id = "rev-v2"
    v2_rec.content = v2_content
    v2_rec.content_hash = v2_hash
    v2_rec.previous_hash = v1_hash

    mock_repo = MagicMock()
    mock_repo.get_history.return_value = [v1_rec, v2_rec]
    mock_repo.get_version.side_effect = lambda m_id, v: v1_rec if v == 1 else v2_rec

    # Manifest store verification fails because the manifest contains the original legitimate hash
    mock_manifest_store = MagicMock()
    mock_manifest_store.has_manifest.return_value = True
    # The manifest signature verification fails for the rewritten content hash
    mock_manifest_store.verify_record.return_value = False

    resolver = TrustedVersionResolver(mock_repo, manifest_store=mock_manifest_store, vault_store=None)
    evaluation = resolver.evaluate_candidates(memory_id)

    assert evaluation["decision"] == "NO_TRUSTED_RECOVERY_POINT"
    assert evaluation["selected_version"] is None
    assert evaluation["candidates"][0]["status"] == "REJECTED_CANDIDATE"
    assert evaluation["candidates"][0]["checks"]["integrity_manifest"] is False
