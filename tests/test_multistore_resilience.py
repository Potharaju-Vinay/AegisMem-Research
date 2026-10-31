import pytest
from pathlib import Path
from unittest.mock import MagicMock

from core.memory.database import SessionLocal
from core.memory.models import MemoryRecord
from core.memory.repository import MemoryRepository
from core.recovery.vault import ReplicatedTrustVault
from core.recovery.resolver import TrustedVersionResolver
from core.recovery.executor import RecoveryExecutor
from core.recovery.models import RecoveryAction
from core.integrity.hash import calculate_version_hash
from core.integrity.manifest_store import IntegrityManifestStore


def test_vault_snapshot_ed25519_verification(tmp_path):
    vault = ReplicatedTrustVault(vault_dir=tmp_path / "vault")
    memory_id = "TEST-MEM-VAULT-001"
    content = "Original authentic enterprise policy content."
    content_hash = calculate_version_hash(content, None)

    # Save authentic snapshot
    snapshot_path = vault.save_snapshot(
        memory_id=memory_id,
        version=1,
        content=content,
        content_hash=content_hash,
        previous_hash=None,
        revision_id="rev-vault-001",
        authorization_signature="dummy-owner-auth",
        authorization_id="auth-001",
    )
    assert snapshot_path.exists()

    candidates = vault.get_candidates(memory_id)
    assert len(candidates) == 1
    snapshot = candidates[0]

    # Verify authentic snapshot passes Ed25519 & hash checks
    assert vault.verify_snapshot(snapshot) is True

    # Test tampering: if attacker modifies content in vault
    tampered_snapshot = dict(snapshot)
    tampered_snapshot["content"] = "MALICIOUS TAMPERED VAULT CONTENT"
    assert vault.verify_snapshot(tampered_snapshot) is False

    # Test tampering: if attacker modifies content_hash
    tampered_hash_snapshot = dict(snapshot)
    tampered_hash_snapshot["content_hash"] = "0000000000000000000000000000000000000000000000000000000000000000"
    assert vault.verify_snapshot(tampered_hash_snapshot) is False


def test_single_store_tampering_failure_without_vault():
    """
    Scenario A: Demonstrates the single-store research gap.
    When an attacker tampers with historical rows in local SQLite and no vault is configured,
    the resolver cannot find a trusted recovery point and rejects the corrupted history.
    """
    mock_repo = MagicMock()
    # Mock history: v1 (tampered content), v2 (attacked)
    rec_v1 = MagicMock(
        version=1,
        revision_id="rev-1",
        content="Tampered local database content",
        content_hash="invalid_hash_123",
        previous_hash=None,
        status="active",
        trust_score=0.9,
        suspicion_score=0.1,
    )
    rec_v2 = MagicMock(
        version=2,
        revision_id="rev-2",
        content="Attacked current state",
        content_hash="attack_hash_456",
        previous_hash="invalid_hash_123",
        status="active",
        trust_score=0.1,
        suspicion_score=0.9,
    )

    mock_repo.get_history.return_value = [rec_v1, rec_v2]
    mock_repo.get_version.side_effect = lambda m_id, v: rec_v1 if v == 1 else rec_v2

    resolver = TrustedVersionResolver(mock_repo, vault_store=None)
    evaluation = resolver.evaluate_candidates("TEST-MEM")

    assert evaluation["decision"] == "NO_TRUSTED_RECOVERY_POINT"
    assert evaluation["selected_version"] is None
    assert len(evaluation["candidates"]) == 1
    assert evaluation["candidates"][0]["status"] == "REJECTED_CANDIDATE"


def test_multistore_resilient_recovery_when_local_db_tampered(tmp_path):
    """
    Scenario B: Solves the research gap.
    When local SQLite historical version is tampered (k=1), but ReplicatedTrustVault
    maintains an independent cryptographically verified snapshot:
    1. Resolver queries the vault and accepts the verified candidate.
    2. Candidate is attributed to 'isolated_cryptographic_vault'.
    3. Resolver returns the clean candidate with 100% authentic content.
    """
    vault = ReplicatedTrustVault(vault_dir=tmp_path / "vault")
    memory_id = "ENT-RESILIENCE-001"
    clean_content = "All employees must use multi-factor authentication."
    clean_hash = calculate_version_hash(clean_content, None)

    # Save authentic snapshot into vault
    vault.save_snapshot(
        memory_id=memory_id,
        version=1,
        content=clean_content,
        content_hash=clean_hash,
        previous_hash=None,
        revision_id="rev-clean-1",
        authorization_signature="auth-sig-1",
        authorization_id="auth-id-1",
    )

    mock_repo = MagicMock()
    # Local DB has tampered v1 and attacked v2
    rec_v1_tampered = MagicMock(
        version=1,
        revision_id="rev-tampered-1",
        content="Tampered local db row by attacker",
        content_hash="bad_hash",
        previous_hash=None,
        status="active",
        trust_score=0.9,
        suspicion_score=0.1,
    )
    rec_v2_attacked = MagicMock(
        version=2,
        revision_id="rev-attacked-2",
        content="Attacked current state",
        content_hash="attacked_hash",
        previous_hash="bad_hash",
        status="active",
        trust_score=0.1,
        suspicion_score=0.9,
    )

    mock_repo.get_history.return_value = [rec_v1_tampered, rec_v2_attacked]
    mock_repo.get_version.side_effect = lambda m_id, v: rec_v1_tampered if v == 1 else rec_v2_attacked

    resolver = TrustedVersionResolver(mock_repo, vault_store=vault)
    evaluation = resolver.evaluate_candidates(memory_id)

    # Verified multi-store recovery succeeds!
    assert evaluation["decision"] == "TRUSTED_RECOVERY_POINT"
    assert evaluation["selected_version"] == 1
    assert evaluation["source_store"] == "isolated_cryptographic_vault"

    # Verify resolved record
    resolved_record = resolver.find_trusted_version(memory_id)
    assert resolved_record is not None
    assert resolved_record.version == 1
    assert resolved_record.content == clean_content
    assert resolved_record.content_hash == clean_hash


def test_all_stores_compromised_failsafe_quarantine(tmp_path):
    """
    Scenario C: Total store compromise (k=n).
    When both local database and vault are tampered:
    All candidates must be rejected, and the system must safely fail safe (zero wrong answers).
    """
    vault = ReplicatedTrustVault(vault_dir=tmp_path / "vault")
    memory_id = "ENT-TOTAL-COMPROMISE"

    # Save a snapshot, then tamper with the vault file directly on disk
    snap_path = vault.save_snapshot(
        memory_id=memory_id,
        version=1,
        content="Original content",
        content_hash=calculate_version_hash("Original content", None),
        previous_hash=None,
        revision_id="rev-1",
    )
    # Attacker tampers with the vault file on disk
    snap_path.write_text('{"store_domain": "isolated_cryptographic_vault", "memory_id": "ENT-TOTAL-COMPROMISE", "version": 1, "content": "FORGED VAULT CONTENT", "content_hash": "forged_hash", "signature": "forged_sig"}', encoding="utf-8")

    mock_repo = MagicMock()
    mock_repo.get_history.return_value = [
        MagicMock(version=1, content="Tampered DB", content_hash="bad", previous_hash=None, status="active", trust_score=0.9, suspicion_score=0.1),
        MagicMock(version=2, content="Attacked DB", content_hash="bad2", previous_hash="bad", status="active", trust_score=0.1, suspicion_score=0.9),
    ]

    resolver = TrustedVersionResolver(mock_repo, vault_store=vault)
    evaluation = resolver.evaluate_candidates(memory_id)

    # Must fail-safe: NO_TRUSTED_RECOVERY_POINT
    assert evaluation["decision"] == "NO_TRUSTED_RECOVERY_POINT"
    assert evaluation["selected_version"] is None
    assert resolver.find_trusted_version(memory_id) is None

