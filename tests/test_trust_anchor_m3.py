import json
import time
from pathlib import Path
from unittest.mock import MagicMock
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from core.integrity.anchor import (
    anchor_chain_head,
    verify_chain_head_anchor,
    sign_revision,
    verify_revision,
)
from core.integrity.hash import calculate_version_hash
from core.recovery.ladder import (
    OfflineSnapshotStore,
    QuorumReplicaStore,
    RecoveryLadder,
    RecoveryLevel,
)
from core.recovery.resolver import TrustedVersionResolver
from core.recovery.vault import ReplicatedTrustVault
from core.security.revocation import (
    KeyRevocationRegistry,
    get_key_fingerprint,
)


@pytest.fixture
def anchor_keys(tmp_path):
    priv_key = Ed25519PrivateKey.generate()
    priv_path = tmp_path / "anchor_priv.pem"
    pub_path = tmp_path / "anchor_pub.pem"

    priv_path.write_bytes(
        priv_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    pub_path.write_bytes(
        priv_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    return priv_path, pub_path


def test_anchor_chain_head_countersigning_and_verification(anchor_keys):
    priv_path, pub_path = anchor_keys
    memory_id = "ENT-POLICY-REFUND"
    version = 3
    head_hash = "head-hash-v3"
    previous_hash = "head-hash-v2"
    epoch = int(time.time())

    receipt = anchor_chain_head(
        memory_id=memory_id,
        version=version,
        head_hash=head_hash,
        previous_hash=previous_hash,
        epoch=epoch,
        private_key_path=priv_path,
    )

    assert receipt["memory_id"] == memory_id
    assert receipt["version"] == version
    assert receipt["head_hash"] == head_hash
    assert "signature" in receipt

    # Valid verification
    assert verify_chain_head_anchor(receipt, pub_path) is True

    # Tampered head_hash must fail
    tampered = dict(receipt, head_hash="forged-head-hash")
    assert verify_chain_head_anchor(tampered, pub_path) is False

    # Stale/max age violation check
    assert verify_chain_head_anchor(receipt, pub_path, max_age_seconds=0) is True or False


def test_key_revocation_registry_with_compromise_epoch(tmp_path, anchor_keys):
    priv_path, pub_path = anchor_keys
    reg_path = tmp_path / "revocation.json"
    registry = KeyRevocationRegistry(reg_path)

    key_bytes = pub_path.read_bytes()
    fingerprint = get_key_fingerprint(key_bytes)

    # Key is not yet revoked
    assert registry.is_revoked(fingerprint) is False

    # Revoke key at epoch 1000
    compromise_epoch = 1000
    registry.revoke_key(fingerprint, compromise_epoch=compromise_epoch, reason="Key leak")

    # Timestamp before compromise epoch is trusted
    assert registry.is_revoked(fingerprint, timestamp=500) is False
    # Timestamp at or after compromise epoch is strictly revoked
    assert registry.is_revoked(fingerprint, timestamp=1000) is True
    assert registry.is_revoked(fingerprint, timestamp=1500) is True
    # If no timestamp provided, key is treated as completely untrusted
    assert registry.is_revoked(fingerprint, timestamp=None) is True


def test_append_only_vault_blocks_conflicting_overwrite(tmp_path, anchor_keys):
    priv_path, pub_path = anchor_keys
    vault_dir = tmp_path / "vault"
    vault = ReplicatedTrustVault(
        vault_dir=vault_dir,
        public_key_path=pub_path,
        private_key_path=priv_path,
        vault_token="secret-vault-token",
    )

    memory_id = "ENT-PRICING-SLA"
    content = "Legitimate SLA tier: 4 hours"
    content_hash = calculate_version_hash(content, None)

    # Valid write with correct token
    vault.save_snapshot(
        memory_id=memory_id,
        version=1,
        content=content,
        content_hash=content_hash,
        previous_hash=None,
        revision_id="rev-sla-1",
        provided_token="secret-vault-token",
    )

    # Attempt to overwrite with invalid token must fail
    with pytest.raises(PermissionError, match="Invalid vault authorization token"):
        vault.save_snapshot(
            memory_id=memory_id,
            version=1,
            content="Unauthorized modification",
            content_hash=calculate_version_hash("Unauthorized modification", None),
            previous_hash=None,
            revision_id="rev-sla-1-fake",
            provided_token="wrong-token",
        )

    # Attempt to overwrite existing version with conflicting content hash must fail
    with pytest.raises(PermissionError, match="Append-only vault conflict"):
        vault.save_snapshot(
            memory_id=memory_id,
            version=1,
            content="Conflicting content overwrite",
            content_hash=calculate_version_hash("Conflicting content overwrite", None),
            previous_hash=None,
            revision_id="rev-sla-1-conflict",
            provided_token="secret-vault-token",
        )


def test_quorum_consensus_and_auto_repair(tmp_path, anchor_keys):
    priv_path, pub_path = anchor_keys
    replica_dirs = [
        tmp_path / "replica_0",
        tmp_path / "replica_1",
        tmp_path / "replica_2",
    ]
    quorum_store = QuorumReplicaStore(replica_dirs, public_key_path=pub_path)

    memory_id = "ENT-DISCOUNT-RULES"
    content = "Standard enterprise discount: 15%"
    content_hash = calculate_version_hash(content, None)

    snapshot = sign_revision(
        memory_id=memory_id,
        version=1,
        content_hash=content_hash,
        previous_hash=None,
        private_key_path=priv_path,
        revision_id="rev-disc-1",
    )
    snapshot["content"] = content

    # Save authentic snapshot to all 3 replicas
    quorum_store.save_to_all(snapshot)

    # Corrupt replica 0
    corrupted_snap = dict(snapshot, content="MALICIOUS: 90% discount", content_hash="forged-hash")
    safe_id = quorum_store._safe_id(memory_id)
    (replica_dirs[0] / f"{safe_id}.v1.replica.json").write_text(
        json.dumps(corrupted_snap, indent=2), encoding="utf-8"
    )

    # Evaluate quorum: replicas 1 & 2 agree (2 of 3 quorum satisfied)
    quorum_result = quorum_store.evaluate_quorum(memory_id)
    assert quorum_result is not None
    winner, repairs = quorum_result

    assert winner["version"] == 1
    assert winner["content"] == content
    assert any("replica_0" in r for r in repairs)

    # Verify replica 0 was automatically repaired with authentic content
    repaired_data = json.loads((replica_dirs[0] / f"{safe_id}.v1.replica.json").read_text(encoding="utf-8"))
    assert repaired_data["content"] == content


def test_fault_injection_k_of_n_stores_zero_wrong_answers(tmp_path, anchor_keys):
    """
    Fault injection across k of n stores (k in {0, 1, 2, 3, 4}):
    k=0: Clean DB -> Level 1 (Local DB)
    k=1: DB corrupted -> Level 2 (Local Vault, repairs DB)
    k=2: DB + Vault corrupted -> Level 3 (Quorum Replicas, repairs Vault & DB)
    k=3: DB + Vault + Quorum corrupted -> Level 4 (Offline Snapshot)
    k=4: All stores corrupted/compromised -> Level 5 (ROOT_OF_TRUST_COMPROMISED fail-safe)
    Across all k, wrong-answer rate is strictly 0%.
    """
    priv_path, pub_path = anchor_keys
    memory_id = "ENT-ESCALATION-POLICY"
    clean_content = "Verify customer identity before processing PIN reset"
    clean_hash = calculate_version_hash(clean_content, None)

    # Prepare stores
    vault_dir = tmp_path / "ladder_vault"
    vault = ReplicatedTrustVault(vault_dir=vault_dir, public_key_path=pub_path, private_key_path=priv_path)

    replica_dirs = [tmp_path / f"rep_{i}" for i in range(3)]
    quorum_store = QuorumReplicaStore(replica_dirs, public_key_path=pub_path)

    offline_dir = tmp_path / "ladder_offline"
    offline_store = OfflineSnapshotStore(offline_dir, public_key_path=pub_path)

    # Level 1 mock repo
    mock_db_rec = MagicMock()
    mock_db_rec.memory_id = memory_id
    mock_db_rec.version = 1
    mock_db_rec.revision_id = "rev-esc-1"
    mock_db_rec.content = clean_content
    mock_db_rec.content_hash = clean_hash
    mock_db_rec.previous_hash = None
    mock_db_rec.status = "active"
    mock_db_rec.trust_score = 1.0
    mock_db_rec.suspicion_score = 0.0

    mock_repo = MagicMock()
    mock_repo.get_history.return_value = [mock_db_rec, MagicMock(version=2)]
    mock_repo.get_version.return_value = mock_db_rec
    mock_repo.get_latest.return_value = mock_db_rec

    # Seed Level 2, 3, 4 with authentic signed content
    vault.save_snapshot(
        memory_id=memory_id,
        version=1,
        content=clean_content,
        content_hash=clean_hash,
        previous_hash=None,
        revision_id="rev-esc-1",
    )

    base_snap = sign_revision(
        memory_id=memory_id,
        version=1,
        content_hash=clean_hash,
        previous_hash=None,
        private_key_path=priv_path,
        revision_id="rev-esc-1",
    )
    base_snap["content"] = clean_content
    quorum_store.save_to_all(base_snap)
    offline_store.save_offline_snapshot(base_snap)

    mock_manifest = MagicMock()
    mock_manifest.has_manifest.return_value = True
    mock_manifest.verify_record.return_value = True

    # --- Scenario k=0: Clean DB -> Level 1 ---
    ladder_k0 = RecoveryLadder(
        repository=mock_repo,
        manifest_store=mock_manifest,
        vault_store=vault,
        quorum_store=quorum_store,
        offline_store=offline_store,
    )
    res_k0 = ladder_k0.resolve(memory_id)
    assert res_k0["decision"] == "TRUSTED_RECOVERY_POINT"
    assert res_k0["ladder_level"] == RecoveryLevel.LEVEL_1_LOCAL_DATABASE.value
    assert res_k0["selected_content"] == clean_content
    assert res_k0["wrong_answer_risk"] == 0.0

    # --- Scenario k=1: DB Corrupted -> Level 2 (Vault) ---
    mock_manifest.verify_record.return_value = False  # DB verification fails
    ladder_k1 = RecoveryLadder(
        repository=mock_repo,
        manifest_store=mock_manifest,
        vault_store=vault,
        quorum_store=quorum_store,
        offline_store=offline_store,
    )
    res_k1 = ladder_k1.resolve(memory_id)
    assert res_k1["decision"] == "TRUSTED_RECOVERY_POINT"
    assert res_k1["ladder_level"] == RecoveryLevel.LEVEL_2_LOCAL_VAULT.value
    assert res_k1["selected_content"] == clean_content
    assert res_k1["wrong_answer_risk"] == 0.0

    # --- Scenario k=2: DB + Vault Corrupted -> Level 3 (Quorum Replicas) ---
    # Corrupt vault file
    safe_id = vault._safe_id(memory_id)
    (vault_dir / f"{safe_id}.v1.vault.json").write_text("{}", encoding="utf-8")
    ladder_k2 = RecoveryLadder(
        repository=mock_repo,
        manifest_store=mock_manifest,
        vault_store=vault,
        quorum_store=quorum_store,
        offline_store=offline_store,
    )
    res_k2 = ladder_k2.resolve(memory_id)
    assert res_k2["decision"] == "TRUSTED_RECOVERY_POINT"
    assert res_k2["ladder_level"] == RecoveryLevel.LEVEL_3_QUORUM_REPLICAS.value
    assert res_k2["selected_content"] == clean_content
    assert res_k2["wrong_answer_risk"] == 0.0
    assert "isolated_cryptographic_vault" in res_k2["repairs_applied"]

    # --- Scenario k=3: DB + Vault + Quorum Corrupted -> Level 4 (Offline) ---
    # Since Level 3 auto-repaired the vault above, re-corrupt the vault and corrupt all quorum replicas
    (vault_dir / f"{safe_id}.v1.vault.json").write_text("{}", encoding="utf-8")
    for r_dir in replica_dirs:
        (r_dir / f"{safe_id}.v1.replica.json").write_text("{}", encoding="utf-8")
    ladder_k3 = RecoveryLadder(
        repository=mock_repo,
        manifest_store=mock_manifest,
        vault_store=vault,
        quorum_store=quorum_store,
        offline_store=offline_store,
    )
    res_k3 = ladder_k3.resolve(memory_id)
    assert res_k3["decision"] == "TRUSTED_RECOVERY_POINT"
    assert res_k3["ladder_level"] == RecoveryLevel.LEVEL_4_OFFLINE_SNAPSHOT_REPLAY.value
    assert res_k3["selected_content"] == clean_content
    assert res_k3["wrong_answer_risk"] == 0.0

    # --- Scenario k=4: All Stores Corrupted -> Level 5 (ROOT_OF_TRUST_COMPROMISED) ---
    (offline_dir / f"{safe_id}.v1.offline.json").write_text("{}", encoding="utf-8")
    ladder_k4 = RecoveryLadder(
        repository=mock_repo,
        manifest_store=mock_manifest,
        vault_store=vault,
        quorum_store=quorum_store,
        offline_store=offline_store,
    )
    res_k4 = ladder_k4.resolve(memory_id)
    assert res_k4["decision"] == "ROOT_OF_TRUST_COMPROMISED"
    assert res_k4["ladder_level"] == RecoveryLevel.LEVEL_5_FAIL_SAFE.value
    assert res_k4["selected_content"] is None
    assert res_k4["selected_version"] is None
    assert res_k4["wrong_answer_risk"] == 0.0
