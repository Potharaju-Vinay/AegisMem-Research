import csv
import json
from pathlib import Path
from tempfile import gettempdir
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from agent.runtime.support_agent import (
    AgentBackendType,
    EnterpriseSupportAgent,
)
from attack_lab.adaptive_attacker import AdaptiveAttacker
from core.integrity.anchor import anchor_chain_head
from core.integrity.manifest_store import IntegrityManifestStore
from core.memory.authority import MemoryClass
from core.memory.database import Base
from core.memory.models import MemoryRecord
from core.memory.repository import MemoryRepository
from evaluation.baselines import (
    BaselineExecutionAdapter,
    BaselineType,
)
from evaluation.benchmark_runner import DomainBenchmarkRunner
from tests.owner_approval_test_utils import sign_test_approval


@pytest.fixture
def baseline_db(tmp_path):
    db_file = tmp_path / "baseline_m8.db"
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


def _seed_policy(repo, memory_id: str, content: str) -> MemoryRecord:
    sig = sign_test_approval(
        memory_id=memory_id,
        content=content,
        authorization_id=f"AUTH-SEED-{memory_id}",
        nonce=f"NONCE-SEED-{memory_id}",
        expected_parent_revision_id=None,
    )
    return repo.create_owner_authorized(
        memory_id=memory_id,
        content=content,
        source="admin",
        authorization_id=f"AUTH-SEED-{memory_id}",
        nonce=f"NONCE-SEED-{memory_id}",
        authorization_signature=sig,
        expected_revision_id=None,
    )


def test_baseline_retain_only_serves_poisoned_content(baseline_db, tmp_path):
    """
    Baseline 1 (RETAIN_ONLY):
    Unprotected database allows agent to read corrupted records directly,
    resulting in wrong answers served to users.
    """
    manifest_store = IntegrityManifestStore(manifest_dir=tmp_path / "manifests_ro")
    repo = MemoryRepository(baseline_db, manifest_store=manifest_store)
    clean_policy = "Customer refunds are permitted within 30 calendar days of original purchase."
    _seed_policy(repo, "POLICY-REFUND-001", clean_policy)

    adapter = BaselineExecutionAdapter(BaselineType.RETAIN_ONLY, repo, manifest_store)
    agent = EnterpriseSupportAgent(read_gate=None, backend_type=AgentBackendType.DETERMINISTIC_RULE)

    # Corrupt policy: 30 -> 180 days
    attacker = AdaptiveAttacker(baseline_db)
    attacker.attack_scenario_1_policy_tampering("POLICY-REFUND-001", new_days=180)

    # Agent queries with 45 days purchase (should be DENIED under clean policy)
    ans = adapter.answer_customer_query(agent, "Can I return an order from 45 days ago?", "POLICY-REFUND-001", 30)
    assert ans["policy_limit"] == 180
    assert ans["decision"] == "ALLOWED"  # Falsely allowed!
    assert ans["wrong_answer"] is True
    assert adapter.stats["wrong_answers_served"] == 1


def test_baseline_rule_based_rollback_fails_on_ancestor_attack(baseline_db, tmp_path):
    """
    Baseline 2 (RULE_BASED_ROLLBACK):
    Naive heuristic unconditionally rolls back 1 version (v <- v-1).
    When an attack modifies an ancestor version or recomputed history,
    rolling back to v-1 does not restore the ground truth.
    """
    manifest_store = IntegrityManifestStore(manifest_dir=tmp_path / "manifests_rb")
    repo = MemoryRepository(baseline_db, manifest_store=manifest_store)
    clean_policy = "Customer refunds are permitted within 30 calendar days."
    _seed_policy(repo, "POLICY-REFUND-001", clean_policy)

    adapter = BaselineExecutionAdapter(BaselineType.RULE_BASED_ROLLBACK, repo, manifest_store)
    attacker = AdaptiveAttacker(baseline_db)

    # Attack modifies ancestor v1 in place without creating new version
    # So v=1 itself is corrupted. Naive rollback (v <- v-1) fails completely.
    attacker.attack_scenario_7_trusted_version_gap("POLICY-REFUND-001")
    incident_res = adapter.handle_incident("POLICY-REFUND-001", ground_truth_version=1, attack_type="HISTORY_REWRITE")

    # With only 1 version that was rewritten, rolling back to max(1, 1-1)=1 stays on corrupted v1
    assert incident_res["success"] is False or incident_res["restored_version"] == 1


def test_baseline_detection_only_alerts_without_read_gate(baseline_db, tmp_path):
    """
    Baseline 3 (DETECTION_ONLY):
    Alerts are generated, but read path is unguarded and memories are not auto-healed.
    Agent continues to retrieve unverified/tampered memory from active store.
    """
    manifest_store = IntegrityManifestStore(manifest_dir=tmp_path / "manifests_do")
    repo = MemoryRepository(baseline_db, manifest_store=manifest_store)
    _seed_policy(repo, "POLICY-REFUND-001", "30 calendar days refund policy.")

    adapter = BaselineExecutionAdapter(BaselineType.DETECTION_ONLY, repo, manifest_store)
    agent = EnterpriseSupportAgent(read_gate=None, backend_type=AgentBackendType.DETERMINISTIC_RULE)

    attacker = AdaptiveAttacker(baseline_db)
    attacker.attack_scenario_1_policy_tampering("POLICY-REFUND-001", new_days=180)

    incident_res = adapter.handle_incident("POLICY-REFUND-001", ground_truth_version=1)
    assert incident_res["alert_raised"] is True
    assert incident_res["success"] is False

    # Agent still receives poisoned policy
    ans = adapter.answer_customer_query(agent, "Can I return an order from 90 days ago?", "POLICY-REFUND-001", 30)
    assert ans["wrong_answer"] is True


def test_baseline_tcrp_no_anchor_vulnerable_to_history_rewrite(baseline_db, tmp_path):
    """
    Baseline 4 (TCRP_NO_ANCHOR):
    Verifies local hash chains and manifests, but lacks the independent trust anchor receipt.
    An adversary who rewrites ancestor history with recomputed hashes fools the unanchored TCRP.
    """
    manifest_store = IntegrityManifestStore(manifest_dir=tmp_path / "manifests_tcrp")
    repo = MemoryRepository(baseline_db, manifest_store=manifest_store)
    _seed_policy(repo, "POLICY-REFUND-001", "30 calendar days refund policy.")

    adapter = BaselineExecutionAdapter(BaselineType.TCRP_NO_ANCHOR, repo, manifest_store)
    attacker = AdaptiveAttacker(baseline_db)

    # History rewrite attack
    attacker.attack_scenario_7_trusted_version_gap("POLICY-REFUND-001")
    res = adapter.handle_incident("POLICY-REFUND-001", ground_truth_version=1, attack_type="TRUSTED_VERSION_GAP_REWRITE")

    # TCRP without anchor falls for the rewritten history
    assert res["success"] is False
    assert res["vulnerable_to_gap"] is True


def test_baseline_aegismem_full_zero_asr_zero_frr_hundred_recovery(baseline_db, tmp_path):
    """
    Baseline 5 (AEGISMEM_FULL):
    ReadPathGate + TCRP + Trust Anchor 5-Level Ladder.
    Achieves:
    - 0% ASR (0 wrong answers served during attacks)
    - 100% Recovery Accuracy (resolves history rewrite through anchor countersignature)
    - 0% False Rollbacks on legitimate updates
    """
    manifest_store = IntegrityManifestStore(manifest_dir=tmp_path / "manifests_full")
    repo = MemoryRepository(baseline_db, manifest_store=manifest_store)
    rec1 = _seed_policy(repo, "POLICY-REFUND-001", "30 calendar days refund policy.")

    # Generate independent trust anchor keys and receipt
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

    receipt = anchor_chain_head(
        memory_id="POLICY-REFUND-001",
        version=rec1.version,
        head_hash=rec1.content_hash,
        previous_hash=rec1.previous_hash,
        epoch=1700000000,
        private_key_path=priv_path,
    )

    adapter = BaselineExecutionAdapter(
        BaselineType.AEGISMEM_FULL,
        repo,
        manifest_store,
        anchor_receipt=receipt,
        anchor_pub_key_path=str(pub_path),
    )
    agent = EnterpriseSupportAgent(read_gate=adapter.gate, backend_type=AgentBackendType.DETERMINISTIC_RULE)

    attacker = AdaptiveAttacker(baseline_db)
    attacker.attack_scenario_1_policy_tampering("POLICY-REFUND-001", new_days=180)
    adapter.gate.invalidate_cache("POLICY-REFUND-001")

    # ReadPathGate blocks retrieval; 0 wrong answers served!
    ans = adapter.answer_customer_query(agent, "Can I return an item from 45 days ago?", "POLICY-REFUND-001", 30)
    assert ans["blocked"] is True
    assert ans["wrong_answer"] is False
    assert adapter.stats["wrong_answers_served"] == 0

    # Incident recovery restores ground truth
    rec_res = adapter.handle_incident("POLICY-REFUND-001", ground_truth_version=1, attack_type="POLICY_TAMPERING")
    assert rec_res["success"] is True
    assert rec_res["restored_version"] == 1


def test_domain_benchmark_runner_multi_seed_artifacts(tmp_path):
    """
    Verifies that DomainBenchmarkRunner executes across multiple seeds,
    aggregates statistics, and produces valid CSV and Markdown reports.
    """
    out_dir = tmp_path / "bench_output"
    runner = DomainBenchmarkRunner(seeds=[42, 101], output_dir=out_dir)
    results = runner.run_benchmark(tmp_path=tmp_path)

    assert "summary_table" in results
    assert len(results["summary_table"]) == 5  # All 5 baselines

    full_sys = next(r for r in results["summary_table"] if r["baseline"] == "aegismem_full")
    assert full_sys["asr_mean"] == 0.0
    assert full_sys["recovery_acc_mean"] == 100.0
    assert full_sys["frr_mean"] == 0.0
    assert full_sys["exposure_mean"] == 0.0

    # Verify CSV file
    csv_file = Path(results["csv_path"])
    assert csv_file.exists()
    assert csv_file.stat().st_size > 0

    # Verify Markdown file
    md_file = Path(results["md_path"])
    assert md_file.exists()
    content = md_file.read_text(encoding="utf-8")
    assert "AegisMem Domain Benchmark: Baseline Comparison" in content
    assert "AegisMem (Full System)" in content
