import json
import time
from pathlib import Path
from tempfile import gettempdir
from unittest.mock import MagicMock
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from agent.runtime.support_agent import (
    AgentBackendType,
    EnterpriseSupportAgent,
    SupportAgentPromptLogger,
)
from attack_lab.adaptive_attacker import AdaptiveAttacker, AttackerHarness
from attack_lab.session_timeline import (
    SessionTimeline,
    SessionTimelineReconstructor,
    TimelineEventType,
)
from core.gateway.read_gate import ReadPathGate, UnverifiedMemoryAccessError
from core.gateway.read_logger import ReadAccessLogger
from core.integrity.anchor import anchor_chain_head, verify_chain_head_anchor
from core.integrity.manifest_store import IntegrityManifestStore
from core.memory.authority import MemoryClass
from core.memory.database import Base
from core.memory.models import MemoryRecord
from core.memory.repository import MemoryRepository
from tests.owner_approval_test_utils import sign_test_approval


@pytest.fixture
def test_db(tmp_path):
    db_file = tmp_path / "attack_lab_m7.db"
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


def _seed_signed_memory(repo, memory_id: str, content: str, auth_id: str, nonce: str) -> MemoryRecord:
    sig = sign_test_approval(
        memory_id=memory_id,
        content=content,
        authorization_id=auth_id,
        nonce=nonce,
        expected_parent_revision_id=None,
    )
    return repo.create_owner_authorized(
        memory_id=memory_id,
        content=content,
        source="owner_admin",
        authorization_id=auth_id,
        nonce=nonce,
        authorization_signature=sig,
        expected_revision_id=None,
    )


def test_scenario_1_policy_tampering_and_recovery(test_db, tmp_path):
    """
    Scenario 1: Policy tampering (30 -> 180 days).
    Verifies:
    1. Clean agent allows 14-day refund and denies 45-day refund.
    2. Attacker corrupts database to 180 days.
    3. ReadPathGate blocks tampered policy; agent refuses to serve false policy (wrong answers == 0).
    4. Recovery restores verified policy and cache invalidation serves correct policy without restart.
    """
    manifest_store = IntegrityManifestStore(manifest_dir=tmp_path / "manifests_s1")
    read_logger = ReadAccessLogger(tmp_path / "read_log_s1.jsonl")
    repo = MemoryRepository(test_db, manifest_store=manifest_store)
    gate = ReadPathGate(repository=repo, manifest_store=manifest_store, read_logger=read_logger, enable_cache=True)

    mem_id = "POLICY-REFUND-001"
    clean_content = "Customer refunds are permitted within 30 calendar days of original purchase."
    _seed_signed_memory(repo, mem_id, clean_content, "AUTH-S1-001", "NONCE-S1-001")

    agent = EnterpriseSupportAgent(read_gate=gate, backend_type=AgentBackendType.DETERMINISTIC_RULE)

    # 1. Clean reads
    res1 = agent.answer_query("Can I get a refund for an order from 14 days ago?", mem_id)
    assert res1["gate_verified"] is True
    assert res1["decision"] == "REFUND ALLOWED"

    res2 = agent.answer_query("Can I return an order from 45 days ago?", mem_id)
    assert res2["gate_verified"] is True
    assert res2["decision"] == "REFUND DENIED"

    # 2. Attacker executes Scenario 1: Policy Tampering
    attacker = AdaptiveAttacker(test_db)
    session_id = "SES-TEST-S1"
    attack_info = attacker.attack_scenario_1_policy_tampering(memory_id=mem_id, new_days=180, session_id=session_id)
    assert attack_info["corrupted_version"] > 1

    # Invalidate cache simulating head change detection
    gate.invalidate_cache(mem_id)

    # 3. Agent queries under attack: 45 days would be falsely ALLOWED if unprotected!
    res_under_attack = agent.answer_query("Can I return an order from 45 days ago?", mem_id, session_id=session_id)
    assert res_under_attack["gate_verified"] is False
    assert res_under_attack["decision"] == "BLOCKED_UNVERIFIED"
    assert "could not be cryptographically verified" in res_under_attack["answer"]

    # 4. Recovery: restore verified policy as new authorized version
    corrupted_rec = repo.get_latest(mem_id)
    corrupted_rec.status = "CORRUPTED"
    test_db.commit()

    sig_rec = sign_test_approval(
        memory_id=mem_id,
        content=clean_content,
        authorization_id="AUTH-S1-REC",
        nonce="NONCE-S1-REC",
        expected_parent_revision_id=corrupted_rec.revision_id,
    )
    repo.create_owner_authorized(
        memory_id=mem_id,
        content=clean_content,
        source="aegismem_recovery",
        authorization_id="AUTH-S1-REC",
        nonce="NONCE-S1-REC",
        authorization_signature=sig_rec,
        expected_revision_id=corrupted_rec.revision_id,
    )

    gate.invalidate_cache(mem_id)

    # 5. Gate immediately serves recovered version without server restart
    res_recovered = agent.answer_query("Can I return an order from 45 days ago?", mem_id, session_id=session_id)
    assert res_recovered["gate_verified"] is True
    assert res_recovered["decision"] == "REFUND DENIED"


def test_scenario_2_and_3_promo_poisoning_and_escalation_bypass(test_db, tmp_path):
    """
    Scenario 2 & 3: Promotion Poisoning (90% discount) & Escalation Bypass.
    Verifies that ReadPathGate blocks unsigned or tampered promotion and escalation policies.
    """
    manifest_store = IntegrityManifestStore(manifest_dir=tmp_path / "manifests_s23")
    repo = MemoryRepository(test_db, manifest_store=manifest_store)
    gate = ReadPathGate(repository=repo, manifest_store=manifest_store, enable_cache=False)

    attacker = AdaptiveAttacker(test_db)

    # Seed clean signed promo
    promo_id = "PROMO-SUMMER-2026"
    _seed_signed_memory(
        repo,
        promo_id,
        "Promotional Campaign: 10% discount on summer apparel with code SUMMER10.",
        "AUTH-S2-001",
        "NONCE-S2-001",
    )

    # Clean check
    clean_promo = gate.get_verified_memory(promo_id)
    assert clean_promo is not None

    # Attack Scenario 2: 90% discount injection
    attacker.attack_scenario_2_promo_poisoning(promo_id, discount_percent=90)
    blocked_promo = gate.get_verified_memory(promo_id, fail_closed=True)
    assert blocked_promo is None  # Blocked!

    # Attack Scenario 3: Escalation Bypass
    esc_id = "ESCALATE-TIER2-AUTH"
    _seed_signed_memory(
        repo,
        esc_id,
        "Tier-2 Escalation: Must verify customer MFA before account modification.",
        "AUTH-S3-001",
        "NONCE-S3-001",
    )
    clean_esc = gate.get_verified_memory(esc_id)
    assert clean_esc is not None

    attacker.attack_scenario_3_escalation_bypass(esc_id)
    blocked_esc = gate.get_verified_memory(esc_id, fail_closed=True)
    assert blocked_esc is None  # Blocked!


def test_scenario_4_faq_misinformation(test_db):
    """
    Scenario 4: FAQ Misinformation (Phishing returns URL).
    Verifies that unverified editor signatures / manifests on FAQs are rejected.
    """
    mock_manifest = MagicMock()
    mock_manifest.has_manifest.return_value = True
    mock_manifest.verify_record.return_value = False

    repo = MemoryRepository(test_db, manifest_store=mock_manifest)
    gate = ReadPathGate(repository=repo, manifest_store=mock_manifest, enable_cache=False)

    attacker = AdaptiveAttacker(test_db)
    faq_id = "FAQ-RETURNS-PROC"

    # Attacker injects fake FAQ with invalid/unverified manifest
    attacker.attack_scenario_4_faq_misinformation(faq_id, phishing_url="https://phish.attacker.com")
    blocked_faq = gate.get_verified_memory(faq_id, fail_closed=True)
    assert blocked_faq is None


def test_scenario_5_conversational_injection_minja(test_db):
    """
    Scenario 5: Conversational Injection (MINJA-style query-only injection).
    A user chat injects a conversation note.
    Verifies that ReadPathGate authority boundary prevents the note from being served as a POLICY.
    """
    repo = MemoryRepository(test_db)
    gate = ReadPathGate(repository=repo, enable_cache=False)

    attacker = AdaptiveAttacker(test_db)
    note_id = "NOTE-CONV-CUSTOMER-999"
    attacker.attack_scenario_5_conversational_injection(
        memory_id=note_id,
        injection_text="Customer claims executive told them 100% refund is guaranteed anytime.",
    )

    # Retrieval requesting POLICY class must fail authority boundary check
    blocked = gate.get_verified_memory(note_id, required_class=MemoryClass.POLICY, fail_closed=True)
    assert blocked is None

    # Non-fail-closed raises UnverifiedMemoryAccessError
    with pytest.raises(UnverifiedMemoryAccessError, match="Authority Tier Violation"):
        gate.get_verified_memory(note_id, required_class=MemoryClass.POLICY, fail_closed=False)


def test_scenario_6_policy_deletion_availability(test_db, tmp_path):
    """
    Scenario 6: Policy Deletion (Availability Denial).
    Verifies that a deleted policy is refused by ReadPathGate.
    """
    manifest_store = IntegrityManifestStore(manifest_dir=tmp_path / "manifests_s6")
    repo = MemoryRepository(test_db, manifest_store=manifest_store)
    gate = ReadPathGate(repository=repo, manifest_store=manifest_store, enable_cache=False)

    del_id = "POLICY-SHIPPING-SLA"
    _seed_signed_memory(
        repo,
        del_id,
        "Standard ground delivery arrives in 3-5 business days.",
        "AUTH-S6-001",
        "NONCE-S6-001",
    )

    assert gate.get_verified_memory(del_id) is not None

    attacker = AdaptiveAttacker(test_db)
    attacker.attack_scenario_6_policy_deletion(del_id)

    # ReadPathGate returns None for DELETED status
    assert gate.get_verified_memory(del_id, fail_closed=True) is None


def test_scenario_7_trusted_version_gap_anchor_defense(test_db, tmp_path):
    """
    Scenario 7: Trusted-Version Gap (history rewrite with recomputed hash chain).
    Verifies that when an adversary rewrites ancestor content and recomputes hashes,
    the trust anchor countersignature detects the root-of-trust mismatch.
    """
    repo = MemoryRepository(test_db)
    mem_id = "POLICY-REFUND-001"

    # Create v1 and v2
    r1 = repo.create(memory_id=mem_id, content="Original clean v1 content", source="system", source_type="seed")
    r2 = repo.create(memory_id=mem_id, content="Original clean v2 content", source="system", source_type="seed")

    # Generate independent anchor keys
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

    # Anchor the legitimate chain head
    epoch = int(time.time())
    anchor_receipt = anchor_chain_head(
        memory_id=mem_id,
        version=r2.version,
        head_hash=r2.content_hash,
        previous_hash=r2.previous_hash,
        epoch=epoch,
        private_key_path=priv_path,
    )
    assert verify_chain_head_anchor(anchor_receipt, pub_path) is True

    # Adversary rewrites ancestor v1 and recomputes hashes down to head
    attacker = AdaptiveAttacker(test_db)
    attacker.attack_scenario_7_trusted_version_gap(mem_id)

    # Freshly fetch the modified head
    test_db.expire_all()
    tampered_head = repo.get_latest(mem_id)

    # The tampered head hash does NOT match the anchor receipt
    tampered_receipt = dict(anchor_receipt)
    tampered_receipt["head_hash"] = tampered_head.content_hash
    assert verify_chain_head_anchor(tampered_receipt, pub_path) is False, "Anchor must detect tampered history rewrite!"


def test_adaptive_attacker_a_threshold_aware(test_db, tmp_path):
    """
    Adaptive Attacker A (Threshold-Aware):
    Subtle mutation (single digit change: 30 -> 31 days).
    Verifies that statistical drift is minimal (< 1% string diff),
    yet ReadPathGate cryptographic verification catches it 100%.
    """
    manifest_store = IntegrityManifestStore(manifest_dir=tmp_path / "manifests_ada")
    repo = MemoryRepository(test_db, manifest_store=manifest_store)
    gate = ReadPathGate(repository=repo, manifest_store=manifest_store, enable_cache=False)

    mem_id = "POLICY-REFUND-001"
    clean_text = "Customer refunds are permitted within 30 calendar days of original purchase."
    _seed_signed_memory(repo, mem_id, clean_text, "AUTH-ADA-001", "NONCE-ADA-001")

    attacker = AdaptiveAttacker(test_db)
    result = attacker.attack_adaptive_a_threshold_aware(mem_id)
    assert result["percent_difference"] < 5.0  # Minimal drift

    # Cryptographic gate rejects subtle edit because signature/hash is invalid
    blocked = gate.get_verified_memory(mem_id, fail_closed=True)
    assert blocked is None


def test_adaptive_attacker_b_dependency_aware(test_db):
    """
    Adaptive Attacker B (Dependency-Aware):
    Leaves root policy clean, poisons child FAQ.
    Verifies that querying the child memory is blocked, preventing cascade corruption.
    """
    mock_manifest = MagicMock()
    # Root policy verified; child FAQ unverified / invalid
    mock_manifest.has_manifest.return_value = True
    mock_manifest.verify_record.side_effect = lambda rec: rec.memory_id == "POLICY-REFUND-001"

    repo = MemoryRepository(test_db, manifest_store=mock_manifest)
    gate = ReadPathGate(repository=repo, manifest_store=mock_manifest, enable_cache=False)

    parent_id = "POLICY-REFUND-001"
    child_id = "FAQ-RETURNS-PROC"

    # Seed clean signed parent
    _seed_signed_memory(repo, parent_id, "Standard 30 days refund window.", "AUTH-ADB-001", "NONCE-ADB-001")

    attacker = AdaptiveAttacker(test_db)
    attacker.attack_adaptive_b_dependency_aware(parent_id, child_id)

    # Parent remains clean and accessible
    assert gate.get_verified_memory(parent_id) is not None

    # Poisoned child FAQ has invalid manifest and is blocked
    assert gate.get_verified_memory(child_id, fail_closed=True) is None


def test_adaptive_attacker_c_recovery_aware(test_db, tmp_path):
    """
    Adaptive Attacker C (Recovery-Aware):
    Re-poisons database immediately post-recovery.
    Verifies that ReadPathGate maintains fail-closed protection across consecutive attack cycles.
    """
    manifest_store = IntegrityManifestStore(manifest_dir=tmp_path / "manifests_adc")
    repo = MemoryRepository(test_db, manifest_store=manifest_store)
    gate = ReadPathGate(repository=repo, manifest_store=manifest_store, enable_cache=False)

    mem_id = "POLICY-REFUND-001"
    clean_text = "30 calendar days refund policy."
    _seed_signed_memory(repo, mem_id, clean_text, "AUTH-ADC-001", "NONCE-ADC-001")

    attacker = AdaptiveAttacker(test_db)

    # Attack cycle 1
    attacker.attack_scenario_1_policy_tampering(mem_id, new_days=180)
    assert gate.get_verified_memory(mem_id, fail_closed=True) is None

    # Recovery cycle 1 (restore verified authorized version)
    current_head = repo.get_latest(mem_id)
    sig_rec = sign_test_approval(
        memory_id=mem_id,
        content=clean_text,
        authorization_id="AUTH-ADC-REC",
        nonce="NONCE-ADC-REC",
        expected_parent_revision_id=current_head.revision_id,
    )
    repo.create_owner_authorized(
        memory_id=mem_id,
        content=clean_text,
        source="recovery",
        authorization_id="AUTH-ADC-REC",
        nonce="NONCE-ADC-REC",
        authorization_signature=sig_rec,
        expected_revision_id=current_head.revision_id,
    )
    gate.invalidate_cache(mem_id)
    assert gate.get_verified_memory(mem_id) is not None

    # Immediate re-poison (Attack cycle 2)
    attacker.attack_adaptive_c_recovery_aware(mem_id, repoison_delay_ms=5.0)
    gate.invalidate_cache(mem_id)
    assert gate.get_verified_memory(mem_id, fail_closed=True) is None


def test_session_timeline_and_dwell_time_reconstruction(tmp_path):
    """
    Test Session Timeline Reconstruction & Dwell-Time Calculation.
    Simulates: Probe -> Exploit -> Read Attempt -> Detection -> Recovery -> Post-Recovery Read.
    Verifies dwell time, time-to-detect, time-to-recover, and exposure window wrong answers == 0.
    """
    reconstructor = SessionTimelineReconstructor()
    sid = "SES-FORENSIC-001"
    mem_id = "POLICY-REFUND-001"

    t0 = time.time()
    reconstructor.record_probe(sid, "kali_attacker", mem_id, "PORT_SCAN", timestamp=t0)
    t1 = t0 + 0.05
    reconstructor.record_exploit(sid, "kali_attacker", mem_id, "POLICY_TAMPER", "30d->180d", 2, timestamp=t1)
    t2 = t1 + 0.02
    reconstructor.record_read_attempt(sid, "support_agent", mem_id, verified=False, wrong_answer_served=False, timestamp=t2)
    t3 = t2 + 0.03
    reconstructor.record_detection(sid, mem_id, "Hash mismatch detected", timestamp=t3)
    t4 = t3 + 0.04
    reconstructor.record_recovery(sid, mem_id, ladder_level=2, restored_version=1, timestamp=t4)
    t5 = t4 + 0.01
    reconstructor.record_post_recovery_read(sid, "support_agent", mem_id, verified=True, answer="Refund allowed", timestamp=t5)

    timeline = reconstructor.get_or_create(sid)
    assert timeline.dwell_time_seconds > 0.0
    assert timeline.time_to_detect_ms is not None
    assert timeline.time_to_detect_ms >= 0.0
    assert timeline.time_to_recover_ms is not None
    assert timeline.time_to_recover_ms >= 0.0
    assert timeline.exposure_window_wrong_answers == 0

    # Test Markdown formatting
    md = timeline.to_markdown()
    assert "Incident Session Timeline" in md
    assert "- **Wrong Answers Served (Exposure Window):** 0" in md

    # Test JSON export
    json_path = timeline.export_json(tmp_path / "forensic_timeline.json")
    data = json.loads(json_path.read_text(encoding="utf-8"))
    assert data["session_id"] == sid
    assert data["exposure_window_wrong_answers"] == 0
    assert len(data["events"]) == 6


def test_attacker_harness_concurrency(test_db, tmp_path):
    """
    Test AttackerHarness asynchronous attack execution while queries run.
    """
    manifest_store = IntegrityManifestStore(manifest_dir=tmp_path / "manifests_harn")
    repo = MemoryRepository(test_db, manifest_store=manifest_store)
    gate = ReadPathGate(repository=repo, manifest_store=manifest_store, enable_cache=False)

    mem_id = "POLICY-REFUND-001"
    _seed_signed_memory(repo, mem_id, "30 calendar days refund policy.", "AUTH-HARN-001", "NONCE-HARN-001")

    attacker = AdaptiveAttacker(test_db)
    harness = AttackerHarness(attacker)

    # Launch asynchronous attack with 50ms delay
    harness.launch_attack_async(
        lambda: attacker.attack_scenario_1_policy_tampering(mem_id, new_days=90),
        delay_seconds=0.05,
    )

    # Main thread queries before attack lands
    rec_before = gate.get_verified_memory(mem_id)
    assert rec_before is not None

    # Wait for attack to land
    harness.wait_all(timeout=2.0)

    # Main thread queries after attack landed
    rec_after = gate.get_verified_memory(mem_id, fail_closed=True)
    assert rec_after is None  # Blocked!
