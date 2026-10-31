"""
Unit & Integration Tests for Milestone M10:
- Forensic Incident Dossier Generator (JSON, Markdown, PDF)
- SOC Dashboard Feed with 6 Memory Class RAG Status Metrics
- FastAPI SOC Telemetry Endpoints
- End-to-End Enterprise Demo Lifecycle
"""

import json
from pathlib import Path
import tempfile
import pytest
from fastapi.testclient import TestClient

from api.main import app
from core.soc.incident_reporter import (
    IncidentReport,
    IncidentManager,
    compute_content_diff,
    get_incident_manager,
)
from core.soc.dashboard_feed import (
    get_soc_dashboard_feed,
    CUSTOMER_SUPPORT_CLASSES,
    build_class_rag_status,
)


def test_content_diff_computation():
    before = "Standard 30-day return policy for customer orders."
    after = "MALICIOUS 180-day return policy for customer orders."
    diff = compute_content_diff(before, after, label_before="v1 (Original)", label_after="v1 (Tampered)")
    assert "--- v1 (Original)" in diff
    assert "+++ v1 (Tampered)" in diff
    assert "-Standard 30-day" in diff
    assert "+MALICIOUS 180-day" in diff


def test_incident_report_creation_and_serialization(tmp_path):
    diff = compute_content_diff("Policy limit: 30 days", "Policy limit: 180 days")
    report = IncidentReport(
        incident_id="INC-UNIT-001",
        title="Unauthorized Policy Modification Attack",
        status="RESOLVED_SECURE",
        severity="CRITICAL",
        severity_score=0.95,
        attacker={
            "actor": "kali-attacker",
            "source_ip": "172.28.0.5",
            "source_port": 50123,
            "scenario": "DIRECT_POLICY_TAMPERING",
            "ttp": "T1565.001 - Stored Memory Manipulation",
        },
        session={
            "session_id": "SES-TEST-999",
            "dwell_time_seconds": 0.045,
            "exposure_window_wrong_answers": 0,
        },
        timeline=[
            {"event_type": "PROBE", "timestamp": 100.0, "actor": "kali-attacker", "memory_id": "POLICY-REFUND-001"},
            {"event_type": "EXPLOIT", "timestamp": 100.02, "actor": "kali-attacker", "memory_id": "POLICY-REFUND-001"},
            {"event_type": "RECOVERY", "timestamp": 100.04, "actor": "aegismem_ladder", "memory_id": "POLICY-REFUND-001"},
        ],
        read_items=[
            {
                "actor": "customer_agent",
                "memory_id": "POLICY-REFUND-001",
                "gate_decision": "BLOCK_UNVERIFIED",
                "verified": False,
                "safe_fallback_used": True,
                "wrong_answer_served": False,
            }
        ],
        modified_items=[
            {
                "memory_id": "POLICY-REFUND-001",
                "memory_class": "POLICY",
                "target_version": 1,
                "original_hash": "aaa",
                "tampered_hash": "bbb",
                "recovered_hash": "aaa",
                "content_diff": diff,
            }
        ],
        detection_evidence={
            "signature_valid": False,
            "hash_chain_valid": False,
            "anchor_verified": False,
            "timestamp_skew_seconds": 0.01,
            "suspicion_score": 0.98,
            "time_to_detect_ms": 2.15,
            "signals": ["MANIFEST_HASH_MISMATCH", "UNVERIFIED_READ_BLOCKED"],
        },
        dependency_impact={
            "primary_node": "POLICY-REFUND-001",
            "direct_dependents": ["FAQ-REFUND-001"],
            "transitive_dependents": ["CUST-VIP-RULES"],
            "blast_radius_score": 0.35,
            "quarantined_items": [],
        },
        tcrp_decision={
            "selected_action": "ROLLBACK",
            "candidate_costs": {"RETAIN": 1.0, "ROLLBACK": 0.15, "QUARANTINE": 0.45},
            "rationale": "Cost-optimal rollback restoring verified state from vault",
        },
        recovery_ladder_level={
            "level": 2,
            "level_name": "LOCAL_APPEND_ONLY_VAULT",
            "restored_version": 1,
            "attestation_id": "ATT-001",
            "time_to_recover_ms": 12.4,
        },
        derived_state_repair={
            "invalidated_templates": ["TEMPLATE-REFUND-APPROVAL"],
            "purged_cache_keys": ["cache:POLICY-REFUND-001"],
            "reindexed_embeddings": ["embed:POLICY-REFUND-001"],
        },
        validation={
            "hash_chain_valid": True,
            "anchor_countersigned": True,
            "read_gate_verified": True,
            "agent_answer_verified": True,
            "status": "RESOLVED_SECURE",
        },
        exposure_count=0,
    )

    mgr = IncidentManager(incidents_dir=tmp_path)
    paths = mgr.save_incident(report)

    # 1. Verify JSON file
    assert paths["json"].exists()
    json_data = json.loads(paths["json"].read_text(encoding="utf-8"))
    assert json_data["incident_id"] == "INC-UNIT-001"
    assert json_data["exposure_count"] == 0
    assert json_data["recovery_ladder_level"]["level"] == 2
    assert json_data["tcrp_decision"]["selected_action"] == "ROLLBACK"

    # 2. Verify Markdown file
    assert paths["md"].exists()
    md_content = paths["md"].read_text(encoding="utf-8")
    assert "AegisMem Forensic Incident Dossier: `INC-UNIT-001`" in md_content
    assert "ZERO WRONG ANSWERS SERVED (0)" in md_content
    assert "T1565.001 - Stored Memory Manipulation" in md_content
    assert "Level 2 (LOCAL_APPEND_ONLY_VAULT)" in md_content

    # 3. Verify PDF file
    assert paths["pdf"].exists()
    assert paths["pdf"].stat().st_size > 500
    pdf_bytes = paths["pdf"].read_bytes()
    assert pdf_bytes.startswith(b"%PDF-1.4")
    assert b"%%EOF" in pdf_bytes

    # 4. Verify Retrieval and Listing
    retrieved = mgr.get_incident("INC-UNIT-001")
    assert retrieved is not None
    assert retrieved.title == "Unauthorized Policy Modification Attack"

    incidents_list = mgr.list_incidents()
    assert len(incidents_list) == 1
    assert incidents_list[0]["incident_id"] == "INC-UNIT-001"


def test_soc_dashboard_feed_structure():
    feed = get_soc_dashboard_feed()
    assert "timestamp" in feed
    assert "global_status" in feed
    assert feed["exposure_window_guarantee"] == 0
    assert "performance_telemetry" in feed
    assert "memory_classes_rag" in feed

    classes = feed["memory_classes_rag"]
    assert len(classes) == 6

    expected_ids = {"POLICY", "PRICING_PROMOTIONS", "ESCALATION_PROCEDURES", "PRODUCT_FAQ", "CUSTOMER_PROFILE", "CONVERSATION_NOTE"}
    actual_ids = {c["class_id"] for c in classes}
    assert actual_ids == expected_ids

    for c in classes:
        assert c["status"] in {"GREEN", "AMBER", "RED"}
        assert c["authority_tier"] in {"OWNER_AUTHORIZED", "OPERATIONS_AUTHORIZED", "KNOWLEDGE_BASE_ADMIN", "SYSTEM_AUTHENTICATED", "CONVERSATION_DERIVED"}
        assert c["criticality_weight"] > 0.0


def test_soc_class_rag_dynamics():
    # Test clean state
    clean_rag = build_class_rag_status(open_alerts=[], incidents=[])
    for c in clean_rag:
        assert c["status"] == "GREEN"

    # Test alerted state on POLICY
    alerted_rag = build_class_rag_status(
        open_alerts=[{"memory_id": "POLICY-REFUND-001", "status": "OPEN", "severity": "CRITICAL"}],
        incidents=[],
    )
    policy_class = next(c for c in alerted_rag if c["class_id"] == "POLICY")
    assert policy_class["status"] == "RED"

    # Other classes remain green
    faq_class = next(c for c in alerted_rag if c["class_id"] == "PRODUCT_FAQ")
    assert faq_class["status"] == "GREEN"


def test_fastapi_soc_endpoints(tmp_path):
    client = TestClient(app)

    # Test /api/soc/dashboard-feed
    res_feed = client.get("/api/soc/dashboard-feed")
    assert res_feed.status_code == 200
    feed_data = res_feed.json()
    assert feed_data["exposure_window_guarantee"] == 0
    assert len(feed_data["memory_classes_rag"]) == 6

    # Test /api/soc/incidents
    res_list = client.get("/api/soc/incidents")
    assert res_list.status_code == 200
    assert isinstance(res_list.json(), list)

    # Save a temporary incident to verify detail, markdown, and pdf endpoints
    mgr = get_incident_manager(Path("data/incidents"))
    test_inc = IncidentReport(
        incident_id="INC-ENDPOINT-TEST",
        title="Endpoint Integration Test Incident",
        status="RESOLVED_SECURE",
        severity="HIGH",
        exposure_count=0,
    )
    mgr.save_incident(test_inc)

    # Test /api/soc/incidents/{incident_id}
    res_detail = client.get("/api/soc/incidents/INC-ENDPOINT-TEST")
    assert res_detail.status_code == 200
    assert res_detail.json()["incident_id"] == "INC-ENDPOINT-TEST"

    # Test /api/soc/incidents/{incident_id}/markdown
    res_md = client.get("/api/soc/incidents/INC-ENDPOINT-TEST/markdown")
    assert res_md.status_code == 200
    assert "AegisMem Forensic Incident Dossier: `INC-ENDPOINT-TEST`" in res_md.text

    # Test /api/soc/incidents/{incident_id}/pdf
    res_pdf = client.get("/api/soc/incidents/INC-ENDPOINT-TEST/pdf")
    assert res_pdf.status_code == 200
    assert res_pdf.headers["content-type"] == "application/pdf"
    assert res_pdf.content.startswith(b"%PDF-1.4")


def test_demo_end_to_end_script_execution():
    import subprocess
    import sys
    result = subprocess.run(
        [sys.executable, "scripts/demo_end_to_end.py"],
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        check=True,
    )
    assert "DEMO COMPLETE" in result.stdout
    assert "EXPOSURE WINDOW: EXACTLY 0 WRONG ANSWERS SERVED" in result.stdout

    # Check that incident was generated
    mgr = get_incident_manager("data/incidents")
    incidents = mgr.list_incidents()
    assert len(incidents) >= 1
    assert any("INC-DEMO-" in inc["incident_id"] for inc in incidents)

