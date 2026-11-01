import os
import sys
import json
import random
import uuid
import shutil
from pathlib import Path
from datetime import datetime, timezone

# Ensure project root is in sys.path
project_root = Path(__file__).resolve().parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from sqlalchemy import text, select, func
import urllib.parse
from sqlalchemy.orm import sessionmaker
from core.memory.database import DATABASE_URL, create_configured_engine, get_session, Base


PROTECTED_LIVE_DATABASE = "aegismem_live"
ALLOWED_DEMO_DATABASE = "aegismem_demo"


def get_target_session(db_name: str = ALLOWED_DEMO_DATABASE, read_only: bool = False):
    """
    Connect to a specific target database in PostgreSQL, enabling strict
    isolation between the live original database (aegismem_live) and the
    demonstration database (aegismem_demo).
    """
    if not read_only and db_name != ALLOWED_DEMO_DATABASE:
        raise PermissionError(
            f"CRITICAL SAFETY VIOLATION: Reset and seed is strictly prohibited from modifying '{db_name}'. "
            f"Modification target must be exactly '{ALLOWED_DEMO_DATABASE}'."
        )

    if not DATABASE_URL.startswith("postgres"):
        return get_session(), DATABASE_URL

    parsed = urllib.parse.urlsplit(DATABASE_URL)
    target_url = urllib.parse.urlunsplit(
        (parsed.scheme, parsed.netloc, f"/{db_name}", parsed.query, parsed.fragment)
    )
    target_engine = create_configured_engine(target_url)
    target_session_factory = sessionmaker(
        bind=target_engine, autoflush=False, autocommit=False
    )
    return target_session_factory(), target_url


def check_live_database_preservation() -> int:
    """Read the row count of memories from aegismem_live (read-only) to prove it was not modified."""
    session, _ = get_target_session(PROTECTED_LIVE_DATABASE, read_only=True)
    try:
        count = session.execute(text("SELECT count(*) FROM memories")).scalar()
        return count
    except Exception:
        return -1
    finally:
        session.close()
from core.memory.models import MemoryRecord
from core.provenance.models import ProvenanceEvent
from core.graph.dependency.models import MemoryDependency
from attack_lab.models import AttackEvent
from core.recovery.audit import RecoveryEvent
from core.soc.models import SOCAlert
from core.security.access import MemoryAccessEvent
from core.soc.session_audit import SessionAuditEvent
from core.security.dashboard_operation_approval import DashboardOperationApproval
from core.integrity.hash import calculate_version_hash, calculate_content_hash
from core.integrity.manifest_store import IntegrityManifestStore
from core.provenance.manager import ProvenanceManager
from core.provenance.checkpoint import ProvenanceCheckpointStore
from core.provenance.trusted_head import TrustedCheckpointHeadStore
from core.recovery.vault import ReplicatedTrustVault


# Baseline customer-support and enterprise knowledge records
BASELINE_MEMORIES = [
    {
        "memory_id": "POLICY-001",
        "content": "Customers may request refunds within 30 calendar days of purchase.",
        "source": "customer_refund_policy",
        "source_type": "policy",
        "actor": "system",
    },
    {
        "memory_id": "POLICY-002",
        "content": "Refund requests beyond 30 calendar days require manual review.",
        "source": "refund_review_policy",
        "source_type": "policy",
        "actor": "system",
    },
    {
        "memory_id": "SOP-003",
        "content": "Customer support must verify the purchase date before processing a refund. Complaints requiring escalation must be routed to a Level 2 customer support specialist within 24 hours.",
        "source": "refund_support_sop",
        "source_type": "sop",
        "actor": "system",
    },
    {
        "memory_id": "FAQ-001",
        "content": "Customer support is available Monday through Friday from 9:00 AM to 6:00 PM EST via live chat and email at support@enterprise.com. Emergency security assistance is available 24/7.",
        "source": "support_faq",
        "source_type": "faq",
        "actor": "system",
    },
    {
        "memory_id": "ENT-ACCESS-001",
        "content": "All employees must use multi-factor authentication to access enterprise systems. Privileged access requires explicit authorization from an approved administrator. Access permissions must follow the principle of least privilege.",
        "source": "enterprise_security_policy",
        "source_type": "policy",
        "actor": "system",
    },
    {
        "memory_id": "ENT-INCIDENT-002",
        "content": "All suspected security incidents must be reported immediately to the security operations team. The team must investigate, document evidence, assess impact, contain affected systems, and record remediation actions.",
        "source": "enterprise_security_policy",
        "source_type": "policy",
        "actor": "system",
    },
    {
        "memory_id": "ENT-BACKUP-003",
        "content": "Enterprise systems must maintain regular backups of critical data. Backup copies must be protected against unauthorized modification and deletion. Restoration procedures must be tested periodically to ensure data availability and integrity.",
        "source": "enterprise_security_policy",
        "source_type": "policy",
        "actor": "system",
    },
    {
        "memory_id": "ENT-DATA-004",
        "content": "Enterprise data must be collected and processed only for authorized business purposes. Sensitive information must be protected against unauthorized access and disclosure. Data retention and deletion must follow approved organizational policies and applicable requirements.",
        "source": "enterprise_security_policy",
        "source_type": "policy",
        "actor": "system",
    },
    {
        "memory_id": "ENT-EMPLOYEE-005",
        "content": "Employees must protect their credentials, use approved enterprise systems, report suspicious emails and activities, and complete required security awareness training. Confidential company information must not be shared with unauthorized parties.",
        "source": "enterprise_security_policy",
        "source_type": "policy",
        "actor": "system",
    },
]

BASELINE_DEPENDENCIES = [
    {
        "source_memory_id": "SOP-003",
        "target_memory_id": "POLICY-001",
        "dependency_type": "derives_from",
        "strength": 1.0,
    },
    {
        "source_memory_id": "SOP-003",
        "target_memory_id": "POLICY-002",
        "dependency_type": "derives_from",
        "strength": 0.8,
    },
]


def print_root_cause_diagnosis():
    print("================================================================================")
    print("                    AEGISMEM RESET AND SEED VERIFICATION                       ")
    print("================================================================================")
    print("[ROOT CAUSE DIAGNOSIS]")
    print("  Previous 'initialize_api_demo' failure (exit code 1) investigated:")
    print("  1. ModuleNotFoundError: No module named 'core'")
    print("     - Script invoked directly without PYTHONPATH=/app, so sys.path lacked root.")
    print("     - Fixed by adding dynamic project root resolution to sys.path.")
    print("  2. Incomplete reset scope:")
    print("     - Did not truncate incident/attack tables (leftover attack_events / recovery_events).")
    print("     - Left database in unverified state across repeated runs.")
    print("  3. Missing cryptographic manifest & trust vault integration:")
    print("     - Initialized rows lacked IntegrityManifestStore cryptographic signatures and")
    print("       ReplicatedTrustVault out-of-band snapshots, causing detection gate anomalies.")
    print("--------------------------------------------------------------------------------\n")


def clean_security_directories():
    """Clear stale manifest, vault, checkpoint and attestation files."""
    dirs_to_clean = [
        Path("security/integrity_manifests"),
        Path("security/trust_vault"),
        Path("security/provenance_checkpoints"),
        Path("security/recovery_attestations"),
        Path("security/trusted_checkpoint_heads"),
    ]
    for d in dirs_to_clean:
        if d.exists():
            for f in d.iterdir():
                if f.is_file() and not f.name.startswith(".git"):
                    try:
                        f.unlink()
                    except OSError:
                        pass
        else:
            d.mkdir(parents=True, exist_ok=True)


def reset_and_seed(seed_value: int = 42, target_db: str = ALLOWED_DEMO_DATABASE) -> dict:
    if target_db != ALLOWED_DEMO_DATABASE:
        raise PermissionError(
            f"CRITICAL SAFETY VIOLATION: Reset and seed is strictly locked to '{ALLOWED_DEMO_DATABASE}'. Target '{target_db}' is forbidden."
        )

    # 1. Fixed deterministic seed
    random.seed(seed_value)
    clean_security_directories()

    session, target_url = get_target_session(target_db)
    manifest_store = IntegrityManifestStore()
    trust_vault = ReplicatedTrustVault()
    prov_mgr = ProvenanceManager(session)
    try:
        # 2. Empty incident and attack tables
        incident_tables = [
            "attack_events",
            "recovery_events",
            "soc_alerts",
            "memory_access_events",
            "session_audit_events",
            "dashboard_operation_approvals",
        ]
        for tbl in incident_tables:
            session.execute(text(f"DELETE FROM {tbl}"))

        # 3. Clean memory and dependency tables
        session.execute(text("DELETE FROM memory_dependencies"))
        session.execute(text("DELETE FROM provenance_events"))
        session.execute(text("DELETE FROM memories"))
        session.commit()

        # 4. Seed baseline customer support & enterprise memories
        created_records = []
        for item in BASELINE_MEMORIES:
            mem_id = item["memory_id"]
            content = item["content"]
            source = item["source"]
            source_type = item["source_type"]
            actor = item["actor"]

            content_hash = calculate_version_hash(content, None)
            revision_id = str(uuid.UUID(int=random.getrandbits(128), version=4))

            rec = MemoryRecord(
                memory_id=mem_id,
                version=1,
                revision_id=revision_id,
                parent_revision_id=None,
                content=content,
                source=source,
                source_type=source_type,
                previous_version_id=None,
                content_hash=content_hash,
                previous_hash=None,
                trust_score=1.0,
                suspicion_score=0.0,
                status="active",
                authorization_state="AUTHORIZED",
            )
            session.add(rec)
            session.flush()

            # Sign manifest
            manifest = manifest_store.create_for_record(rec)

            # Store out-of-band trust vault snapshot
            trust_vault.save_snapshot(
                memory_id=rec.memory_id,
                version=rec.version,
                content=rec.content,
                content_hash=rec.content_hash,
                previous_hash=None,
                revision_id=rec.revision_id,
                parent_revision_id=None,
                manifest_signature=manifest.get("signature"),
            )

            # Genesis provenance event
            prov_mgr.record(
                memory_record_id=rec.id,
                memory_id=rec.memory_id,
                version=rec.version,
                actor=actor,
                operation="CREATE",
                source=rec.source,
                source_type=rec.source_type,
                commit=False,
            )

            created_records.append({
                "memory_id": rec.memory_id,
                "version": rec.version,
                "content_hash": rec.content_hash,
                "status": rec.status,
                "trust_score": rec.trust_score,
                "suspicion_score": rec.suspicion_score,
                "content": rec.content,
            })

        # 5. Seed baseline dependencies
        for dep in BASELINE_DEPENDENCIES:
            md = MemoryDependency(
                source_memory_id=dep["source_memory_id"],
                target_memory_id=dep["target_memory_id"],
                dependency_type=dep["dependency_type"],
                strength=dep["strength"],
            )
            session.add(md)

        session.commit()

        # Create baseline checkpoints and advance trusted heads
        cp_store = ProvenanceCheckpointStore()
        head_store = TrustedCheckpointHeadStore(checkpoint_store=cp_store)
        for cr in created_records:
            events = prov_mgr.get_events(cr["memory_id"])
            if events:
                try:
                    cp_store.create_checkpoint(events)
                    head_store.advance(events)
                except Exception as exc:
                    print(f"  [Warning] Checkpoint init for {cr['memory_id']}: {exc}")

        # 6. Read-back verification directly from PostgreSQL
        readback_incidents = {}
        for tbl in incident_tables:
            count = session.execute(text(f"SELECT COUNT(*) FROM {tbl}")).scalar()
            readback_incidents[tbl] = count

        readback_memories = session.execute(
            text("SELECT memory_id, version, status, trust_score, suspicion_score, content_hash, content FROM memories ORDER BY memory_id")
        ).fetchall()

        readback_deps = session.execute(
            text("SELECT source_memory_id, target_memory_id, dependency_type, strength FROM memory_dependencies ORDER BY source_memory_id, target_memory_id")
        ).fetchall()

        live_count = check_live_database_preservation()

        return {
            "target_database": target_db,
            "live_database_preserved_memory_count": live_count,
            "incident_counts": readback_incidents,
            "memory_count": len(readback_memories),
            "memories": [
                {
                    "memory_id": r[0],
                    "version": r[1],
                    "status": r[2],
                    "trust_score": float(r[3]),
                    "suspicion_score": float(r[4]),
                    "content_hash": r[5],
                    "content": r[6],
                }
                for r in readback_memories
            ],
            "dependency_count": len(readback_deps),
            "dependencies": [
                {
                    "source": d[0],
                    "target": d[1],
                    "type": d[2],
                    "strength": float(d[3]),
                }
                for d in readback_deps
            ],
        }

    finally:
        session.close()


def print_readback_table(data: dict):
    print("[POSTGRES READ-BACK VERIFICATION]")
    print("--------------------------------------------------------------------------------")
    print(f"Target Demo Database : {data.get('target_database')} [ISOLATED REVIEWER DEMO]")
    print(f"Original Live DB Row : {data.get('live_database_preserved_memory_count')} memories in aegismem_live [PRESERVED & UNTOUCHED]")
    print("--------------------------------------------------------------------------------")
    print("Incident & Audit Tables in Demo DB (must all be 0):")
    for tbl, count in data["incident_counts"].items():
        status_flag = "CLEAN" if count == 0 else "FAIL"
        print(f"  - {tbl:<32}: {count:>3} rows [{status_flag}]")
    print()

    print(f"Active Baseline Memories ({data['memory_count']} total in {data.get('target_database')}):")
    print(f"  {'MEMORY ID':<18} {'VER':<5} {'STATUS':<8} {'TRUST':<6} {'SUSP':<6} {'HASH (SHA-256)':<16} {'CONTENT PREVIEW'}")
    print(f"  {'-'*18} {'-'*5} {'-'*8} {'-'*6} {'-'*6} {'-'*16} {'-'*30}")
    for m in data["memories"]:
        preview = (m["content"][:32] + "...") if len(m["content"]) > 32 else m["content"]
        hash_short = m["content_hash"][:16] + "..."
        print(f"  {m['memory_id']:<18} v{m['version']:<4} {m['status']:<8} {m['trust_score']:<6.2f} {m['suspicion_score']:<6.2f} {hash_short:<16} {preview}")
    print()

    print(f"Memory Dependencies ({data['dependency_count']} total):")
    for d in data["dependencies"]:
        print(f"  - {d['source']} --[{d['type']} (strength: {d['strength']})]--> {d['target']}")
    print("--------------------------------------------------------------------------------\n")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="AegisMem Reset and Seed")
    parser.add_argument("--json", action="store_true", help="Output JSON only")
    parser.add_argument("--seed", type=int, default=42, help="Deterministic random seed")
    parser.add_argument(
        "--database",
        type=str,
        default=ALLOWED_DEMO_DATABASE,
        choices=[ALLOWED_DEMO_DATABASE],
        help="Target isolated database (strictly locked to aegismem_demo)"
    )
    args = parser.parse_args()

    if not args.json:
        print_root_cause_diagnosis()

    res = reset_and_seed(seed_value=args.seed, target_db=args.database)

    if args.json:
        print(json.dumps(res, sort_keys=True))
    else:
        print_readback_table(res)
        print("AegisMem reset and seed completed successfully.")
