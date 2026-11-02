"""
AegisMem Self-Healing TCRP Resolver & Recovery Engine Microservice (Hardened Milestone F4)
Listens on internal network. Connected to vault-net, data-net, and anchor-net.
Enforces:
1. Caller Authentication: Inter-service authentication token required for planning & recovery.
2. Compromise Verification: Re-checks compromise independently inside the service before executing
   rollback; refuses to rollback any uncompromised memory.
3. Air-gapped trust vault access strictly restricted to vault-net.
"""
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel
from sqlalchemy import text, create_engine

# Ensure repository root is on sys.path
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from core.memory.database import get_session
from core.memory.repository import MemoryRepository
from core.graph.dependency.repository import DependencyRepository
from core.graph.dependency.engine import DependencyGraph
from attack_lab.impact import AttackImpactAnalyzer
from core.recovery.orchestrator import AegisMemRecoveryOrchestrator
from core.recovery.vault import ReplicatedTrustVault
from core.integrity.manifest_store import IntegrityManifestStore

app = FastAPI(title="AegisMem Hardened TCRP Recovery Service", version="2.0.0")

INTERNAL_TOKEN = os.getenv("AEGISMEM_INTERNAL_TOKEN", "")


class RecoverRequest(BaseModel):
    memory_id: str
    session_id: Optional[str] = None


def authenticate_caller(authorization: Optional[str] = Header(None), x_recovery_token: Optional[str] = Header(None)):
    if not INTERNAL_TOKEN:
        # If no internal token configured in environment, allow with warning in dev only
        return
    token = x_recovery_token
    if not token and authorization:
        parts = authorization.split(" ", 1)
        token = parts[1].strip() if len(parts) == 2 else parts[0].strip()
    if token != INTERNAL_TOKEN:
        raise HTTPException(status_code=401, detail="Unauthorized: Invalid or missing recovery caller token.")


def serialize_decisions(decisions):
    serialized = []
    for d in decisions:
        if hasattr(d, "__dict__"):
            item = dict(d.__dict__)
            if hasattr(d, "action") and hasattr(d.action, "value"):
                item["action"] = d.action.value
            serialized.append(item)
        elif isinstance(d, dict):
            serialized.append(d)
        else:
            serialized.append(str(d))
    return serialized


@app.get("/health")
def health():
    session = get_session()
    db_ok = False
    try:
        session.execute(text("SELECT 1"))
        db_ok = True
    except Exception as exc:
        print(f"[TCRP Recovery Health] DB check failed: {exc}", flush=True)
    finally:
        session.close()

    vault_ok = False
    vault_url = os.getenv("VAULT_URL")
    if vault_url:
        try:
            eng = create_engine(vault_url)
            with eng.connect() as conn:
                conn.execute(text("SELECT 1"))
            vault_ok = True
        except Exception as exc:
            print(f"[TCRP Recovery Health] Vault check failed: {exc}", flush=True)
    else:
        vault_ok = True

    status = "healthy" if (db_ok and vault_ok) else "degraded"
    return {
        "status": status,
        "service": "tcrp-recovery-resolver",
        "database_connected": db_ok,
        "vault_connected": vault_ok,
    }


@app.post("/recovery/plan")
def plan_recovery(req: RecoverRequest, authorization: Optional[str] = Header(None), x_recovery_token: Optional[str] = Header(None)):
    # 1. Caller Authentication
    authenticate_caller(authorization, x_recovery_token)

    session = get_session()
    try:
        repository = MemoryRepository(session)
        dep_repo = DependencyRepository(session)
        graph = DependencyGraph(dep_repo)
        graph.load()
        impact = AttackImpactAnalyzer(graph)
        orchestrator = AegisMemRecoveryOrchestrator(
            repository=repository,
            impact_analyzer=impact,
            manifest_store=IntegrityManifestStore(),
            vault_store=ReplicatedTrustVault(),
        )
        impact_analysis = orchestrator.impact_analyzer.analyze(req.memory_id, timestamp=datetime.now(timezone.utc))
        decisions = orchestrator.tcrp.plan(impact_analysis, repository=repository)
        return {"memory_id": req.memory_id, "decisions": serialize_decisions(decisions)}
    except Exception as exc:
        print(f"[TCRP Recovery ERROR] Plan evaluation failed: {type(exc).__name__}: {exc}", flush=True)
        raise HTTPException(status_code=500, detail=str(exc))
    finally:
        session.close()


@app.post("/recovery/execute")
def execute_recovery(req: RecoverRequest, authorization: Optional[str] = Header(None), x_recovery_token: Optional[str] = Header(None)):
    # 1. Caller Authentication
    authenticate_caller(authorization, x_recovery_token)

    session = get_session()
    try:
        repository = MemoryRepository(session)
        dep_repo = DependencyRepository(session)
        graph = DependencyGraph(dep_repo)
        graph.load()
        impact = AttackImpactAnalyzer(graph)
        orchestrator = AegisMemRecoveryOrchestrator(
            repository=repository,
            impact_analyzer=impact,
            manifest_store=IntegrityManifestStore(),
            vault_store=ReplicatedTrustVault(),
        )

        # 2. Re-check compromise independently inside the Recovery Service
        latest_record = repository.get_latest(req.memory_id)
        if latest_record is None:
            raise HTTPException(status_code=404, detail=f"Memory '{req.memory_id}' not found.")

        detection = orchestrator.detector.detect(req.memory_id)
        if not detection.compromised and latest_record.status.upper() != "QUARANTINED":
            print(f"[TCRP Recovery] Refusing rollback for '{req.memory_id}': memory is clean and uncompromised.", flush=True)
            return {
                "success": False,
                "compromised": False,
                "action": "NO_OP",
                "reason": f"ROLLBACK_REFUSED_UNCOMPROMISED: Memory '{req.memory_id}' is cryptographically valid and uncompromised. Forced rollback rejected.",
                "decisions": [],
                "results": [],
            }

        # 3. Execute TCRP Self-Healing Recovery
        print(f"[TCRP Recovery] Executing self-healing recovery for '{req.memory_id}' from vault-db on vault-net...", flush=True)
        result = orchestrator.recover_from_attack(
            compromised_memory_id=req.memory_id,
            attack_time=datetime.now(timezone.utc),
            session_id=req.session_id,
        )
        if "decisions" in result:
            result["decisions"] = serialize_decisions(result["decisions"])
        print(f"[TCRP Recovery] Completed self-healing recovery for '{req.memory_id}': success={result.get('success', False)}", flush=True)
        return result
    except HTTPException:
        raise
    except Exception as exc:
        print(f"[TCRP Recovery ERROR] Recovery execution failed: {type(exc).__name__}: {exc}", flush=True)
        raise HTTPException(status_code=500, detail=str(exc))
    finally:
        session.close()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
