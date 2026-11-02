"""
AegisMem Enterprise Support Agent Microservice
Customer-facing AI agent listening on public-net and data-net.
Performs retrieval strictly through ReadPathGate and answers customer inquiries.
"""
import os
import sys
from pathlib import Path
from typing import Optional
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

# Ensure repository root is on sys.path
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from core.memory.database import get_session
from core.memory.repository import MemoryRepository
from core.gateway.read_gate import ReadPathGate
from agent.runtime.agent import EnterpriseAgent

app = FastAPI(title="AegisMem Support Agent Service", version="1.0.0")


class ChatQueryRequest(BaseModel):
    question: str
    memory_id: Optional[str] = "POLICY-001"
    protection: Optional[bool] = True
    session_id: Optional[str] = None


@app.get("/health")
def health():
    return {
        "status": "healthy",
        "service": "support-agent",
        "agent_backend": "deterministic_rule",
    }


@app.post("/chat")
def chat(req: ChatQueryRequest):
    question = req.question.strip()
    if not question:
        raise HTTPException(status_code=400, detail="Question cannot be empty.")

    session = get_session()
    try:
        repository = MemoryRepository(session)
        target_memory = req.memory_id or "POLICY-001"

        if req.protection:
            read_gate = ReadPathGate(repository)
            verified_record = read_gate.get_verified_memory(
                target_memory,
                fail_closed=True,
                session_id=req.session_id,
            )
            if verified_record is None:
                current = repository.get_latest(target_memory)
                return {
                    "answer": (
                        "I found relevant enterprise memory, "
                        "but AegisMem blocked it because the memory "
                        "could not be verified as trusted."
                    ),
                    "mode": "enterprise",
                    "memory_used": True,
                    "aegismem_verified": False,
                    "protection_active": True,
                    "decision": "BLOCKED",
                    "memory_id": target_memory,
                    "memory_version": current.version if current else None,
                    "trust": current.trust_score if current else None,
                    "trust_score": current.trust_score if current else None,
                    "status": current.status if current else "UNKNOWN",
                    "policy_limit": None,
                    "security_reason": "ReadPathGate blocked unverified or corrupted memory.",
                }

            agent = EnterpriseAgent(session, allow_untrusted=False)
            result = agent.answer_question(
                memory_id=target_memory,
                question=question,
            )
            result["mode"] = "enterprise"
            result["memory_used"] = True
            result["aegismem_verified"] = True
            result["protection_active"] = True
            result["security_reason"] = "Memory passed AegisMem ReadPathGate security verification."
            print(
                f"[Support Agent] Query: '{question}' -> Decision: {result.get('decision')} "
                f"(v{result.get('memory_version')}, verified=True)",
                flush=True,
            )
            return result
        else:
            # Unprotected baseline mode
            current = repository.get_latest(target_memory)
            if not current:
                raise HTTPException(status_code=404, detail=f"Memory '{target_memory}' not found")
            agent = EnterpriseAgent(session, allow_untrusted=True)
            result = agent.answer_question(
                memory_id=target_memory,
                question=question,
            )
            result["mode"] = "enterprise"
            result["memory_used"] = True
            result["aegismem_verified"] = False
            result["protection_active"] = False
            result["security_reason"] = "Protection disabled: unverified memory served without gate."
            print(
                f"[Support Agent] Query: '{question}' -> Decision: {result.get('decision')} "
                f"(v{result.get('memory_version')}, verified=False)",
                flush=True,
            )
            return result
    except Exception as exc:
        print(f"[Support Agent ERROR] Failed processing query: {type(exc).__name__}: {exc}", flush=True)
        raise HTTPException(status_code=500, detail=str(exc))
    finally:
        session.close()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
