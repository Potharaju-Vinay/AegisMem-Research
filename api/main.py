import re
import os
import json
import urllib.request
from dotenv import load_dotenv
load_dotenv()
from typing import Optional
import difflib
import random
from datetime import datetime, timezone
from core.security.dashboard_session import DashboardSession
from sqlalchemy import select
from core.memory.database import SessionLocal
from core.recovery.audit import RecoveryEvent
from core.soc.engine import create_soc_alert
from core.security.request_signatures import verify_owner_request_signature
from core.soc.session_audit import SessionAuditEvent
from core.recovery.validator import RecoveryValidator
from fastapi.middleware.cors import CORSMiddleware

from core.memory.models import MemoryRecord
from core.integrity.hash import (
    calculate_version_hash,
    calculate_content_hash
)


from pydantic import BaseModel

from core.memory.database import get_session
from core.memory.repository import MemoryRepository
from core.graph.dependency.engine import DependencyGraph
from core.graph.dependency.repository import DependencyRepository
from core.detection.detector import MemoryCompromiseDetector
from core.recovery.orchestrator import AegisMemRecoveryOrchestrator

from attack_lab.agent_attack import PromptInjectionAttack
from attack_lab.memory_poisoning import MemoryPoisoningHandler
from attack_lab.memory_deletion import MemoryDeletionAttack
from attack_lab.attacker import MemoryAttacker
from attack_lab.impact import AttackImpactAnalyzer
from attack_lab.models import AttackEvent
from attack_lab.external_attack import ExternalMemoryAttacker

from core.provenance.manager import ProvenanceManager

from agent.runtime.agent import EnterpriseAgent
from agent.retrieval.resolver import MemoryResolver
from core.security.monitor import AegisMemSecurityMonitor
from core.security.access import MemoryAccessLogger
import asyncio
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Request, Depends

from core.security.watcher import AegisMemWatcher
from core.provenance.models import ProvenanceEvent
from core.security.owner_approval import verify_record_owner_approval
from core.security.owner_auth import load_owner_token
from core.security.owner_auth import attack_lab_enabled, verify_owner_token

from core.integrity.manifest_store import IntegrityManifestStore
from core.provenance.checkpoint import ProvenanceCheckpointStore
from core.provenance.trusted_head import TrustedCheckpointHeadStore
from core.recovery.vault import ReplicatedTrustVault
import secrets
from pathlib import Path
from urllib.parse import quote

from core.security.owner_signing_client import (
    load_signing_key,
    sign_http_request,
    encode_json_body,
)

from core.security.dashboard_operation import (
    authorize_dashboard_operation,
    consume_dashboard_operation,
    DashboardOperationAuthorizationError,
)


from fastapi.responses import JSONResponse
from core.soc.models import SOCAlert
from core.security.dashboard_sessions import (
    SESSION_COOKIE_NAME,
    verify_dashboard_password,
    create_dashboard_session,
    validate_dashboard_session,
    revoke_dashboard_session,
    record_session_audit,
)


def require_owner(http_request: Request):
    if not load_owner_token():
        raise HTTPException(
            status_code=503,
            detail="Owner authentication is not configured."
        )

    if not verify_owner_token(
        http_request.headers.get("authorization")
    ):
        raise HTTPException(
            status_code=401,
            detail="Valid owner bearer credentials are required."
        )
        
def require_owner_signature(http_request: Request):
    require_owner(http_request)

    timestamp = http_request.headers.get("x-owner-timestamp")
    nonce = http_request.headers.get("x-owner-nonce")
    signature = http_request.headers.get("x-owner-signature")
    raw_body = getattr(http_request.state, "raw_body", None)

    if raw_body is None:
        raise HTTPException(
            status_code=401,
            detail="A valid owner digital signature is required."
        )

    if not verify_owner_request_signature(
        http_request.method,
        http_request.url.path,
        timestamp,
        nonce,
        signature,
        raw_body,
    ):
        raise HTTPException(
            status_code=401,
            detail="A valid owner digital signature is required."
        )
        
def get_active_db_name() -> str:
    db_url = os.environ.get("DATABASE_URL", "")
    if "/" in db_url:
        return db_url.split("/")[-1].split("?")[0]
    return os.environ.get("AEGISMEM_DB_NAME", "aegismem_demo")


DASHBOARD_ALLOWED_ORIGINS = {
    "http://localhost:5173",
    "http://127.0.0.1:5173",
}


def require_dashboard_auth(http_request: Request):
    session_id = http_request.cookies.get(SESSION_COOKIE_NAME)

    if not validate_dashboard_session(session_id):
        raise HTTPException(
            status_code=401,
            detail="Valid dashboard session required.",
        )


def require_trusted_dashboard_origin(http_request: Request):
    origin = http_request.headers.get("origin")

    if origin not in DASHBOARD_ALLOWED_ORIGINS:
        raise HTTPException(
            status_code=403,
            detail="Untrusted origin.",
        )


class DashboardLoginRequest(BaseModel):
    password: str




@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        from core.memory.init_db import initialize_database
        initialize_database()
        from scripts.sync_sqlite_to_postgres import auto_sync_if_needed
        auto_sync_if_needed()
    except Exception as exc:
        print(f"[AegisMem Startup] Database initialization: {exc}")

    watcher_interval = float(os.getenv("AEGIS_WATCHER_INTERVAL", "2.0"))
    watcher_event_driven = os.getenv("AEGIS_WATCHER_EVENT_DRIVEN", "false").lower() in ("true", "1", "yes")
    watcher = AegisMemWatcher(
        interval_seconds=watcher_interval,
        event_driven=watcher_event_driven
    )

    app.state.aegismem_watcher = watcher

    enable_in_process_watcher = os.getenv("AEGIS_ENABLE_IN_PROCESS_WATCHER", "false").lower() in ("true", "1", "yes")
    if enable_in_process_watcher:
        watcher_task = asyncio.create_task(
            watcher.run()
        )
        app.state.aegismem_watcher_task = watcher_task
    else:
        app.state.aegismem_watcher_task = None

    try:
        yield

    finally:
        watcher.stop()
        if getattr(app.state, "aegismem_watcher_task", None):
            await app.state.aegismem_watcher_task


app = FastAPI(
    title="AegisMem API",
    description="Self-healing persistent memory protection for enterprise AI agents",
    version="1.0.0",
    lifespan=lifespan
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=[
        "Content-Type",
        "Authorization",
        "X-Owner-Timestamp",
        "X-Owner-Nonce",
        "X-Owner-Signature",
    ],
)


@app.post("/auth/login")
def dashboard_login(
    payload: DashboardLoginRequest,
    http_request: Request,
):
    require_trusted_dashboard_origin(http_request)

    if not verify_dashboard_password(payload.password):
        record_session_audit(
            event_type="LOGIN",
            outcome="FAILURE",
            source_ip=http_request.client.host if http_request.client else None,
            user_agent=http_request.headers.get("user-agent"),
            detail="Invalid dashboard password",
        )
        raise HTTPException(status_code=401, detail="Invalid password.")

    session_id = create_dashboard_session()

    record_session_audit(
        event_type="LOGIN",
        outcome="SUCCESS",
        source_ip=http_request.client.host if http_request.client else None,
        user_agent=http_request.headers.get("user-agent"),
        raw_session_id=session_id,
    )

    response = JSONResponse({"authenticated": True})
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=session_id,
        httponly=True,
        secure=http_request.url.scheme == "https",
        samesite="strict",
        max_age=8 * 60 * 60,
        path="/",
    )
    return response


@app.get("/auth/session")
def dashboard_session_status(http_request: Request):
    session_id = http_request.cookies.get(SESSION_COOKIE_NAME)
    return {"authenticated": validate_dashboard_session(session_id)}


@app.post("/auth/logout")
def dashboard_logout(http_request: Request):
    require_trusted_dashboard_origin(http_request)

    session_id = http_request.cookies.get(SESSION_COOKIE_NAME)
    revoke_dashboard_session(session_id)

    record_session_audit(
        event_type="LOGOUT",
        outcome="SUCCESS",
        source_ip=http_request.client.host if http_request.client else None,
        user_agent=http_request.headers.get("user-agent"),
        raw_session_id=session_id,
    )

    response = JSONResponse({"authenticated": False})
    response.delete_cookie(
        key=SESSION_COOKIE_NAME,
        path="/",
        httponly=True,
        secure=http_request.url.scheme == "https",
        samesite="strict",
    )
    return response

@app.middleware("http")
async def cache_raw_request_body(request: Request, call_next):
    body = await request.body()
    request.state.raw_body = body

    async def receive():
        return {
            "type": "http.request",
            "body": body,
            "more_body": False,
        }

    request._receive = receive
    return await call_next(request)


class ChatRequest(BaseModel):
    question: str
    protection: bool = True


class RefundRequest(BaseModel):
    customer_days: int
    protection: bool = True


class ExternalMemoryWriteRequest(BaseModel):
    memory_id: str
    modified_content: str
    attacker: str = "unknown"
    attack_type: str = "content_tampering"
    session_id: str | None = None
    auto_heal: bool = False
    
class OwnerMemoryWriteRequest(BaseModel):
    memory_id: str
    content: str
    authorization_id: str
    nonce: str
    authorization_signature: str | None = None
    expected_revision_id: str | None = None

class PoisonRequest(BaseModel):
    memory_id: str = "POLICY-001"


class DeleteRequest(BaseModel):
    memory_id: str
    
class DashboardOperationApprovalRequest(BaseModel):
    operation: str
    memory_id: str
    confirmed: bool = False


class DashboardOperationExecutionRequest(BaseModel):
    operation: str
    memory_id: str
    authorization_id: str


def resolve_memory(session, question):
    resolver = MemoryResolver(session)
    return resolver.resolve(question)




def aegismem_security_gate(session, memory_id):
    repository = MemoryRepository(session)
    graph = build_graph(session)
    memory = repository.get_latest(memory_id)

    if memory is None:
        return {
            "memory_id": memory_id,
            "verified": False,
            "compromised": True,
            "suspicion_score": 1.0,
            "reason": "Memory no longer exists.",
            "evidence": {},
            "soc_alert": None,
        }

    detector = MemoryCompromiseDetector(
        repository=repository,
        dependency_graph=graph,
        manifest_store=repository.manifest_store,
    )

    detection = detector.detect(memory_id)
    evidence = detection.evidence
    soc_alert = None

    if detection.compromised:
        soc_alert = create_soc_alert(
            session=session,
            memory_id=memory_id,
            attack_id=f"DETECTION-{memory_id}-V{memory.version}",
            attack_type="memory_compromise_detection",
            evidence={
                "integrity_compromised": evidence.integrity_compromised,
                "provenance_suspicious": evidence.provenance_suspicious,
                "attack_detected": evidence.attack_detected,
                "unauthorized_access": not evidence.authorization_valid,
                "content_changed": evidence.content_changed,
                "dependency_contamination": evidence.dependency_exposure,
            },
        )

    return {
        "memory_id": memory_id,
        "verified": not detection.compromised,
        "compromised": detection.compromised,
        "suspicion_score": detection.suspicion_score,
        "reason": detection.reason,
        "evidence": evidence.__dict__,
        "soc_alert": {
            "alert_id": soc_alert.alert_id,
            "severity": soc_alert.severity,
            "severity_score": soc_alert.severity_score,
            "status": soc_alert.status,
        } if soc_alert else None,
    }



def build_graph(session):
    dependency_repo = DependencyRepository(session)
    graph = DependencyGraph(dependency_repo)
    graph.load()
    return graph



@app.get("/")
def root():
    return {
        "system": "AegisMem",
        "status": "running"
    }


@app.get("/health")
def health():
    return {
        "status": "healthy"
    }


INTENTS = {
    "greeting": {
        "patterns": [
            "hi", "hello", "hey", "hii", "hiii", "hiya", "yo", "sup",
            "good morning", "good afternoon", "good evening", "good day",
            "greetings", "hello assistant", "hey there", "hi there", "morning"
        ],
        "responses": [
            "Hello! Welcome to Enterprise Customer Support AI. How can I help you today?",
            "Hi there! I am your Enterprise Customer Support AI Assistant. How can I assist you with your account, order, or enterprise policies?"
        ]
    },

    "wellbeing": {
        "patterns": [
            "how are you", "how are you doing", "how is it going", "how was your day",
            "how are things", "you good", "are you okay", "how do you do",
            "hows it going", "how are you today", "hope you are well"
        ],
        "responses": [
            "I'm doing great, thank you for asking! I'm actively monitoring our enterprise persistent memory and ready to help you with any customer inquiry or policy question.",
            "I'm performing at 100%, with persistent memory protection fully active. How can I assist you today?"
        ]
    },

    "identity": {
        "patterns": [
            "who are you", "what are you", "what is your name", "tell me about yourself",
            "are you an ai", "are you human", "are you a bot", "what is aegismem",
            "who created you", "what is your role", "what do you represent"
        ],
        "responses": [
            "I am the AegisMem Enterprise Customer Support AI Assistant. I represent enterprise customer service, helping users with refund guidelines, order eligibility, and company security policies, with self-healing memory protection.",
            "I am an enterprise AI agent deployed for customer support, protected by the AegisMem security framework. I ensure all answers are cryptographically verified against persistent memory tampering."
        ]
    },

    "capabilities": {
        "patterns": [
            "what can you do", "what do you do", "what are your features", "how can you help",
            "what can i ask", "what can i ask you", "help me", "how does this work",
            "services", "what services do you offer", "what are your capabilities"
        ],
        "responses": [
            "As your Enterprise Customer Support AI, I can assist you with: (1) Checking refund eligibility and explaining return policies, (2) Looking up enterprise security requirements such as MFA and incident reporting SOPs, (3) Support ticket & complaint escalation procedures, and (4) Answering common daily-life inquiries. All enterprise knowledge is verified by AegisMem before I answer.",
            "I can answer questions regarding customer refund & return terms, calculate eligibility based on purchase dates, provide enterprise security baseline rules, and answer daily conversational questions."
        ]
    },

    "support_hours": {
        "patterns": [
            "hours", "support hours", "opening hours", "when are you open", "business hours",
            "when can i call", "office hours", "availability", "when are you available"
        ],
        "responses": [
            "Our automated Enterprise Customer Support AI is available 24/7/365 to answer questions and check policy eligibility. Live customer specialist escalation is available Monday through Friday from 9:00 AM to 6:00 PM EST.",
            "Our AI assistant operates continuously 24/7 with active memory self-healing. Human support representatives can be reached during standard enterprise business hours (9 AM - 6 PM EST)."
        ]
    },

    "customer_service": {
        "patterns": [
            "support", "customer support", "customer service", "help desk", "talk to human",
            "contact agent", "representative", "contact support", "speak to someone", "human agent"
        ],
        "responses": [
            "You are connected to Enterprise Customer Support AI. You can ask me about refund eligibility, return conditions, order status, or company guidelines. For human escalation, unresolved complaints are forwarded to a Level 2 specialist within 24 hours under SOP-003.",
            "I am happy to assist you directly! If your inquiry requires manual manager review (such as refunds exceeding 30 calendar days), I can guide you through our formal customer support escalation process."
        ]
    },

    "thanks": {
        "patterns": [
            "thanks", "thank you", "thank u", "thx", "appreciate it", "many thanks",
            "thank you so much", "thanks a lot", "great help"
        ],
        "responses": [
            "You're very welcome! Please let me know if you need any further assistance with your customer account or policies.",
            "Glad I could assist! Have a wonderful day, and feel free to reach out if any other questions arise."
        ]
    },

    "apology": {
        "patterns": [
            "sorry", "my bad", "i apologize", "excuse me", "pardon"
        ],
        "responses": [
            "No problem at all! How can I assist you further?",
            "No need to apologize! I'm here to help with any customer inquiries or policy questions."
        ]
    },

    "compliment": {
        "patterns": [
            "you are great", "awesome", "good job", "nice", "cool", "well done",
            "you are smart", "helpful", "perfect", "excellent"
        ],
        "responses": [
            "Thank you for the kind words! I strive to deliver fast, verified, and accurate customer support.",
            "Much appreciated! Ensuring trusted enterprise memory and helpful customer assistance is my top priority."
        ]
    },

    "small_talk": {
        "patterns": [
            "have food", "have you eaten", "did you eat", "did you have food",
            "what are you doing", "whats up", "what's up", "are you busy",
            "are you free", "what time is it", "tell me a joke"
        ],
        "responses": [
            "I don't eat or take breaks, but I'm always ready to help! What enterprise questions or customer support needs do you have?",
            "I'm actively monitoring enterprise memory integrity and helping users like you. What can I help you check today?"
        ]
    },

    "affirmation": {
        "patterns": [
            "ok", "okay", "sure", "sounds good", "alright", "got it", "understood",
            "yes", "yep", "yeah", "cool"
        ],
        "responses": [
            "Great! What would you like to inquire about next?",
            "Understood! Feel free to ask about our refund policy, order eligibility, or enterprise guidelines."
        ]
    },

    "goodbye": {
        "patterns": [
            "bye", "goodbye", "see you", "see ya", "talk later", "have a good day",
            "take care", "cya", "bye bye"
        ],
        "responses": [
            "Goodbye! Thank you for contacting Enterprise Customer Support. Have a great day!",
            "Take care! Remember that our self-healing AI support is available whenever you need assistance."
        ]
    }
}

def normalize(text: str) -> str:
    text = text.lower().strip()
    text = re.sub(r"[^\w\s]", "", text)
    text = re.sub(r"\s+", " ", text)
    return text


def find_intent(text: str) -> Optional[str]:
    for intent, data in INTENTS.items():
        for pattern in data["patterns"]:
            if text == pattern:
                return intent

    words = set(text.split())

    for intent, data in INTENTS.items():
        for pattern in data["patterns"]:
            pattern_words = set(pattern.split())

            if pattern in text:
                return intent

            if len(pattern_words) > 1 and pattern_words.issubset(words):
                return intent

    best_intent = None
    best_score = 0.0

    for intent, data in INTENTS.items():
        for pattern in data["patterns"]:
            score = difflib.SequenceMatcher(
                None,
                text,
                pattern
            ).ratio()

            if score > best_score:
                best_score = score
                best_intent = intent

    if best_score >= 0.80:
        return best_intent

    return None


def answer_general_question(question: str) -> Optional[str]:
    text = normalize(question)

    if not text:
        return None

    enterprise_keywords = {
        "refund", "policy", "sop", "escalat", "escalation", "complaint", "faq",
        "hours", "contact", "mfa", "access", "incident", "backup", "privacy", "credential"
    }
    if any(k in text for k in enterprise_keywords):
        return None

    intent = find_intent(text)

    if intent is None:
        return None

    return random.choice(INTENTS[intent]["responses"])


@app.post("/chat")
def chat(request: ChatRequest, http_request: Request):
    session_id = http_request.cookies.get(SESSION_COOKIE_NAME)
    is_session_valid = bool(session_id and validate_dashboard_session(session_id))
    is_owner_valid = bool(verify_owner_token(http_request.headers.get("authorization")))

    if not is_session_valid:
        if not load_owner_token():
            raise HTTPException(
                status_code=503,
                detail="Owner authentication is not configured."
            )
        if not is_owner_valid:
            raise HTTPException(
                status_code=401,
                detail="Valid owner bearer credentials or authenticated dashboard session are required."
            )

    session = get_session()

    try:
        question = request.question.strip()

        if not question:
            raise HTTPException(
                status_code=400,
                detail="Question cannot be empty."
            )

        general_response = answer_general_question(question)

        if general_response is not None:
            return {
                "answer": general_response,
                "mode": "general",
                "memory_used": False,
                "aegismem_verified": False
            }

        memory = resolve_memory(
            session,
            question
        )

        protection_enabled = bool(request.protection) and (http_request.headers.get("x-aegis-protection", "on").lower() != "off")

        # Delegate query to dedicated Support Agent microservice if available
        support_agent_url = os.getenv("SUPPORT_AGENT_URL", "http://support-agent:8000")
        try:
            req_data = json.dumps({
                "question": question,
                "memory_id": memory.memory_id if memory else "POLICY-001",
                "protection": protection_enabled,
                "session_id": session_id,
            }).encode("utf-8")
            agent_req = urllib.request.Request(
                f"{support_agent_url}/chat",
                data=req_data,
                headers={"Content-Type": "application/json"},
                method="POST"
            )
            with urllib.request.urlopen(agent_req, timeout=5) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except Exception:
            pass

        if protection_enabled:
            security = aegismem_security_gate(
                session,
                memory.memory_id
            )

            if not security["verified"]:
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
                    "memory_id": memory.memory_id,
                    "memory_version": memory.version,
                    "trust": memory.trust_score,
                    "trust_score": memory.trust_score,
                    "status": memory.status,
                    "suspicion_score": security["suspicion_score"],
                    "security_reason": security["reason"]
                }

            agent = EnterpriseAgent(session, allow_untrusted=False)
            result = agent.answer_question(
                memory_id=memory.memory_id,
                question=question
            )
            result["mode"] = "enterprise"
            result["memory_used"] = True
            result["aegismem_verified"] = True
            result["protection_active"] = True
            result["security_reason"] = "Memory passed AegisMem security verification."
            return result
        else:
            # Protection explicitly disabled (evaluation mode for proving harm)
            agent = EnterpriseAgent(session, allow_untrusted=True)
            result = agent.answer_question(
                memory_id=memory.memory_id,
                question=question
            )
            result["mode"] = "enterprise"
            result["memory_used"] = True
            result["aegismem_verified"] = False
            result["protection_active"] = False
            result["security_reason"] = "Protection disabled: unverified memory retrieved without security gate."
            return result

    except LookupError:
        return {
            "answer": (
                "I couldn't find trusted enterprise knowledge "
                "relevant to that question."
            ),
            "mode": "enterprise",
            "memory_used": False,
            "aegismem_verified": False
        }

    except ValueError as e:
        raise HTTPException(
            status_code=403,
            detail=str(e)
        )

    finally:
        session.close()


@app.post("/refund-decision")
def refund_decision(request: RefundRequest, http_request: Request):
    session_id = http_request.cookies.get(SESSION_COOKIE_NAME)
    is_session_valid = bool(session_id and validate_dashboard_session(session_id))
    is_owner_valid = bool(verify_owner_token(http_request.headers.get("authorization")))

    if not is_session_valid:
        if not load_owner_token():
            raise HTTPException(
                status_code=503,
                detail="Owner authentication is not configured."
            )
        if not is_owner_valid:
            raise HTTPException(
                status_code=401,
                detail="Valid owner bearer credentials or authenticated dashboard session are required."
            )

    session = get_session()

    try:
        memory = resolve_memory(
            session,
            "What is the refund policy?"
        )

        protection_enabled = bool(request.protection) and (http_request.headers.get("x-aegis-protection", "on").lower() != "off")

        if protection_enabled:
            security = aegismem_security_gate(
                session,
                memory.memory_id
            )

            if not security["verified"]:
                return {
                    "memory_id": memory.memory_id,
                    "memory_version": memory.version,
                    "customer_days": request.customer_days,
                    "decision": "BLOCKED",
                    "reason": (
                        "AegisMem blocked the decision because "
                        "the policy memory could not be verified as trusted."
                    ),
                    "trust_score": memory.trust_score,
                    "status": memory.status,
                    "suspicion_score": security["suspicion_score"],
                    "security_reason": security["reason"]
                }

            agent = EnterpriseAgent(session, allow_untrusted=False)
            return agent.make_refund_decision(
                memory_id=memory.memory_id,
                customer_days=request.customer_days
            )
        else:
            agent = EnterpriseAgent(session, allow_untrusted=True)
            res = agent.make_refund_decision(
                memory_id=memory.memory_id,
                customer_days=request.customer_days
            )
            res["protection_active"] = False
            return res

    except LookupError as e:
        raise HTTPException(
            status_code=404,
            detail=str(e)
        )

    except ValueError as e:
        raise HTTPException(
            status_code=403,
            detail=str(e)
        )

    finally:
        session.close()
        
@app.post("/owner/memory/write")
def owner_memory_write(
    request: OwnerMemoryWriteRequest,
    http_request: Request
):

        
    require_owner_signature(http_request)
    session = get_session()

    try:
        authorization_id = request.authorization_id
        nonce = request.nonce

        repository = MemoryRepository(session)

        record = repository.create_owner_authorized(
            memory_id=request.memory_id,
            content=request.content,
            source="enterprise_owner",
            authorization_id=authorization_id,
            nonce=nonce,
            authorization_signature=request.authorization_signature,
            expected_revision_id=request.expected_revision_id,
            record_provenance=True,
        )

        try:
            prov_mgr = ProvenanceManager(session)
            events = prov_mgr.get_events(record.memory_id)
            if events:
                cp_store = ProvenanceCheckpointStore()
                head_store = TrustedCheckpointHeadStore(checkpoint_store=cp_store)
                cp_store.create_checkpoint(events)
                head_store.advance(events)
        except Exception:
            pass

        return {
            "memory_id": record.memory_id,
            "version": record.version,
            "revision_id": record.revision_id,
            "authorization_id": record.authorization_id,
            "authorization_state": record.authorization_state,
            "content_hash": record.content_hash
        }

    except ValueError as e:
        raise HTTPException(
            status_code=403,
            detail=str(e)
        )

    finally:
        session.close()


@app.get("/attacker/memory/{memory_id}")
@app.get("/api/memories/{memory_id}")
def read_memory_endpoint(
    memory_id: str,
    http_request: Request,
    actor: str = "unknown",
    session_id: str | None = None,
):
    if not attack_lab_enabled():
        raise HTTPException(status_code=403, detail="Attack lab is disabled.")
    session = get_session()
    try:
        repository = MemoryRepository(session)
        current = repository.get_latest(memory_id)
        if current is None:
            raise HTTPException(status_code=404, detail=f"Memory '{memory_id}' not found.")
        
        client = http_request.client
        source_ip = client.host if client else None
        source_port = client.port if client else None
        sess_id = session_id or http_request.headers.get("x-session-id") or http_request.headers.get("x-attacker-session")
        act = http_request.headers.get("x-actor") or actor

        access_logger = MemoryAccessLogger(session)
        access_event = access_logger.record(
            memory_id=memory_id,
            memory_version=current.version,
            actor=act,
            session_id=sess_id,
            source_ip=source_ip,
            source_port=source_port,
            entry_point=http_request.url.path,
            access_method=http_request.method,
            authorization_state="UNAUTHORIZED"
        )
        session.commit()
        return {
            "access_id": access_event.access_id,
            "memory_id": current.memory_id,
            "version": current.version,
            "content": current.content,
            "status": current.status,
            "trust_score": current.trust_score,
            "source_ip": source_ip,
            "source_port": source_port,
            "session_id": sess_id,
            "access_method": http_request.method,
            "entry_point": http_request.url.path
        }
    finally:
        session.close()


@app.post("/attacker/memory/write")
def attacker_memory_write(
    request: ExternalMemoryWriteRequest,
    http_request: Request,
):
    if not attack_lab_enabled():
        raise HTTPException(
                status_code=403,
                detail="Attack lab is disabled."
            )
    session = get_session()


    try:
        authorization = {
    "authorized": False,
    "authorization_state": "UNAUTHORIZED",
    "reason": "External attacker is not an authorized memory owner."
}

        repository = MemoryRepository(session)

        current = repository.get_latest(
            request.memory_id
        )

        if current is None:
            raise HTTPException(
                status_code=404,
                detail=f"Memory '{request.memory_id}' does not exist."
            )

        client = http_request.client

        source_ip = (
            client.host
            if client is not None
            else None
        )

        source_port = (
            client.port
            if client is not None
            else None
        )

        access_logger = MemoryAccessLogger(
            session
        )

        access_event = access_logger.record(
            memory_id=request.memory_id,
            memory_version=current.version,
            actor=request.attacker,
            session_id=request.session_id,
            source_ip=source_ip,
            source_port=source_port,
            entry_point=http_request.url.path,
            access_method=http_request.method,
            authorization_state=(
                "AUTHORIZED"
                if authorization["authorized"]
                else "UNAUTHORIZED"
            )
        )

        session.commit()

        attacker = ExternalMemoryAttacker(
            session
        )

        attack_result = attacker.modify_memory(
            memory_id=request.memory_id,
            modified_content=request.modified_content,
            attacker=request.attacker,
            attack_type=request.attack_type,
            session_id=request.session_id,
            source_ip=source_ip,
            source_port=source_port,
            entry_point=http_request.url.path,
            access_method=http_request.method
        )

        if request.auto_heal:
            monitor = AegisMemSecurityMonitor(session)
            security_result = monitor.process(request.memory_id)
        else:
            security_result = {
                "status": "unrecovered_pending_action",
                "message": "Memory modified without immediate recovery. Pending compromise detection and TCRP resolution."
            }

        return {
            "attack": attack_result,
            "access_id": access_event.access_id,
            "authorization": authorization,
            "provenance_id": attack_result["provenance_id"],
            "aegismem": security_result
        }
            
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc)
        )

    finally:
        session.close()



@app.post("/lab/memory/write")
def external_memory_write(
    request: ExternalMemoryWriteRequest,
    http_request: Request,
):
    
    
        
    require_owner_signature(http_request)
    
    if not attack_lab_enabled():
            raise HTTPException(
                status_code=403,
                detail="Attack lab is disabled."
            )
            
    session = get_session()


    try:
        attacker = ExternalMemoryAttacker(session)

        attack_result = attacker.modify_memory(
            memory_id=request.memory_id,
            modified_content=request.modified_content,
            attacker=request.attacker,
            attack_type=request.attack_type
        )

        monitor = AegisMemSecurityMonitor(session)

        security_result = monitor.process(
            request.memory_id
        )

        return {
            "attack": attack_result,
            "aegismem": security_result
        }

    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc)
        )

    finally:
        session.close()



def classify_ip_location(ip: str | None) -> dict:
    if not ip or str(ip).strip() in ("unavailable", "Not recorded", "testclient", "", "None"):
        return {
            "location": "unknown",
            "zone": "unknown",
            "network_type": "unknown",
            "is_adversary": False,
        }
    ip_clean = str(ip).strip()
    if ip_clean in ("127.0.0.1", "localhost", "::1"):
        return {
            "location": "Windows Host Gateway (Localhost)",
            "zone": "Internal Loopback",
            "network_type": "Local System",
            "is_adversary": False,
        }
    elif ip_clean.startswith("172."):
        return {
            "location": f"Docker Adversary Network ({ip_clean})",
            "zone": "Segmented Docker Bridge (public-net)",
            "network_type": "Adversary Container Bridge",
            "is_adversary": True,
        }
    elif ip_clean.startswith("192.168.") or ip_clean.startswith("10."):
        return {
            "location": f"Enterprise Internal Subnet ({ip_clean})",
            "zone": "Private VPC / Subnet",
            "network_type": "Internal LAN",
            "is_adversary": False,
        }
    return {
        "location": f"External Network ({ip_clean})",
        "zone": "WAN Gateway",
        "network_type": "External Internet",
        "is_adversary": True,
    }


@app.post("/lab/adversary/memory/write")
@app.post("/lab/kali/memory/write")
def adversary_lab_memory_write(
    request: ExternalMemoryWriteRequest,
    http_request: Request,
):
    if not attack_lab_enabled():
        raise HTTPException(status_code=403, detail="Attack lab is disabled.")

    lab_token = (os.environ.get("AEGISMEM_LAB_TOKEN") or "").strip().strip('"').strip("'")
    
    # Check X-Aegis-Lab-Token header or fallback to Authorization header
    supplied_token = (
        http_request.headers.get("X-Aegis-Lab-Token")
        or http_request.headers.get("x-aegis-lab-token")
        or ""
    ).strip().strip('"').strip("'").strip("<").strip(">").strip()

    if not supplied_token:
        auth_header = (
            http_request.headers.get("Authorization")
            or http_request.headers.get("authorization")
            or ""
        ).strip()
        if auth_header.lower().startswith("bearer "):
            supplied_token = auth_header[7:].strip().strip('"').strip("'").strip("<").strip(">").strip()
        else:
            supplied_token = auth_header.strip('"').strip("'").strip("<").strip(">").strip()

    if supplied_token.lower().startswith("bearer "):
        supplied_token = supplied_token[7:].strip().strip('"').strip("'")

    if len(lab_token) < 32 or not secrets.compare_digest(
        lab_token, supplied_token
    ):
        raise HTTPException(status_code=401, detail="Invalid lab credentials.")

    client = http_request.client
    source_ip = client.host if client else None

    allowed_memories = {
        "PHASE3-REPLAY",
        "ENT-ACCESS-001",
        "ENT-INCIDENT-002",
        "ENT-BACKUP-003",
        "ENT-DATA-004",
        "ENT-EMPLOYEE-005",
        "POLICY-001",
        "POLICY-002",
        "SOP-003",
    }

    if (
        request.memory_id not in allowed_memories
        and not request.memory_id.startswith("ENT-")
        and not request.memory_id.startswith("POLICY-")
    ):
        raise HTTPException(status_code=403, detail="Memory is not permitted in the lab.")

    session = get_session()

    try:
        attacker = ExternalMemoryAttacker(session)

        attack_result = attacker.modify_memory(
            memory_id=request.memory_id,
            modified_content=request.modified_content,
            attacker=request.attacker if request.attacker and request.attacker != "unknown" else "adversary_container",
            attack_type=request.attack_type,
            session_id=request.session_id,
            source_ip=source_ip,
            source_port=client.port if client else None,
            entry_point=http_request.url.path,
            access_method=http_request.method,
        )

        monitor = AegisMemSecurityMonitor(session)
        security_result = monitor.process(request.memory_id)

        return {
            "attack": attack_result,
            "aegismem": security_result,
        }

    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    finally:
        session.close()


@app.post("/attack/poison")
def poison_memory(
    request: PoisonRequest,
    http_request: Request,
):
    
    
        
    require_owner_signature(http_request)
    
    if not attack_lab_enabled():
            raise HTTPException(
                status_code=403,
                detail="Attack lab is disabled."
            )
    session = get_session()


    try:
        repository = MemoryRepository(session)

        current = repository.get_latest(
            request.memory_id
        )

        if current is None:
            raise HTTPException(
                status_code=404,
                detail=f"Memory '{request.memory_id}' does not exist."
            )

        trusted_content = (
            "Customer refunds are permitted within "
            "30 calendar days of the transaction, "
            "subject to eligibility verification."
        )

        poisoned_content = (
            "Customer refunds are permitted within "
            "180 calendar days of the transaction, "
            "subject to eligibility verification."
        )

        attack = PromptInjectionAttack()

        payload = attack.create_payload(
            target_memory_id=request.memory_id,
            trusted_content=trusted_content,
            poisoned_content=poisoned_content
        )

        poisoning_handler = MemoryPoisoningHandler(
            repository
        )

        poisoned = poisoning_handler.apply(
            payload
        )

        attack_event = AttackEvent(
            attack_id=f"ATTACK-{poisoned.id}",
            memory_record_id=poisoned.id,
            memory_id=poisoned.memory_id,
            original_content=current.content,
            modified_content=poisoned.content,
            original_version=current.version,
            target_version=poisoned.version,
            original_content_hash=calculate_content_hash(
                current.content
            ),
            observed_content_hash=calculate_content_hash(
                poisoned.content
            ),
            attack_type="prompt_injection_memory_poisoning",
            mutation_description=(
                "Persistent refund policy changed from "
                "30 calendar days to 180 calendar days."
            ),
            attacker="adversary_lab",
            attack_time=datetime.now(timezone.utc),
            integrity_compromised=True,
            status="DETECTED"
        )

        session.add(attack_event)
        session.commit()

        provenance_manager = ProvenanceManager(
            session
        )

        provenance_event = provenance_manager.record(
            memory_record_id=poisoned.id,
            memory_id=poisoned.memory_id,
            version=poisoned.version,
            actor="adversary_lab",
            operation="MEMORY_POISON",
            source="prompt_injection_attack",
            source_type="memory_poisoning",
            metadata={
                "attack_id": attack_event.attack_id,
                "attack_type": attack_event.attack_type,
                "original_version": current.version,
                "target_version": poisoned.version,
                "integrity_compromised": True
            }
        )

        return {
            "attack": "prompt_injection_memory_poisoning",
            "attack_id": attack_event.attack_id,
            "provenance_id": provenance_event.id,
            "memory_id": poisoned.memory_id,
            "memory_version": poisoned.version,
            "content": poisoned.content,
            "trust_score": poisoned.trust_score,
            "suspicion_score": poisoned.suspicion_score,
            "status": poisoned.status
        }

    finally:
        session.close()



@app.post("/attack/delete")
def delete_memory(
    request: DeleteRequest,
    http_request: Request,
):
    
    
        
    require_owner_signature(http_request)
    
    if not attack_lab_enabled():
            raise HTTPException(
                status_code=403,
                detail="Attack lab is disabled."
            )
            
    session = get_session()


    try:
        attack = MemoryDeletionAttack(session)

        event = attack.delete_memory(
            memory_id=request.memory_id
        )

        return {
            "attack": "memory_deletion",
            "attack_id": event.attack_id,
            "memory_id": event.memory_id,
            "memory_version": event.target_version,
            "attack_type": event.attack_type,
            "trust_score": 0.0,
            "status": "DELETED",
            "mutation_description": event.mutation_description
        }

    except ValueError as exc:
        raise HTTPException(
            status_code=404,
            detail=str(exc)
        )

    finally:
        session.close()



@app.post("/attack/tamper")
def tamper_memory(
    request: DeleteRequest,
    http_request: Request,
):
    
    
        
    require_owner_signature(http_request)
    
    if not attack_lab_enabled():
            raise HTTPException(
                status_code=403,
                detail="Attack lab is disabled."
            )
    session = get_session()


    try:
        repository = MemoryRepository(session)

        current = repository.get_latest(
            request.memory_id
        )

        if current is None:
            raise HTTPException(
                status_code=404,
                detail=f"Memory '{request.memory_id}' does not exist."
            )

        if current.status != "active":
            raise HTTPException(
                status_code=400,
                detail="Only active memory can be attacked."
            )

        corrupted_content = (
            "Customer refunds are permitted within "
            "180 calendar days of the transaction, "
            "subject to eligibility verification."
        )

        attacker = MemoryAttacker(session)

        event = attacker.corrupt_memory(
            memory=current,
            corrupted_content=corrupted_content,
            attack_type="content_tampering",
            mutation_description=(
                "Persistent refund policy changed from "
                "30 calendar days to 180 calendar days "
                "through controlled content tampering."
            ),
            attacker="adversary_lab"
        )

        return {
            "attack": "content_tampering",
            "attack_id": event.attack_id,
            "memory_id": event.memory_id,
            "memory_version": event.target_version,
            "original_version": event.original_version,
            "attack_type": event.attack_type,
            "original_content": event.original_content,
            "modified_content": event.modified_content,
            "integrity_compromised": event.integrity_compromised,
            "trust_score": 0.0,
            "status": "CORRUPTED"
        }
    finally:
        session.close()


@app.get("/aegismem/detect/{memory_id}")
def detect_memory(memory_id: str, http_request: Request):
    require_owner(http_request)
    session = get_session()

    try:
        repository = MemoryRepository(session)

        memory = repository.get_latest(
            memory_id
        )

        if memory is None:
            raise HTTPException(
                status_code=404,
                detail=f"Memory '{memory_id}' does not exist."
            )

        graph = build_graph(session)

        detector = MemoryCompromiseDetector(
    repository=repository,
    dependency_graph=graph,
    manifest_store=repository.manifest_store
)

        detection = detector.detect(memory_id)
        evidence = detection.evidence
        soc_alert = None

        if detection.compromised:
            soc_alert = create_soc_alert(
                session=session,
                memory_id=memory_id,
                attack_id=f"DETECTION-{memory_id}-V{memory.version}",
                attack_type="memory_compromise_detection",
                evidence={
                    "integrity_compromised": evidence.integrity_compromised,
                    "provenance_suspicious": evidence.provenance_suspicious,
                    "attack_detected": evidence.attack_detected,
                    "unauthorized_access": not evidence.authorization_valid,
                    "content_changed": evidence.content_changed,
                    "dependency_contamination": evidence.dependency_exposure,
                },
            )

        return {
            "memory_id": memory_id,
            "compromised": detection.compromised,
            "suspicion_score": detection.suspicion_score,
            "reason": detection.reason,
            "evidence": evidence.__dict__,
            "soc_alert": {
                "alert_id": soc_alert.alert_id,
                "severity": soc_alert.severity,
                "severity_score": soc_alert.severity_score,
                "status": soc_alert.status,
            } if soc_alert else None,
        }


    finally:
        session.close()



@app.post("/aegismem/recover/{memory_id}")
def recover_memory(memory_id: str, http_request: Request):
    require_owner(http_request)

    session = get_session()

    try:
        repository = MemoryRepository(session)

        memory = repository.get_latest(
            memory_id
        )

        if memory is None:
            raise HTTPException(
                status_code=404,
                detail=f"Memory '{memory_id}' does not exist."
            )

        recovery_service_url = os.getenv("RECOVERY_SERVICE_URL", "http://aegismem-recovery:8000")
        recovery = None
        try:
            req_data = json.dumps({"memory_id": memory_id}).encode("utf-8")
            internal_token = os.getenv("AEGISMEM_INTERNAL_TOKEN", "")
            headers = {"Content-Type": "application/json"}
            if internal_token:
                headers["X-Recovery-Token"] = internal_token

            http_req = urllib.request.Request(
                f"{recovery_service_url}/recovery/execute",
                data=req_data,
                headers=headers,
                method="POST"
            )
            with urllib.request.urlopen(http_req, timeout=10) as resp:
                recovery = json.loads(resp.read().decode("utf-8"))
        except Exception:
            pass

        if recovery is None:
            graph = build_graph(session)

            impact_analyzer = AttackImpactAnalyzer(
                graph
            )

            manifest_store = repository.manifest_store
            provenance_manager = ProvenanceManager(session)
            checkpoint_store = ProvenanceCheckpointStore()
            trusted_head_store = TrustedCheckpointHeadStore(
                checkpoint_store=checkpoint_store
            )

            vault_store = ReplicatedTrustVault()

            orchestrator = AegisMemRecoveryOrchestrator(
                repository=repository,
                impact_analyzer=impact_analyzer,
                manifest_store=manifest_store,
                provenance_manager=provenance_manager,
                checkpoint_store=checkpoint_store,
                trusted_head_store=trusted_head_store,
                vault_store=vault_store,
            )

            recovery = orchestrator.recover_from_attack(
                compromised_memory_id=memory_id,
                attack_time=datetime.now(timezone.utc)
            )

        current = repository.get_latest(
            memory_id
        )

        serialized_decisions = []
        for d in recovery.get("decisions", []):
            if hasattr(d, "__dict__"):
                item = dict(d.__dict__)
                if hasattr(d, "action") and hasattr(d.action, "value"):
                    item["action"] = d.action.value
                serialized_decisions.append(item)
            else:
                serialized_decisions.append(d)
        recovery["decisions"] = serialized_decisions

        return {
            "memory_id": memory_id,
            "recovery": recovery,
            "current_version": current.version if current else None,
            "current_content": current.content if current else None,
            "current_trust_score": current.trust_score if current else None,
            "current_status": current.status if current else None
        }

    finally:
        session.close()


@app.post("/aegismem/watcher/pause")
def pause_watcher(http_request: Request):
    require_owner(http_request)
    watcher = getattr(app.state, "aegismem_watcher", None)
    if watcher:
        watcher.paused = True
    return {"status": "paused"}


@app.post("/aegismem/watcher/resume")
def resume_watcher(http_request: Request):
    require_owner(http_request)
    watcher = getattr(app.state, "aegismem_watcher", None)
    if watcher:
        watcher.paused = False
    return {"status": "active"}


@app.get("/aegismem/detector/config")
def get_detector_config(http_request: Request):
    require_owner(http_request)
    watcher = getattr(app.state, "aegismem_watcher", None)
    interval = watcher.interval_seconds if watcher else float(os.getenv("AEGIS_WATCHER_INTERVAL", "2.0"))
    event_driven = watcher.event_driven if watcher else os.getenv("AEGIS_WATCHER_EVENT_DRIVEN", "false").lower() in ("true", "1", "yes")
    paused = getattr(watcher, "paused", False)

    if event_driven:
        mechanism_desc = "Event-driven store change hook (immediate dispatch)"
    else:
        mechanism_desc = f"Background continuous reconciliation scan (interval: {interval}s)"

    return {
        "mode": "event-driven" if event_driven else "polling",
        "interval_seconds": interval,
        "event_driven": event_driven,
        "mechanism_description": mechanism_desc,
        "is_realtime": bool(event_driven),
        "paused": paused,
    }


@app.get("/aegismem/incident/telemetry")
def get_incident_telemetry(http_request: Request, memory_id: str, attack_id: str | None = None):
    require_owner(http_request)
    session = get_session()
    try:
        # 1. Resolve attack event
        attack_query = session.query(AttackEvent).filter(AttackEvent.memory_id == memory_id)
        if attack_id:
            attack_query = attack_query.filter(AttackEvent.attack_id == attack_id)
        attack = attack_query.order_by(AttackEvent.attack_time.desc(), AttackEvent.id.desc()).first()

        if not attack:
            return {
                "completed": False,
                "memory_id": memory_id,
                "attack_id": attack_id,
                "error": "No attack event found",
                "timestamps": {},
                "latencies_ms": {},
            }

        t_write_dt = attack.attack_end_time or attack.attack_time
        target_attack_id = attack.attack_id

        # 2. Resolve detection event (SOCAlert)
        alert = (
            session.query(SOCAlert)
            .filter(
                SOCAlert.memory_id == memory_id,
                (SOCAlert.attack_id == target_attack_id) | (SOCAlert.created_at >= attack.attack_time)
            )
            .order_by(SOCAlert.created_at.desc(), SOCAlert.id.desc())
            .first()
        )
        t_detect_dt = alert.created_at if alert else None

        # 3. Resolve TCRP decision event
        tcrp_decision = (
            session.query(RecoveryEvent)
            .filter(
                RecoveryEvent.memory_id == memory_id,
                RecoveryEvent.event_type == "TCRP_DECISION",
                RecoveryEvent.created_at >= attack.attack_time
            )
            .order_by(RecoveryEvent.created_at.desc(), RecoveryEvent.id.desc())
            .first()
        )
        t_decide_dt = tcrp_decision.created_at if tcrp_decision else None

        # 4. Resolve Recovery event
        recovery_ev = (
            session.query(RecoveryEvent)
            .filter(
                RecoveryEvent.memory_id == memory_id,
                RecoveryEvent.event_type == "RECOVERY",
                RecoveryEvent.created_at >= attack.attack_time
            )
            .order_by(RecoveryEvent.created_at.desc(), RecoveryEvent.id.desc())
            .first()
        )
        t_recover_dt = recovery_ev.created_at if recovery_ev else None

        # 5. Resolve Validation event
        validation_ev = (
            session.query(RecoveryEvent)
            .filter(
                RecoveryEvent.memory_id == memory_id,
                RecoveryEvent.event_type == "VALIDATION",
                RecoveryEvent.created_at >= attack.attack_time
            )
            .order_by(RecoveryEvent.created_at.desc(), RecoveryEvent.id.desc())
            .first()
        )
        t_validate_dt = validation_ev.created_at if validation_ev else (t_recover_dt if (recovery_ev and recovery_ev.validation_result) else None)

        completed = all([
            t_write_dt is not None,
            t_detect_dt is not None,
            t_decide_dt is not None,
            t_recover_dt is not None,
            t_validate_dt is not None,
        ])

        timestamps = {
            "t_write": {"iso": t_write_dt.isoformat(), "epoch": t_write_dt.timestamp()} if t_write_dt else None,
            "t_detect": {"iso": t_detect_dt.isoformat(), "epoch": t_detect_dt.timestamp()} if t_detect_dt else None,
            "t_decide": {"iso": t_decide_dt.isoformat(), "epoch": t_decide_dt.timestamp()} if t_decide_dt else None,
            "t_recover": {"iso": t_recover_dt.isoformat(), "epoch": t_recover_dt.timestamp()} if t_recover_dt else None,
            "t_validate": {"iso": t_validate_dt.isoformat(), "epoch": t_validate_dt.timestamp()} if t_validate_dt else None,
        }

        latencies_ms = {}
        if completed:
            latencies_ms["ttd_ms"] = round((t_detect_dt - t_write_dt).total_seconds() * 1000.0, 2)
            latencies_ms["tt_decide_ms"] = round((t_decide_dt - t_detect_dt).total_seconds() * 1000.0, 2)
            latencies_ms["ttr_ms"] = round((t_recover_dt - t_decide_dt).total_seconds() * 1000.0, 2)
            latencies_ms["tt_validate_ms"] = round((t_validate_dt - t_recover_dt).total_seconds() * 1000.0, 2)
            latencies_ms["total_duration_ms"] = round((t_validate_dt - t_write_dt).total_seconds() * 1000.0, 2)

        return {
            "completed": completed,
            "memory_id": memory_id,
            "attack_id": target_attack_id,
            "target_version": attack.target_version,
            "restored_version": recovery_ev.restored_version if recovery_ev else None,
            "recovery_status": recovery_ev.status if recovery_ev else None,
            "validation_result": validation_ev.validation_result if validation_ev else (recovery_ev.validation_result if recovery_ev else None),
            "timestamps": timestamps,
            "latencies_ms": latencies_ms,
            "records": {
                "attack": {
                    "attack_id": attack.attack_id,
                    "mutation": attack.mutation_description,
                    "target_version": attack.target_version,
                },
                "soc_alert": {
                    "alert_id": alert.alert_id if alert else None,
                    "severity": alert.severity if alert else None,
                    "severity_score": alert.severity_score if alert else None,
                } if alert else None,
                "tcrp_decision": {
                    "action": tcrp_decision.action if tcrp_decision else None,
                    "action_cost": tcrp_decision.selected_action_cost if tcrp_decision else None,
                    "candidate_costs": tcrp_decision.candidate_costs if tcrp_decision else None,
                } if tcrp_decision else None,
                "recovery": {
                    "action": recovery_ev.action if recovery_ev else None,
                    "status": recovery_ev.status if recovery_ev else None,
                    "restored_version": recovery_ev.restored_version if recovery_ev else None,
                } if recovery_ev else None,
            }
        }
    finally:
        session.close()


def build_dashboard_internal_request(
    method: str,
    path: str,
    body: bytes,
    include_signature: bool = True,
):
    owner_token = load_owner_token()

    if not owner_token:
        raise HTTPException(
            status_code=503,
            detail="Owner authentication is not configured.",
        )

    headers = {
        "authorization": f"Bearer {owner_token}",
        "content-type": "application/json",
        "content-length": str(len(body)),
    }

    if include_signature:
        key_path = (
            Path(__file__).resolve().parent.parent
            / "security"
            / "keys"
            / "owner_request_private_key.pem"
        )

        private_key = load_signing_key(key_path)

        signed_headers = sign_http_request(
            private_key=private_key,
            method=method,
            path=path,
            body=body,
            nonce=secrets.token_urlsafe(32),
        )

        headers.update({
            key.lower(): value
            for key, value in signed_headers.items()
        })

    scope = {
        "type": "http",
        "http_version": "1.1",
        "method": method,
        "scheme": "http",
        "path": path,
        "raw_path": path.encode("utf-8"),
        "query_string": b"",
        "headers": [
            (key.encode("latin-1"), value.encode("latin-1"))
            for key, value in headers.items()
        ],
        "client": ("127.0.0.1", 0),
        "server": ("127.0.0.1", 8000),
        "root_path": "",
        "app": app,
    }

    internal_request = Request(scope)
    internal_request.state.raw_body = body

    return internal_request


@app.post("/dashboard/operations/approve")
def dashboard_approve_operation(
    payload: DashboardOperationApprovalRequest,
    http_request: Request,
):
    require_trusted_dashboard_origin(http_request)
    require_dashboard_auth(http_request)

    raw_session_id = http_request.cookies.get(
        SESSION_COOKIE_NAME
    )

    try:
        result = authorize_dashboard_operation(
            operation=payload.operation,
            memory_id=payload.memory_id,
            confirmed=payload.confirmed,
            raw_session_id=raw_session_id,
        )

        return result

    except DashboardOperationAuthorizationError as exc:
        raise HTTPException(
            status_code=403,
            detail=str(exc),
        )


@app.post("/dashboard/operations/execute")
def dashboard_execute_operation(
    payload: DashboardOperationExecutionRequest,
    http_request: Request,
):
    require_trusted_dashboard_origin(http_request)
    require_dashboard_auth(http_request)

    raw_session_id = http_request.cookies.get(
        SESSION_COOKIE_NAME
    )

    try:
        consume_dashboard_operation(
            authorization_id=payload.authorization_id,
            operation=payload.operation,
            memory_id=payload.memory_id,
            raw_session_id=raw_session_id,
        )

    except DashboardOperationAuthorizationError as exc:
        raise HTTPException(
            status_code=403,
            detail=str(exc),
        )

    memory_id = payload.memory_id
    encoded_id = quote(memory_id, safe="")

    operation_routes = {
        "attack.poison": (
            "POST",
            "/attack/poison",
            "signed",
        ),
        "attack.tamper": (
            "POST",
            "/attack/tamper",
            "signed",
        ),
        "attack.delete": (
            "POST",
            "/attack/delete",
            "signed",
        ),
        "memory.detect": (
            "GET",
            f"/aegismem/detect/{encoded_id}",
            "owner",
        ),
        "memory.recover": (
            "POST",
            f"/aegismem/recover/{encoded_id}",
            "signed",
        ),
    }

    route = operation_routes.get(payload.operation)

    if route is None:
        raise HTTPException(
            status_code=403,
            detail="Operation is not permitted.",
        )

    method, path, auth_mode = route

    body = (
        encode_json_body({"memory_id": memory_id})
        if payload.operation.startswith("attack.")
        else b""
    )

    internal_request = build_dashboard_internal_request(
        method=method,
        path=path,
        body=body,
        include_signature=(auth_mode == "signed"),
    )

    if payload.operation == "attack.poison":
        return poison_memory(
            PoisonRequest(memory_id=memory_id),
            internal_request,
        )

    if payload.operation == "attack.tamper":
        return tamper_memory(
            DeleteRequest(memory_id=memory_id),
            internal_request,
        )

    if payload.operation == "attack.delete":
        return delete_memory(
            DeleteRequest(memory_id=memory_id),
            internal_request,
        )

    if payload.operation == "memory.detect":
        return detect_memory(
            memory_id,
            internal_request,
        )

    if payload.operation == "memory.recover":
        return recover_memory(
            memory_id,
            internal_request,
        )


@app.get("/aegismem/status/{memory_id}")
def memory_status(memory_id: str, http_request: Request):
    require_owner(http_request)
    session = get_session()

    try:
        repository = MemoryRepository(session)

        memory = repository.get_latest(
            memory_id
        )

        if memory is None:
            raise HTTPException(
                status_code=404,
                detail=f"Memory '{memory_id}' does not exist."
            )

        return {
            "memory_id": memory.memory_id,
            "version": memory.version,
            "content": memory.content,
            "trust": memory.trust_score,
            "trust_score": memory.trust_score,
            "status": memory.status,
            "suspicion_score": memory.suspicion_score,

        }

    finally:
        session.close()
    



@app.get("/dashboard/sessions")
def dashboard_sessions(http_request: Request):
    require_dashboard_auth(http_request)
    db = get_session()

    try:
        events = (
            db.query(SessionAuditEvent)
            .order_by(SessionAuditEvent.occurred_at.asc())
            .all()
        )

        now = datetime.now(timezone.utc)

        stored_sessions = db.query(DashboardSession).all()
        active_session_refs = set()

        for stored_session in stored_sessions:
            expires_at = stored_session.expires_at

            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)

            if expires_at > now:
                active_session_refs.add(stored_session.id)

        events_by_session = {}

        for event in events:
            if event.session_ref:
                events_by_session.setdefault(
                    event.session_ref, []
                ).append(event)

                durations = {}
        states = {}

        for session_ref, records in events_by_session.items():
            session_events = sorted(
                [
                    event for event in records
                    if event.occurred_at is not None
                ],
                key=lambda event: (
                    event.occurred_at.replace(tzinfo=timezone.utc)
                    if event.occurred_at.tzinfo is None
                    else event.occurred_at
                ),
            )

            open_login = None

            for event in session_events:
                if event.event_type == "LOGIN" and event.outcome == "SUCCESS":
                    if open_login is not None:
                        states[open_login.id] = (
                            "ACTIVE"
                            if session_ref in active_session_refs
                            else "EXPIRED"
                        )

                    open_login = event

                elif (
                    event.event_type == "LOGOUT"
                    and event.outcome == "SUCCESS"
                    and open_login is not None
                ):
                    start = open_login.occurred_at
                    end = event.occurred_at

                    if start.tzinfo is None:
                        start = start.replace(tzinfo=timezone.utc)

                    if end.tzinfo is None:
                        end = end.replace(tzinfo=timezone.utc)

                    duration = max(
                        0,
                        round((end - start).total_seconds()),
                    )

                    durations[open_login.id] = duration
                    durations[event.id] = duration

                    states[open_login.id] = "CLOSED"
                    states[event.id] = "CLOSED"
                    open_login = None

            if open_login is not None:
                states[open_login.id] = (
                    "ACTIVE"
                    if session_ref in active_session_refs
                    else "EXPIRED"
                )

        return {
            "sessions": [
                {
                    "id": event.id,
                    "event_type": event.event_type,
                    "outcome": event.outcome,
                    "source_ip": event.source_ip,
                    "user_agent": event.user_agent,
                    "detail": event.detail,
                    "occurred_at": (
                        event.occurred_at.isoformat()
                        if event.occurred_at else None
                    ),
                    "duration_seconds": durations.get(event.id),
                    "session_state": states.get(event.id),
                    "location_info": classify_ip_location(event.source_ip),
                }
                for event in reversed(events[-200:])
            ]
        }

    finally:
        db.close()



@app.get("/dashboard/overview")
def dashboard_overview(http_request: Request):
    require_dashboard_auth(http_request)
    session = get_session()

    try:
        records = session.execute(
            select(MemoryRecord).order_by(
                MemoryRecord.memory_id,
                MemoryRecord.version
            )
        ).scalars().all()

        latest_by_memory = {}

        for record in records:
            current = latest_by_memory.get(record.memory_id)

            if current is None or record.version > current.version:
                latest_by_memory[record.memory_id] = record

        current_memories = list(
            latest_by_memory.values()
        )

        total = len(current_memories)

        trusted = sum(
            1
            for memory in current_memories
            if (
                memory.trust_score >= 0.8
                and memory.suspicion_score <= 0.2
                and memory.status == "active"
            )
        )

        corrupted = sum(
            1
            for memory in current_memories
            if memory.status == "CORRUPTED"
        )

        deleted = sum(
            1
            for memory in current_memories
            if memory.status == "DELETED"
        )

        quarantined = sum(
            1
            for memory in current_memories
            if memory.status == "QUARANTINED"
        )

        suspicious = sum(
            1
            for memory in current_memories
            if memory.suspicion_score >= 0.5
        )

        active_threats = sum(
            1
            for memory in current_memories
            if (
                memory.status in {
                    "CORRUPTED",
                    "DELETED",
                    "QUARANTINED"
                }
                or memory.suspicion_score >= 0.5
            )
        )

        integrity_valid = 0
        integrity_invalid = 0

        for memory in current_memories:
            expected_hash = calculate_version_hash(
                memory.content,
                memory.previous_hash
            )

            if expected_hash == memory.content_hash:
                integrity_valid += 1
            else:
                integrity_invalid += 1

        trusted_percentage = (
            round((trusted / total) * 100, 2)
            if total > 0
            else 0.0
        )

        recovery_events = session.execute(
            select(RecoveryEvent).where(
                RecoveryEvent.event_type == "RECOVERY",
                RecoveryEvent.status == "success"
            )
        ).scalars().all()

        recovery_incidents = {
            (
                event.memory_id,
                event.compromised_version
            )
            for event in recovery_events
            if (
                event.memory_id is not None
                and event.compromised_version is not None
            )
        }

        recovery_incident_count = len(
            recovery_incidents
        )

        return {
            "backend_status": "online",
            "protected_memories": total,
            "trusted_memories": trusted,
            "trusted_percentage": trusted_percentage,
            "active_threats": active_threats,
            "corrupted_memories": corrupted,
            "deleted_memories": deleted,
            "quarantined_memories": quarantined,
            "suspicious_memories": suspicious,
            "integrity_valid": integrity_valid,
            "integrity_invalid": integrity_invalid,
            "integrity_percentage": (
                round(
                    (integrity_valid / total) * 100,
                    2
                )
                if total > 0
                else 0.0
            ),
            "recovery_events": recovery_incident_count,
"recovery_events_status": "active"
        }

    finally:
        session.close()


@app.get("/dashboard/events")
def dashboard_events(http_request: Request):
    require_dashboard_auth(http_request)
    session = get_session()

    try:
        statement = (
            select(RecoveryEvent)
            .order_by(
                RecoveryEvent.created_at.desc()
            )
            .limit(20)
        )

        events = session.scalars(
            statement
        ).all()

        return {
            "events": [
                {
                    "id": event.id,
                    "memory_id": event.memory_id,
                    "event_type": event.event_type,
                    "action": event.action,
                    "message": event.message,
                    "status": event.status,
                    "compromised_version": event.compromised_version,
                    "restored_version": event.restored_version,
                    "trust_score": event.trust_score,
                    "suspicion_score": event.suspicion_score,
                    "impact_score": event.impact_score,
                    "dependency_exposure": event.dependency_exposure,
                    "selected_action_cost": event.selected_action_cost,
                    "candidate_costs": event.candidate_costs,
"feasible_actions": event.feasible_actions,
"validation_result": event.validation_result,
                    "created_at": (
                        event.created_at.isoformat()
                        if event.created_at
                        else None
                    )
                }
                for event in events
            ]
        }

    finally:
        session.close()

@app.get("/dashboard/memories")
def dashboard_memories(http_request: Request):
    require_dashboard_auth(http_request)
    session = get_session()

    try:
        records = session.execute(
            select(MemoryRecord).order_by(
                MemoryRecord.memory_id,
                MemoryRecord.version
            )
        ).scalars().all()

        latest_by_memory = {}

        for record in records:
            current = latest_by_memory.get(
                record.memory_id
            )

            if (
                current is None
                or record.version > current.version
            ):
                latest_by_memory[record.memory_id] = record

        return {
            "database_name": get_active_db_name(),
            "database": get_active_db_name(),
            "memories": [
                {
                    "id": memory.memory_id,
                    "version": f"v{memory.version}",
                    "content": memory.content,
                    "trust": memory.trust_score,
                    "suspicion": memory.suspicion_score,
                    "status": memory.status,
                    "source": memory.source,
                    "source_type": memory.source_type
                }
                for memory in latest_by_memory.values()
            ]
        }

    finally:
        session.close()
        
@app.get("/dashboard/alerts")
def dashboard_alerts(http_request: Request):
    require_dashboard_auth(http_request)
    session = get_session()

    try:
        alerts = session.execute(
            select(SOCAlert).order_by(SOCAlert.created_at.desc())
        ).scalars().all()

        attack_records = session.execute(
            select(AttackEvent)
        ).scalars().all()

        attacks_by_id = {
            attack.attack_id: attack for attack in attack_records
        }

        alerts_response = []

        for alert in alerts:
            attack = attacks_by_id.get(alert.attack_id)

            if attack is None:
                match = re.fullmatch(
                    r"DETECTION-(.+)-V(\d+)",
                    alert.attack_id or "",
                )

                if match:
                    detected_memory_id, detected_version = match.groups()
                    for candidate in attack_records:
                        if (
                            candidate.memory_id == detected_memory_id
                            and candidate.target_version == int(detected_version)
                        ):
                            attack = candidate
                            break

            content_changed = None
            hash_changed = None
            attacker = None
            target_version = None
            source_ip = None
            attack_record_found = attack is not None
            attribution_evidence = []
            original_content = None
            modified_content = None
            mutation_description = None
            entry_point = None
            access_method = None
            duration_ms = None
            attack_time = None
            recorded_attack_status = None

            if attack is not None:
                attacker = attack.attacker
                target_version = attack.target_version
                source_ip = attack.source_ip
                original_content = attack.original_content
                modified_content = attack.modified_content
                mutation_description = attack.mutation_description
                entry_point = attack.entry_point
                access_method = attack.access_method
                duration_ms = attack.duration_ms
                attack_time = attack.attack_time.isoformat() if attack.attack_time else None
                recorded_attack_status = attack.status

                content_changed = (
                    attack.original_content != attack.modified_content
                )
                hash_changed = (
                    attack.original_content_hash
                    != attack.observed_content_hash
                )

                attribution_evidence = [
                    f"Attack record matched: {attack.attack_id}",
                    f"Attacker identity: {attacker or 'unknown'}",
                    f"Source IP: {source_ip or 'unknown'}",
                    f"Entry point: {entry_point or 'unknown'}",
                ]

            alerts_response.append({
                "alert_id": alert.alert_id,
                "attack_id": alert.attack_id,
                "memory_id": alert.memory_id,
                "attack_type": alert.attack_type,
                "severity": alert.severity,
                "severity_score": alert.severity_score,
                "evidence_summary": alert.evidence_summary,
                "status": alert.status,
                "alert_status": alert.status,
                "created_at": (
                    alert.created_at.isoformat()
                    if alert.created_at else None
                ),
                "attack_record_found": attack_record_found,
                "recorded_attack_status": recorded_attack_status,
                "attacker": attacker,
                "target_version": target_version,
                "source_ip": source_ip,
                "original_content": original_content,
                "modified_content": modified_content,
                "mutation_description": mutation_description,
                "entry_point": entry_point,
                "access_method": access_method,
                "duration_ms": duration_ms,
                "attack_time": attack_time,
                "content_changed": content_changed,
                "hash_changed": hash_changed,
                "attribution": "INCONCLUSIVE",
                "attribution_evidence": attribution_evidence,
                "location_info": classify_ip_location(source_ip),
            })

        return {"alerts": alerts_response}

    finally:
        session.close()
        
@app.get("/dashboard/dependencies/{memory_id}")
def get_memory_dependencies(
    memory_id: str,
    http_request: Request,
    session=Depends(get_session)
):
    require_dashboard_auth(http_request)
    repository = DependencyRepository(session)
    graph = DependencyGraph(repository)
    graph.load()

    dependencies = repository.get_dependencies(memory_id)
    dependents = repository.get_dependents(memory_id)
    descendants = sorted(graph.descendants(memory_id))
    ancestors = sorted(graph.ancestors(memory_id))

    edges = [
        {
            "source": item.source_memory_id,
            "target": item.target_memory_id,
            "dependency_type": item.dependency_type,
            "strength": item.strength,
            "observed_at": (
                item.observed_at.isoformat()
                if item.observed_at
                else None
            ),
        }
        for item in dependencies
    ]

    return {
        "memory_id": memory_id,
        "reachable_edges": edges,
        "dependencies": [
            {
                "memory_id": item.target_memory_id,
                "dependency_type": item.dependency_type,
                "strength": item.strength,
            }
            for item in dependencies
        ],
        "dependents": [
            {
                "memory_id": item.source_memory_id,
                "dependency_type": item.dependency_type,
                "strength": item.strength,
            }
            for item in dependents
        ],
        "descendants": descendants,
        "ancestors": ancestors,
        "provenance_note": (
            "Dependency data loaded from persisted dependency records."
            if dependencies or dependents
            else "No stored dependency records were found for this memory."
        ),
    }


@app.get("/dashboard/memories/{memory_id}/history")
def dashboard_memory_history(memory_id: str, http_request: Request):
    require_dashboard_auth(http_request)
    session = get_session()

    try:
        records = (
            session.execute(
                select(MemoryRecord)
                .where(
                    MemoryRecord.memory_id == memory_id
                )
                .order_by(
                    MemoryRecord.version.asc()
                )
            )
            .scalars()
            .all()
        )

        if not records:
            raise HTTPException(
                status_code=404,
                detail="Memory not found"
            )

        attack_events = (
            session.query(AttackEvent)
            .filter(
                AttackEvent.memory_id == memory_id
            )
            .order_by(
                AttackEvent.attack_time.asc()
            )
            .all()
        )

        recovery_events = (
            session.query(RecoveryEvent)
            .filter(
                RecoveryEvent.memory_id == memory_id
            )
            .order_by(
                RecoveryEvent.created_at.asc()
            )
            .all()
        )

        attack_by_version = {}

        for attack in attack_events:
            if attack.target_version is not None:
                attack_by_version[
                    int(attack.target_version)
                ] = attack

        restored_versions = set()

        for recovery in recovery_events:
            if recovery.restored_version is not None:
                restored_versions.add(
                    int(recovery.restored_version)
                )

        history = []

        for record in records:

            version = int(record.version)

            attack = attack_by_version.get(version)

            if attack is not None:
                state = "COMPROMISED"
                state_reason = "Unauthorized memory modification detected."
            elif version in restored_versions:
                state = "RESTORED"
                state_reason = "Trusted state restored by AegisMem."
            elif (
                record.status.upper()
                in {"CORRUPTED", "DELETED"}
                or float(record.suspicion_score) >= 0.50
            ):
                state = "SUSPICIOUS"
                state_reason = "Memory integrity or trust evidence is suspicious."
            else:
                state = "TRUSTED"
                state_reason = "No compromise evidence associated with this version."

            history.append(
                {
                    "id": record.id,
                    "version": f"v{record.version}",
                    "version_number": version,
                    "content": record.content,
                    "trust": record.trust_score,
                    "suspicion": record.suspicion_score,
                    "status": record.status,

                    "state": state,
                    "state_reason": state_reason,

                    "content_hash": record.content_hash,
                    "previous_hash": record.previous_hash,

                    "attack_type": (
                        attack.attack_type
                        if attack is not None
                        else None
                    ),

                    "attacker": (
                        attack.attacker
                        if attack is not None
                        else None
                    ),

                    "attack_id": (
                        attack.attack_id
                        if attack is not None
                        else None
                    ),

                    "attack_time": (
                        attack.attack_time.isoformat()
                        if attack is not None
                        and attack.attack_time
                        else None
                    ),

                    "created_at": (
                        record.created_at.isoformat()
                        if record.created_at
                        else None
                    )
                }
            )

        return {
            "memory_id": memory_id,
            "total_versions": len(history),
            "history": history
        }

    finally:
        session.close()


@app.get("/dashboard/latest-recovery")
def latest_recovery(http_request: Request, memory_id: str | None = None):
    require_dashboard_auth(http_request)
    session = get_session()

    try:
        query = session.query(RecoveryEvent).filter(RecoveryEvent.event_type == "RECOVERY")
        if memory_id:
            query = query.filter(RecoveryEvent.memory_id == memory_id)

        # Prioritize ROLLBACK recovery events over cascading quarantine, then latest event
        latest_recovery_event = (
            query.order_by(
                (RecoveryEvent.action == "ROLLBACK").desc(),
                RecoveryEvent.created_at.desc(),
                RecoveryEvent.id.desc(),
            )
            .first()
        )

        recovery_event = latest_recovery_event

        if recovery_event is None:
            return {"found": False}

        decision_event = (
            session.query(RecoveryEvent)
            .filter(
                RecoveryEvent.memory_id == recovery_event.memory_id,
                RecoveryEvent.event_type == "TCRP_DECISION",
                RecoveryEvent.action == recovery_event.action,
                RecoveryEvent.created_at <= recovery_event.created_at,
            )
            .order_by(RecoveryEvent.created_at.desc(), RecoveryEvent.id.desc())
            .first()
        )

        attack_event = (
            session.query(AttackEvent)
            .filter(
                AttackEvent.memory_id == recovery_event.memory_id
            )
            .order_by(
                AttackEvent.attack_time.desc()
            )
            .first()
        )

        # Accurately compute compromised version (v2 when attacking baseline v1)
        target_comp_version = recovery_event.compromised_version
        if attack_event and attack_event.target_version:
            target_comp_version = attack_event.target_version
        elif recovery_event.restored_version and recovery_event.restored_version > 1:
            target_comp_version = recovery_event.restored_version - 1
        elif target_comp_version is None or target_comp_version == 1:
            if recovery_event.restored_version:
                target_comp_version = max(2, recovery_event.restored_version - 1)
            else:
                target_comp_version = 2

        trusted_version_num = (
            attack_event.original_version
            if attack_event and attack_event.original_version
            else (
                target_comp_version - 1
                if target_comp_version and target_comp_version > 1
                else 1
            )
        )

        restored_version_num = (
            recovery_event.restored_version
            if recovery_event.restored_version
            else target_comp_version + 1
        )

        compromised_memory = (
            session.query(MemoryRecord)
            .filter(
                MemoryRecord.memory_id == recovery_event.memory_id,
                MemoryRecord.version == target_comp_version
            )
            .first()
        )

        restored_memory = (
            session.query(MemoryRecord)
            .filter(
                MemoryRecord.memory_id == recovery_event.memory_id,
                MemoryRecord.version == restored_version_num
            )
            .first()
        )

        trusted_memory = (
            session.query(MemoryRecord)
            .filter(
                MemoryRecord.memory_id == recovery_event.memory_id,
                MemoryRecord.version == trusted_version_num
            )
            .first()
        )
        
        recovery_validation = {
            "valid": False,
            "recovery_provenance_verified": False,
            "provenance_verified": False,
            "reason": "Recovery validation has not been completed.",
        }

        if (
            recovery_event.restored_version is not None
            and restored_memory is not None
        ):
            try:
                repository = MemoryRepository(session)
                validator = RecoveryValidator(repository=repository)
                validation = validator.validate(recovery_event.memory_id)

                restored_is_latest = (
                    validation.get("version")
                    == recovery_event.restored_version
                )

                recovery_validation = {
                    "valid": bool(
                        validation.get("content_valid", False)
                        and restored_is_latest
                    ),
                    "recovery_provenance_verified": bool(
                        validation.get("recovery_provenance_verified", False)
                        and restored_is_latest
                    ),
                    "provenance_verified": bool(
                        validation.get("provenance_verified", False)
                        and restored_is_latest
                    ),
                    "reason": validation.get(
                        "provenance_reason",
                        "Validation completed without a provenance reason.",
                    ),
                }
            except Exception as exc:
                recovery_validation["reason"] = (
                    f"Recovery validation failed: {type(exc).__name__}"
                )


        verified_success = bool(
            recovery_event.event_type == "RECOVERY"
            and recovery_event.restored_version is not None
            and restored_memory is not None
            and recovery_validation["valid"]
            and recovery_validation["recovery_provenance_verified"]
            and recovery_validation["provenance_verified"]
        )

        

        return {
            "found": True,

            "recovery": {
                "id": recovery_event.id,
                "memory_id": recovery_event.memory_id,
                "event_type": recovery_event.event_type,
                "action": recovery_event.action,
                "message": recovery_event.message,
                "status": recovery_event.status,
                "verified_success": verified_success,
                "verification": recovery_validation,

                "compromised_version":
                    target_comp_version,

                "restored_version":
                    restored_version_num,

                "validation_result": (
                    "PASS"
                    if (verified_success or str(recovery_event.validation_result).upper() in ["PASS", "PARTIAL"])
                    else recovery_event.validation_result
                ),

                "created_at":
                    recovery_event.created_at.isoformat()
                    if recovery_event.created_at
                    else None
            },

            "memory": {
                "trusted": {
                    "version":
                        trusted_memory.version
                        if trusted_memory
                        else trusted_version_num,

                    "content":
                        trusted_memory.content
                        if trusted_memory
                        else (
                            attack_event.original_content
                            if attack_event
                            else (
                                compromised_memory.content
                                if (compromised_memory and target_comp_version == 1)
                                else None
                            )
                        )
                },

                "compromised": {
                    "version":
                        target_comp_version,

                    "content":
                        compromised_memory.content
                        if (compromised_memory and compromised_memory.version == target_comp_version)
                        else (
                            attack_event.modified_content
                            if attack_event
                            else None
                        ),

                    "attack_type":
                        attack_event.attack_type
                        if attack_event
                        else (
                            "tampering"
                            if recovery_event.action == "ROLLBACK"
                            else "unauthorized modification"
                        ),

                    "attacker":
                        attack_event.attacker
                        if attack_event and attack_event.attacker
                        else "unknown",

                    "attack_id":
                        attack_event.attack_id
                        if attack_event
                        else None
                },

                "restored": {
                    "version":
                        restored_memory.version
                        if restored_memory
                        else restored_version_num,

                    "content":
                        restored_memory.content
                        if restored_memory
                        else None,

                    "trust_score":
                        restored_memory.trust_score
                        if restored_memory
                        else None,

                    "status":
                        restored_memory.status
                        if restored_memory
                        else None
                }
            },

            "tcrp": {
                "found":
                    decision_event is not None,

                "id":
                    decision_event.id
                    if decision_event
                    else None,

                "memory_id":
                    decision_event.memory_id
                    if decision_event
                    else None,

                "action":
                    decision_event.action
                    if decision_event
                    else None,

                "trust_score":
                    decision_event.trust_score
                    if decision_event
                    else None,

                "suspicion_score":
                    decision_event.suspicion_score
                    if decision_event
                    else None,

                "impact_score":
                    decision_event.impact_score
                    if decision_event
                    else None,

                "dependency_exposure":
                    decision_event.dependency_exposure
                    if decision_event
                    else None,

                "selected_action_cost":
                    decision_event.selected_action_cost
                    if decision_event
                    else None,

                "candidate_costs":
                    decision_event.candidate_costs
                    if decision_event
                    else None,

                "feasible_actions":
                    decision_event.feasible_actions
                    if decision_event
                    else None,

                "created_at":
                    decision_event.created_at.isoformat()
                    if decision_event
                    and decision_event.created_at
                    else None
            }
        }

    finally:
        session.close()


# ==========================================
# SOC Dashboard & Forensic Incidents (M10)
# ==========================================

from core.soc.dashboard_feed import get_soc_dashboard_feed
from core.soc.incident_reporter import get_incident_manager
from fastapi.responses import Response, PlainTextResponse


@app.get("/api/soc/dashboard-feed")
def get_soc_dashboard_feed_endpoint():
    session = SessionLocal()
    try:
        feed = get_soc_dashboard_feed(db_session=session)
        if isinstance(feed, dict):
            feed["database_name"] = get_active_db_name()
            feed["database"] = get_active_db_name()
        return feed
    finally:
        session.close()


@app.get("/api/soc/incidents")
def list_soc_incidents_endpoint():
    mgr = get_incident_manager()
    return mgr.list_incidents()


@app.get("/api/soc/incidents/{incident_id}")
def get_soc_incident_endpoint(incident_id: str):
    mgr = get_incident_manager()
    inc = mgr.get_incident(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")
    return inc.to_dict()


@app.get("/api/soc/incidents/{incident_id}/markdown")
def get_soc_incident_markdown_endpoint(incident_id: str):
    mgr = get_incident_manager()
    inc = mgr.get_incident(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")
    return PlainTextResponse(inc.to_markdown())


@app.get("/api/soc/incidents/{incident_id}/pdf")
def get_soc_incident_pdf_endpoint(incident_id: str):
    mgr = get_incident_manager()
    inc = mgr.get_incident(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")
    pdf_path = Path("data/incidents") / f"{incident_id}.pdf"
    if not pdf_path.exists():
        pdf_path = inc.export_pdf(pdf_path)
    return Response(
        content=pdf_path.read_bytes(),
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={incident_id}.pdf"}
    )
