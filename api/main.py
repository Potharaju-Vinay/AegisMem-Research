import re
from typing import Optional
import difflib
import random
from datetime import datetime, timezone
from sqlalchemy import select
from core.memory.database import SessionLocal
from core.recovery.audit import RecoveryEvent

from core.memory.models import MemoryRecord
from core.integrity.hash import (
    calculate_version_hash,
    calculate_content_hash
)

from fastapi import FastAPI, HTTPException
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
import asyncio
from contextlib import asynccontextmanager

from core.security.watcher import AegisMemWatcher

@asynccontextmanager
async def lifespan(app: FastAPI):

    watcher = AegisMemWatcher(
        interval_seconds=2.0
    )

    app.state.aegismem_watcher = watcher

    watcher_task = asyncio.create_task(
        watcher.run()
    )

    app.state.aegismem_watcher_task = watcher_task

    try:
        yield

    finally:
        watcher.stop()

        await watcher_task


app = FastAPI(
    title="AegisMem API",
    description="Self-healing persistent memory protection for enterprise AI agents",
    version="1.0.0",
    lifespan=lifespan
)


class ChatRequest(BaseModel):
    question: str


class RefundRequest(BaseModel):
    customer_days: int


class ExternalMemoryWriteRequest(BaseModel):
    memory_id: str
    modified_content: str
    attacker: str = "kali-attacker"
    attack_type: str = "content_tampering"

class PoisonRequest(BaseModel):
    memory_id: str = "POLICY-001"


class DeleteRequest(BaseModel):
    memory_id: str


def resolve_memory(session, question):
    resolver = MemoryResolver(session)
    return resolver.resolve(question)


def aegismem_security_gate(session, memory_id):
    repository = MemoryRepository(session)
    graph = build_graph(session)

    detector = MemoryCompromiseDetector(
        repository=repository,
        dependency_graph=graph
    )

    detection = detector.detect(memory_id)

    if detection.compromised:
        return {
            "verified": False,
            "compromised": True,
            "suspicion_score": detection.suspicion_score,
            "reason": detection.reason,
            "evidence": detection.evidence.__dict__
        }

    memory = repository.get_latest(memory_id)

    if memory is None:
        return {
            "verified": False,
            "compromised": True,
            "suspicion_score": 1.0,
            "reason": "Memory no longer exists.",
            "evidence": {}
        }

    trusted = (
        memory.status == "active"
        and memory.trust_score >= 0.8
        and memory.suspicion_score <= 0.2
    )

    return {
        "verified": trusted,
        "compromised": not trusted,
        "suspicion_score": detection.suspicion_score,
        "reason": detection.reason,
        "evidence": detection.evidence.__dict__
    }


def build_graph(session):
    dependency_repo = DependencyRepository(session)

    existing = dependency_repo.get_dependencies("POLICY-001")

    if not existing:
        dependency_repo.add_dependency(
            source_memory_id="POLICY-001",
            target_memory_id="POLICY-002",
            dependency_type="derived_from",
            strength=0.9
        )

        dependency_repo.add_dependency(
            source_memory_id="POLICY-002",
            target_memory_id="SOP-003",
            dependency_type="derived_from",
            strength=0.8
        )

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
            "hi",
            "hello",
            "hey",
            "hii",
            "hiii",
            "hiya",
            "yo",
            "sup",
            "good morning",
            "good afternoon",
            "good evening",
            "good night"
        ],
        "responses": [
            "Hello! How can I help you today?",
            "Hey! What can I do for you?"
        ]
    },

    "wellbeing": {
        "patterns": [
            "how are you",
            "how are you doing",
            "how is it going",
            "how was your day",
            "how are things",
            "you good",
            "are you okay"
        ],
        "responses": [
            "I'm doing well and ready to help. You can ask me general questions or questions about protected enterprise knowledge."
        ]
    },

    "small_talk": {
        "patterns": [
            "have food",
            "have you eaten",
            "did you eat",
            "did you have food",
            "what are you doing",
            "whats up",
            "what's up",
            "are you busy",
            "are you free"
        ],
        "responses": [
            "I don't eat or take breaks, but I'm always ready to help. What would you like to talk about?"
        ]
    },

    "identity": {
        "patterns": [
            "who are you",
            "what are you",
            "what is your name",
            "tell me about yourself"
        ],
        "responses": [
            "I'm the AegisMem enterprise AI assistant. I can handle general conversation and answer questions using protected enterprise knowledge."
        ]
    },

    "capabilities": {
        "patterns": [
            "what can you do",
            "what do you do",
            "what are your features",
            "how can you help"
        ],
        "responses": [
            "I can have general conversations and answer enterprise questions using trusted memory protected by the AegisMem security layer."
        ]
    },

    "thanks": {
        "patterns": [
            "thanks",
            "thank you",
            "thank u",
            "thx",
            "appreciate it"
        ],
        "responses": [
            "You're welcome! Let me know if you need anything else."
        ]
    },

    "goodbye": {
        "patterns": [
            "bye",
            "goodbye",
            "see you",
            "see ya",
            "talk later"
        ],
        "responses": [
            "Goodbye! Feel free to come back if you have more questions."
        ]
    },

    "affirmation": {
        "patterns": [
            "ok",
            "okay",
            "sure",
            "sounds good",
            "alright"
        ],
        "responses": [
            "Great! Let me know what you'd like to do next."
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

    intent = find_intent(text)

    if intent is None:
        return None

    return random.choice(INTENTS[intent]["responses"])


@app.post("/chat")
def chat(request: ChatRequest):
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
                "memory_id": memory.memory_id,
                "memory_version": memory.version,
                "trust": memory.trust_score,
                "trust_score": memory.trust_score,
                "status": memory.status,
                "suspicion_score": security["suspicion_score"],
                "security_reason": security["reason"]
            }

        agent = EnterpriseAgent(session)

        result = agent.answer_question(
            memory_id=memory.memory_id,
            question=question
        )

        result["mode"] = "enterprise"
        result["memory_used"] = True
        result["aegismem_verified"] = True
        result["security_reason"] = "Memory passed AegisMem security verification."

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
def refund_decision(request: RefundRequest):

    session = get_session()

    try:
        memory = resolve_memory(
            session,
            "What is the refund policy?"
        )

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

        agent = EnterpriseAgent(session)

        return agent.make_refund_decision(
            memory_id=memory.memory_id,
            customer_days=request.customer_days
        )

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

@app.post("/attacker/memory/write")
def attacker_memory_write(request: ExternalMemoryWriteRequest):

    session = get_session()

    try:
        attacker = ExternalMemoryAttacker(session)

        attack_result = attacker.modify_memory(
            memory_id=request.memory_id,
            modified_content=request.modified_content,
            attacker=request.attacker,
            attack_type=request.attack_type
        )

        return {
            "attack": attack_result,
            "aegismem": {
                "triggered": False,
                "message": "Memory modified by external actor. AegisMem monitoring is independent."
            }
        }

    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc)
        )

    finally:
        session.close()


@app.post("/lab/memory/write")
def external_memory_write(request: ExternalMemoryWriteRequest):
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

@app.post("/attack/poison")
def poison_memory(request: PoisonRequest):

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
            attacker="controlled_kali_lab",
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
            actor="controlled_kali_lab",
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
def delete_memory(request: DeleteRequest):

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
def tamper_memory(request: DeleteRequest):

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
            attacker="controlled_kali_lab"
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
def detect_memory(memory_id: str):

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
            dependency_graph=graph
        )

        detection = detector.detect(
            memory_id
        )

        return {
            "memory_id": memory_id,
            "compromised": detection.compromised,
            "suspicion_score": detection.suspicion_score,
            "reason": detection.reason,
            "evidence": detection.evidence.__dict__
        }

    finally:
        session.close()


@app.post("/aegismem/recover/{memory_id}")
def recover_memory(memory_id: str):

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

        impact_analyzer = AttackImpactAnalyzer(
            graph
        )

        orchestrator = AegisMemRecoveryOrchestrator(
            repository=repository,
            impact_analyzer=impact_analyzer
        )

        recovery = orchestrator.recover_from_attack(
            compromised_memory_id=memory_id,
            attack_time=datetime.now(timezone.utc)
        )

        current = repository.get_latest(
            memory_id
        )

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


@app.get("/aegismem/status/{memory_id}")
def memory_status(memory_id: str):

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


@app.get("/dashboard/overview")
def dashboard_overview():
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
def dashboard_events():
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
def dashboard_memories():
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


@app.get("/dashboard/memories/{memory_id}/history")
def dashboard_memory_history(memory_id: str):
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
def latest_recovery():
    session = get_session()

    try:
        recovery_event = (
            session.query(RecoveryEvent)
            .filter(
                RecoveryEvent.restored_version.isnot(None)
            )
            .order_by(
                RecoveryEvent.created_at.desc()
            )
            .first()
        )

        if recovery_event is None:
            return {"found": False}

        decision_event = (
            session.query(RecoveryEvent)
            .filter(
                RecoveryEvent.memory_id == recovery_event.memory_id,
                RecoveryEvent.event_type == "TCRP_DECISION",
                RecoveryEvent.compromised_version == recovery_event.compromised_version
            )
            .order_by(
                RecoveryEvent.created_at.desc()
            )
            .first()
        )

        attack_event = (
            session.query(AttackEvent)
            .filter(
                AttackEvent.memory_id == recovery_event.memory_id,
                AttackEvent.target_version == recovery_event.compromised_version
            )
            .order_by(
                AttackEvent.attack_time.desc()
            )
            .first()
        )

        compromised_memory = (
            session.query(MemoryRecord)
            .filter(
                MemoryRecord.memory_id == recovery_event.memory_id,
                MemoryRecord.version == recovery_event.compromised_version
            )
            .first()
        )

        restored_memory = (
            session.query(MemoryRecord)
            .filter(
                MemoryRecord.memory_id == recovery_event.memory_id,
                MemoryRecord.version == recovery_event.restored_version
            )
            .first()
        )

        trusted_memory = None

        if attack_event and attack_event.original_version:
            trusted_memory = (
                session.query(MemoryRecord)
                .filter(
                    MemoryRecord.memory_id == recovery_event.memory_id,
                    MemoryRecord.version == attack_event.original_version
                )
                .first()
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

                "compromised_version":
                    recovery_event.compromised_version,

                "restored_version":
                    recovery_event.restored_version,

                "validation_result":
                    recovery_event.validation_result,

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
                        else (
                            attack_event.original_version
                            if attack_event
                            else None
                        ),

                    "content":
                        trusted_memory.content
                        if trusted_memory
                        else (
                            attack_event.original_content
                            if attack_event
                            else None
                        )
                },

                "compromised": {
                    "version":
                        compromised_memory.version
                        if compromised_memory
                        else (
                            attack_event.target_version
                            if attack_event
                            else None
                        ),

                    "content":
                        compromised_memory.content
                        if compromised_memory
                        else (
                            attack_event.modified_content
                            if attack_event
                            else None
                        ),

                    "attack_type":
                        attack_event.attack_type
                        if attack_event
                        else None,

                    "attacker":
                        attack_event.attacker
                        if attack_event
                        else None,

                    "attack_id":
                        attack_event.attack_id
                        if attack_event
                        else None
                },

                "restored": {
                    "version":
                        restored_memory.version
                        if restored_memory
                        else recovery_event.restored_version,

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