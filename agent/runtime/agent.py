import re

from sqlalchemy.orm import Session

from agent.retrieval.service import MemoryRetriever
from agent.extraction.query_parser import QueryParser


class EnterpriseAgent:

    def __init__(self, session: Session):
        self.retriever = MemoryRetriever(session)
        self.parser = QueryParser()

    def _extract_policy_limit(self, content: str) -> int:
        match = re.search(
            r"(\d+)\s+calendar\s+days?",
            content.lower()
        )

        if not match:
            raise ValueError(
                "Unable to determine refund policy from memory content."
            )

        return int(match.group(1))

    def answer_from_memory(
        self,
        memory_id: str,
        question: str
    ) -> dict:

        memory = self.retriever.retrieve(
            memory_id
        )

        return {
            "memory_id": memory.memory_id,
            "memory_version": memory.version,
            "question": question,
            "answer": memory.content,
            "trust_score": memory.trust_score,
            "status": memory.status
        }

    def make_refund_decision(
        self,
        memory_id: str,
        customer_days: int
    ) -> dict:

        memory = self.retriever.retrieve(
            memory_id
        )

        policy_limit = self._extract_policy_limit(
            memory.content
        )

        decision = (
            "REFUND ALLOWED"
            if customer_days <= policy_limit
            else "REFUND DENIED"
        )

        return {
            "memory_id": memory.memory_id,
            "memory_version": memory.version,
            "customer_days": customer_days,
            "policy_limit": policy_limit,
            "decision": decision,
            "trust_score": memory.trust_score,
            "status": memory.status
        }

    def answer_question(
        self,
        memory_id: str,
        question: str
    ) -> dict:

        parsed = self.parser.parse(question)

        memory = self.retriever.retrieve(
            memory_id
        )

        text = question.lower().strip()

        policy_question = any(
            phrase in text
            for phrase in [
                "what is the refund policy",
                "what's the refund policy",
                "tell me the refund policy",
                "explain the refund policy",
                "refund policy"
            ]
        )

        if policy_question:
            return {
                "memory_id": memory.memory_id,
                "memory_version": memory.version,
                "question": question,
                "intent": "policy_information",
                "topic": "refund_policy",
                "answer": memory.content,
                "trust_score": memory.trust_score,
                "status": memory.status
            }

        if parsed.intent == "refund_eligibility":

            if parsed.customer_days is None:
                return {
                    "memory_id": memory.memory_id,
                    "memory_version": memory.version,
                    "question": question,
                    "intent": parsed.intent,
                    "topic": parsed.topic,
                    "answer": (
                        "Please provide how many days ago "
                        "the purchase was made."
                    ),
                    "trust_score": memory.trust_score,
                    "status": memory.status
                }

            decision = self.make_refund_decision(
                memory_id=memory_id,
                customer_days=parsed.customer_days
            )

            return {
                "memory_id": memory.memory_id,
                "memory_version": memory.version,
                "question": question,
                "intent": parsed.intent,
                "topic": parsed.topic,
                "customer_days": parsed.customer_days,
                "policy_limit": decision["policy_limit"],
                "answer": decision["decision"],
                "trust_score": memory.trust_score,
                "status": memory.status
            }

        return {
            "memory_id": memory.memory_id,
            "memory_version": memory.version,
            "question": question,
            "intent": parsed.intent,
            "topic": parsed.topic,
            "answer": memory.content,
            "trust_score": memory.trust_score,
            "status": memory.status
        }