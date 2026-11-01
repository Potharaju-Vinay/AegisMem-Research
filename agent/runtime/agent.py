import re
from sqlalchemy.orm import Session
from agent.retrieval.service import MemoryRetriever
from agent.extraction.query_parser import QueryParser


class EnterpriseAgent:

    def __init__(self, session: Session, allow_untrusted: bool = False):
        self.retriever = MemoryRetriever(session, allow_untrusted=allow_untrusted)
        self.parser = QueryParser()

    def _extract_policy_limit(self, content: str) -> int:
        match = re.search(r"(\d+)\s+calendar\s+days?", content.lower())
        if not match:
            match = re.search(r"(\d+)\s+days?", content.lower())
        if not match:
            return 30
        return int(match.group(1))

    def answer_from_memory(self, memory_id: str, question: str) -> dict:
        memory = self.retriever.retrieve(memory_id)
        return {
            "memory_id": memory.memory_id,
            "memory_version": memory.version,
            "question": question,
            "answer": memory.content,
            "trust_score": memory.trust_score,
            "status": memory.status
        }

    def make_refund_decision(self, memory_id: str, customer_days: int) -> dict:
        memory = self.retriever.retrieve(memory_id)
        policy_limit = self._extract_policy_limit(memory.content)

        decision = (
            "REFUND ALLOWED"
            if customer_days <= policy_limit
            else "REFUND DENIED"
        )

        if decision == "REFUND ALLOWED":
            explanation = (
                f"Based on our Enterprise Customer Refund Policy (limit of {policy_limit} calendar days), "
                f"your purchase made {customer_days} days ago is REFUND ALLOWED. "
                f"Please provide your transaction receipt to customer support to process your refund."
            )
        else:
            explanation = (
                f"Based on our Enterprise Customer Refund Policy (limit of {policy_limit} calendar days), "
                f"your purchase made {customer_days} days ago is REFUND DENIED as it exceeds the {policy_limit} "
                f"calendar day window. Refund requests beyond {policy_limit} days require manager exception review."
            )

        return {
            "memory_id": memory.memory_id,
            "memory_version": memory.version,
            "customer_days": customer_days,
            "policy_limit": policy_limit,
            "decision": decision,
            "explanation": explanation,
            "trust_score": memory.trust_score,
            "status": memory.status
        }

    def answer_question(self, memory_id: str, question: str) -> dict:
        parsed = self.parser.parse(question)
        memory = self.retriever.retrieve(memory_id)
        text = question.lower().strip()

        # Handle refund eligibility check with specified customer days
        if parsed.intent == "refund_eligibility" and parsed.customer_days is not None:
            decision_data = self.make_refund_decision(
                memory_id=memory_id,
                customer_days=parsed.customer_days
            )
            return {
                "memory_id": memory.memory_id,
                "memory_version": memory.version,
                "question": question,
                "intent": "refund_eligibility",
                "topic": "refund_policy",
                "customer_days": parsed.customer_days,
                "policy_limit": decision_data["policy_limit"],
                "decision": decision_data["decision"],
                "answer": decision_data["explanation"],
                "trust_score": memory.trust_score,
                "status": memory.status
            }

        # Handle general refund/return policy inquiry
        policy_keywords = ["refund", "refunds", "return", "returns", "exchange", "money back"]
        if any(kw in text for kw in policy_keywords) and memory.memory_id.startswith("POLICY"):
            return {
                "memory_id": memory.memory_id,
                "memory_version": memory.version,
                "question": question,
                "intent": "policy_information",
                "topic": "refund_and_return_policy",
                "answer": (
                    f"Enterprise Customer Refund & Return Policy: {memory.content} "
                    f"If you made a purchase and would like to verify eligibility, please tell me how many days ago it was purchased."
                ),
                "trust_score": memory.trust_score,
                "status": memory.status
            }

        # Handle Enterprise Security & Compliance Policies
        if memory.memory_id == "ENT-ACCESS-001":
            return {
                "memory_id": memory.memory_id,
                "memory_version": memory.version,
                "question": question,
                "intent": "security_policy",
                "topic": "access_and_mfa",
                "answer": f"Enterprise Access & Multi-Factor Authentication (MFA) Guideline: {memory.content}",
                "trust_score": memory.trust_score,
                "status": memory.status
            }

        if memory.memory_id == "ENT-INCIDENT-002":
            return {
                "memory_id": memory.memory_id,
                "memory_version": memory.version,
                "question": question,
                "intent": "security_policy",
                "topic": "incident_reporting",
                "answer": f"Enterprise Incident Reporting Policy: {memory.content}",
                "trust_score": memory.trust_score,
                "status": memory.status
            }

        if memory.memory_id == "ENT-BACKUP-003":
            return {
                "memory_id": memory.memory_id,
                "memory_version": memory.version,
                "question": question,
                "intent": "disaster_recovery",
                "topic": "backup_policy",
                "answer": f"Enterprise Disaster Recovery & Backup Policy: {memory.content}",
                "trust_score": memory.trust_score,
                "status": memory.status
            }

        if memory.memory_id == "ENT-DATA-004":
            return {
                "memory_id": memory.memory_id,
                "memory_version": memory.version,
                "question": question,
                "intent": "compliance_policy",
                "topic": "data_protection",
                "answer": f"Enterprise Customer Data Protection & Privacy Standard: {memory.content}",
                "trust_score": memory.trust_score,
                "status": memory.status
            }

        if memory.memory_id == "ENT-EMPLOYEE-005":
            return {
                "memory_id": memory.memory_id,
                "memory_version": memory.version,
                "question": question,
                "intent": "compliance_policy",
                "topic": "credential_hygiene",
                "answer": f"Enterprise Employee Credential Policy: {memory.content}",
                "trust_score": memory.trust_score,
                "status": memory.status
            }

        if memory.memory_id == "FAQ-001":
            return {
                "memory_id": memory.memory_id,
                "memory_version": memory.version,
                "question": question,
                "intent": "customer_support_faq",
                "topic": "support_hours_and_contact",
                "answer": f"Enterprise Customer Support FAQ: {memory.content}",
                "trust_score": memory.trust_score,
                "status": memory.status
            }

        if memory.memory_id == "SOP-003":
            return {
                "memory_id": memory.memory_id,
                "memory_version": memory.version,
                "question": question,
                "intent": "support_sop",
                "topic": "customer_support_escalation",
                "answer": f"Customer Support Complaint & Escalation SOP: {memory.content}",
                "trust_score": memory.trust_score,
                "status": memory.status
            }

        # Default fallback
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
