import re
from sqlalchemy.orm import Session
from core.memory.models import MemoryRecord


class MemoryResolver:

    STOP_WORDS = {
        "what", "is", "the", "a", "an", "are", "of", "to", "for", "in", "on",
        "and", "or", "does", "do", "can", "within", "this", "that", "how", "tell",
        "me", "about", "our", "my", "your", "we", "you", "i"
    }

    DOMAIN_HINTS = {
        "ENT-ACCESS-001": {"access", "mfa", "multifactor", "authentication", "privileged", "permission", "login", "least", "sso"},
        "ENT-INCIDENT-002": {"incident", "incidents", "breach", "security", "report", "reporting", "containment", "compromise"},
        "ENT-BACKUP-003": {"backup", "backups", "recovery", "disaster", "restore", "retention", "dr"},
        "ENT-DATA-004": {"data", "privacy", "collected", "processed", "authorized", "confidentiality", "gdpr", "storage"},
        "ENT-EMPLOYEE-005": {"employee", "employees", "credential", "credentials", "password", "hygiene", "phishing", "training"},
        "POLICY-001": {"refund", "refunds", "refundable", "return", "returns", "exchange", "calendar", "day", "days", "reimbursement"},
        "POLICY-002": {"manual", "exception", "review", "manager", "escalation"},
        "SOP-003": {"sop", "complaint", "complaints", "ticket", "tickets", "verify", "support", "escalat", "agent", "service"}
    }

    def __init__(self, session: Session):
        self.session = session

    def _normalize(self, text: str):
        words = re.findall(r"[a-z0-9]+", text.lower())
        normalized = []
        for word in words:
            if word in self.STOP_WORDS:
                continue
            if word.endswith("ies") and len(word) > 4:
                word = word[:-3] + "y"
            elif word.endswith("es") and len(word) > 4:
                word = word[:-2]
            elif word.endswith("s") and len(word) > 3:
                word = word[:-1]
            normalized.append(word)
        return set(normalized)

    def resolve(self, question: str) -> MemoryRecord:
        # Fetch candidate memories from active records or latest versions
        memories = (
            self.session.query(MemoryRecord)
            .filter(
                MemoryRecord.status == "active",
                MemoryRecord.trust_score >= 0.8,
                MemoryRecord.suspicion_score <= 0.2
            )
            .order_by(
                MemoryRecord.trust_score.desc(),
                MemoryRecord.version.desc()
            )
            .all()
        )

        # Fallback to all latest records if no active trusted records exist
        if not memories:
            all_records = (
                self.session.query(MemoryRecord)
                .order_by(MemoryRecord.version.desc())
                .all()
            )
            latest_map = {}
            for r in all_records:
                if r.memory_id not in latest_map:
                    latest_map[r.memory_id] = r
            memories = list(latest_map.values())

        if not memories:
            raise LookupError("No enterprise memory is available.")

        question_words = self._normalize(question)

        best_memory_id = None
        best_score = 0

        for memory in memories:
            content_words = self._normalize(memory.content or "")
            source_words = self._normalize(memory.source or "")
            domain_words = self.DOMAIN_HINTS.get(memory.memory_id, set())

            content_matches = question_words.intersection(content_words)
            source_matches = question_words.intersection(source_words)
            domain_matches = question_words.intersection(domain_words)

            score = (
                len(content_matches)
                + (2 * len(source_matches))
                + (8 * len(domain_matches))
            )

            # Extra weight if memory_id root keyword is directly in question
            id_lower = memory.memory_id.lower()
            for kw in question_words:
                if kw in id_lower:
                    score += 10

            if score > best_score:
                best_score = score
                best_memory_id = memory.memory_id

        if best_memory_id is None or best_score == 0:
            raise LookupError("No relevant enterprise memory was found.")

        # Find latest record for best_memory_id
        target = (
            self.session.query(MemoryRecord)
            .filter(MemoryRecord.memory_id == best_memory_id)
            .order_by(MemoryRecord.version.desc())
            .first()
        )

        if target is None:
            raise LookupError(f"No version exists for memory '{best_memory_id}'.")

        return target
