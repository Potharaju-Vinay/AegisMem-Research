import re

from sqlalchemy.orm import Session

from core.memory.models import MemoryRecord


class MemoryResolver:

    STOP_WORDS = {
        "what",
        "is",
        "the",
        "a",
        "an",
        "are",
        "of",
        "to",
        "for",
        "in",
        "on",
        "and",
        "or",
        "does",
        "do",
        "can",
        "within",
        "this",
        "that"
    }

    def __init__(self, session: Session):
        self.session = session

    def _normalize(self, text: str):
        words = re.findall(
            r"[a-z0-9]+",
            text.lower()
        )

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

        if not memories:
            raise LookupError(
                "No trusted active memory is available."
            )

        question_words = self._normalize(question)

        best_memory_id = None
        best_score = 0

        for memory in memories:

            content_words = self._normalize(
                memory.content
            )

            source_words = self._normalize(
                memory.source
            )

            content_matches = question_words.intersection(
                content_words
            )

            source_matches = question_words.intersection(
                source_words
            )

            score = (
                len(content_matches)
                + (2 * len(source_matches))
            )

            if score > best_score:
                best_score = score
                best_memory_id = memory.memory_id

        if best_memory_id is None or best_score == 0:
            raise LookupError(
                "No relevant trusted memory was found."
            )

        trusted_memory = (
            self.session.query(MemoryRecord)
            .filter(
                MemoryRecord.memory_id == best_memory_id,
                MemoryRecord.status == "active",
                MemoryRecord.trust_score >= 0.8,
                MemoryRecord.suspicion_score <= 0.2
            )
            .order_by(
                MemoryRecord.version.desc()
            )
            .first()
        )

        if trusted_memory is None:
            raise LookupError(
                f"No trusted version exists for memory '{best_memory_id}'."
            )

        return trusted_memory