import re
from dataclasses import dataclass


@dataclass
class QueryIntent:
    intent: str
    topic: str | None
    customer_days: int | None
    keywords: list[str]


class QueryParser:

    REFUND_WORDS = {
        "refund",
        "refunds",
        "refundable",
        "refunds",
        "eligible"
    }

    def parse(self, question: str) -> QueryIntent:

        text = question.lower()

        customer_days = self._extract_days(text)

        if any(word in text for word in self.REFUND_WORDS):
            intent = "refund_eligibility"
            topic = "refund_policy"
        else:
            intent = "memory_query"
            topic = None

        keywords = self._extract_keywords(text)

        return QueryIntent(
            intent=intent,
            topic=topic,
            customer_days=customer_days,
            keywords=keywords
        )

    def _extract_days(self, text: str):

        patterns = [
            r"(\d+)\s*days?\s*ago",
            r"(\d+)\s*days?",
            r"(\d+)\s*day\s*ago"
        ]

        for pattern in patterns:

            match = re.search(
                pattern,
                text
            )

            if match:
                return int(match.group(1))

        return None

    def _extract_keywords(self, text: str):

        words = re.findall(
            r"[a-z0-9]+",
            text
        )

        stop_words = {
            "i",
            "am",
            "is",
            "the",
            "a",
            "an",
            "this",
            "that",
            "can",
            "could",
            "would",
            "should",
            "what",
            "is",
            "are",
            "was",
            "were",
            "do",
            "does",
            "did",
            "my",
            "me",
            "for",
            "to",
            "of",
            "in",
            "on",
            "within",
            "ago"
        }

        return [
            word
            for word in words
            if word not in stop_words
        ]