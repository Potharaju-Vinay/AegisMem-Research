
import hashlib
import json
from typing import Any


class MemoryHasher:

    @staticmethod
    def canonicalize(
        memory_id: str,
        content: str,
        source: str,
        source_type: str
    ) -> str:

        payload = {
            "memory_id": memory_id,
            "content": content,
            "source": source,
            "source_type": source_type
        }

        return json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False
        )

    @classmethod
    def hash_memory(
        cls,
        memory_id: str,
        content: str,
        source: str,
        source_type: str
    ) -> str:

        canonical = cls.canonicalize(
            memory_id,
            content,
            source,
            source_type
        )

        return hashlib.sha256(
            canonical.encode("utf-8")
        ).hexdigest()
