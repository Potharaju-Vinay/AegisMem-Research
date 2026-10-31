from dataclasses import dataclass
from hashlib import sha256
from uuid import uuid4

from core.memory.models import MemoryRecord


@dataclass
class CorruptionCase:
    attack_id: str
    memory_id: str
    original_content: str
    modified_content: str
    corruption_type: str
    original_hash: str
    modified_hash: str


class CorruptionGenerator:

    def _build_case(
        self,
        memory: MemoryRecord,
        modified_content: str,
        corruption_type: str
    ) -> CorruptionCase:

        if not modified_content:
            raise ValueError("Modified content cannot be empty.")

        if modified_content == memory.content:
            raise ValueError(
                "Modified content must differ from original content."
            )

        original_hash = sha256(
            memory.content.encode("utf-8")
        ).hexdigest()

        modified_hash = sha256(
            modified_content.encode("utf-8")
        ).hexdigest()

        return CorruptionCase(
            attack_id=f"ATT-{uuid4().hex[:12].upper()}",
            memory_id=memory.memory_id,
            original_content=memory.content,
            modified_content=modified_content,
            corruption_type=corruption_type,
            original_hash=original_hash,
            modified_hash=modified_hash
        )

    def generate(
        self,
        memory: MemoryRecord,
        modified_content: str,
        corruption_type: str = "content_tampering"
    ) -> CorruptionCase:

        return self._build_case(
            memory,
            modified_content,
            corruption_type
        )

    def numerical_mutation(
        self,
        memory: MemoryRecord,
        old_value: str,
        new_value: str
    ) -> CorruptionCase:

        if old_value not in memory.content:
            raise ValueError(
                f"Value '{old_value}' not found in memory."
            )

        modified = memory.content.replace(
            old_value,
            new_value,
            1
        )

        return self._build_case(
            memory,
            modified,
            "numerical_mutation"
        )

    def negation_mutation(
        self,
        memory: MemoryRecord,
        target: str,
        replacement: str
    ) -> CorruptionCase:

        if target not in memory.content:
            raise ValueError(
                f"Target '{target}' not found in memory."
            )

        modified = memory.content.replace(
            target,
            replacement,
            1
        )

        return self._build_case(
            memory,
            modified,
            "negation_mutation"
        )

    def permission_mutation(
        self,
        memory: MemoryRecord,
        target: str,
        replacement: str
    ) -> CorruptionCase:

        if target not in memory.content:
            raise ValueError(
                f"Target '{target}' not found in memory."
            )

        modified = memory.content.replace(
            target,
            replacement,
            1
        )

        return self._build_case(
            memory,
            modified,
            "permission_mutation"
        )

    def obligation_mutation(
        self,
        memory: MemoryRecord,
        target: str,
        replacement: str
    ) -> CorruptionCase:

        if target not in memory.content:
            raise ValueError(
                f"Target '{target}' not in memory."
            )

        modified = memory.content.replace(
            target,
            replacement,
            1
        )

        return self._build_case(
            memory,
            modified,
            "obligation_mutation"
        )
