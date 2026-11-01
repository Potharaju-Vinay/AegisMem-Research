import json
from dataclasses import dataclass

from core.integrity.hash import calculate_version_hash
from core.integrity.hasher import MemoryHasher


@dataclass(frozen=True)
class IntegrityResult:
    memory_id: str
    expected_hash: str
    observed_hash: str
    valid: bool


class IntegrityVerifier:
    def __init__(self, manifest_store=None):
        self.manifest_store = manifest_store

    def verify(self, memory_id, content, source, source_type, expected_hash):
        observed_hash = MemoryHasher.hash_memory(
            memory_id=memory_id,
            content=content,
            source=source,
            source_type=source_type,
        )
        return IntegrityResult(
            memory_id=memory_id,
            expected_hash=expected_hash,
            observed_hash=observed_hash,
            valid=observed_hash == expected_hash,
        )

    def verify_memory(self, memory):
        expected_hash = getattr(memory, "content_hash", None)
        if expected_hash is None:
            return False

        observed_hash = calculate_version_hash(
            memory.content, memory.previous_hash
        )
        if observed_hash != expected_hash:
            return False

        if self.manifest_store is not None:
            return self.manifest_store.verify_record(memory)

        return True

    def verify_chain(self, history):
        if not history:
            return True

        previous_hash = None
        previous_version = 0

        for record in history:
            if record.version != previous_version + 1:
                return False
            if record.previous_hash != previous_hash:
                return False

            calculated_hash = calculate_version_hash(
                record.content, record.previous_hash
            )
            if calculated_hash != record.content_hash:
                return False

            previous_hash = record.content_hash
            previous_version = record.version

        return True

    
    def verify_provenance_chain(self, events):
        if not events:
            return True

        previous_hash = None
        previous_version = None
        previous_memory_id = None

        try:
            for event in events:
                if previous_version is None:
                    if event.previous_event_hash is not None:
                        return False
                elif event.memory_id != previous_memory_id:
                    return False
                elif event.previous_event_hash != previous_hash:
                    return False

                if (
                    previous_version is not None
                    and event.version < previous_version
                ):
                    return False

                metadata = {}
                if event.event_metadata:
                    metadata = json.loads(event.event_metadata)

                if not isinstance(metadata, dict):
                    return False

                payload = {
                    "memory_record_id": event.memory_record_id,
                    "memory_id": event.memory_id,
                    "version": event.version,
                    "actor": event.actor,
                    "operation": event.operation,
                    "source": event.source,
                    "source_type": event.source_type,
                    "previous_event_hash": event.previous_event_hash,
                    "metadata": metadata,
                }

                calculated_hash = calculate_version_hash(
                    json.dumps(payload, sort_keys=True),
                    None,
                )

                if calculated_hash != event.event_hash:
                    return False

                previous_hash = event.event_hash
                previous_version = event.version
                previous_memory_id = event.memory_id

        except (ValueError, TypeError, AttributeError):
            return False

        return True
