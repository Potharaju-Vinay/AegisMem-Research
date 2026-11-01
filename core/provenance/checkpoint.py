import base64
import hashlib
import json
import os
import tempfile
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from core.integrity.verifier import IntegrityVerifier


def _canonical_payload(checkpoint: dict) -> bytes:
    fields = {
        "memory_id": checkpoint["memory_id"],
        "version": checkpoint["version"],
        "event_hash": checkpoint["event_hash"],
        "event_count": checkpoint["event_count"],
    }
    return json.dumps(
        fields, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


class ProvenanceCheckpointStore:
    def __init__(
        self,
        checkpoint_dir="security/provenance_checkpoints",
        private_key_path="security/keys/integrity_anchor_private.pem",
        public_key_path="security/keys/integrity_anchor_public.pem",
    ):
        self.checkpoint_dir = Path(checkpoint_dir)
        self.private_key_path = Path(private_key_path)
        self.public_key_path = Path(public_key_path)

    def _path(self, memory_id: str, version: int) -> Path:
        safe_id = hashlib.sha256(
            memory_id.encode("utf-8")
        ).hexdigest()
        return self.checkpoint_dir / f"{safe_id}.{version}.json"

    def create_checkpoint(self, events: list) -> dict:
        if not events:
            raise ValueError("Cannot checkpoint an empty provenance chain")
        
        events = sorted(events, key=lambda event: event.version)

        if not IntegrityVerifier().verify_provenance_chain(events):
            raise ValueError("Cannot checkpoint an invalid provenance chain")

        memory_id = events[0].memory_id

        if any(event.memory_id != memory_id for event in events):
            raise ValueError("Events must belong to the same memory")

        for i in range(1, len(events)):
            if events[i].version < events[i-1].version:
                raise ValueError("Provenance versions must be monotonic")

        checkpoint = {
            "memory_id": memory_id,
            "version": events[-1].version,
            "event_hash": events[-1].event_hash,
            "event_count": len(events),
        }

        private_key = serialization.load_pem_private_key(
            self.private_key_path.read_bytes(),
            password=None,
        )
        signature = private_key.sign(_canonical_payload(checkpoint))
        checkpoint["signature"] = base64.b64encode(
            signature
        ).decode("ascii")

        self.checkpoint_dir.mkdir(parents=True, exist_ok=True)
        destination = self._path(memory_id, events[-1].version)

        if destination.exists():
            raise FileExistsError(
                f"Checkpoint already exists for version {events[-1].version}"
            )

        fd, temporary_name = tempfile.mkstemp(
            prefix=".checkpoint-",
            suffix=".tmp",
            dir=self.checkpoint_dir,
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(checkpoint, handle, sort_keys=True, indent=2)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary_name, destination)
        except Exception:
            try:
                os.unlink(temporary_name)
            except FileNotFoundError:
                pass
            raise

        return checkpoint

    def verify_checkpoint(self, events: list) -> str:
        if not events:
            return "CHECKPOINT_MISSING"
        
        if not IntegrityVerifier().verify_provenance_chain(events):
            return "CHAIN_TAMPERED"

        events = sorted(events, key=lambda event: event.version)
        memory_id = events[0].memory_id

        if any(event.memory_id != memory_id for event in events):
            return "CHAIN_TAMPERED"

        for i in range(1, len(events)):
            if events[i].version < events[i-1].version:
                return "CHAIN_TAMPERED"

        latest_version = events[-1].version
        path = self._path(memory_id, latest_version)

        if not path.is_file():
            return "CHECKPOINT_MISSING"

        try:
            checkpoint = json.loads(path.read_text(encoding="utf-8"))
            public_key = serialization.load_pem_public_key(
                self.public_key_path.read_bytes()
            )
            signature = base64.b64decode(
                checkpoint["signature"], validate=True
            )
            public_key.verify(
                signature,
                _canonical_payload(checkpoint),
            )
        except InvalidSignature:
            return "CHECKPOINT_INVALID"
        except (
            OSError,
            json.JSONDecodeError,
            KeyError,
            TypeError,
            ValueError,
        ):
            return "CHECKPOINT_INVALID"

        if (
            checkpoint.get("memory_id") != memory_id
            or checkpoint.get("version") != latest_version
            or checkpoint.get("event_hash") != events[-1].event_hash
            or checkpoint.get("event_count") != len(events)
        ):
            return "CHECKPOINT_MISMATCH"

        return "VALID"

