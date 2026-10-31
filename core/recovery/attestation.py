import base64
import hashlib
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization


BASE_DIR = Path(__file__).resolve().parents[2]
PRIVATE_KEY_PATH = BASE_DIR / "security" / "keys" / "recovery_attestation_private.pem"
PUBLIC_KEY_PATH = BASE_DIR / "security" / "keys" / "recovery_attestation_public.pem"
ATTESTATION_DIR = BASE_DIR / "security" / "recovery_attestations"
PROTOCOL = "aegismem-recovery-attestation-v1"


def canonical_payload(attestation: dict) -> bytes:
    fields = {
        key: value
        for key, value in attestation.items()
        if key != "signature"
    }
    return json.dumps(
        fields,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


class RecoveryAttestationStore:
    def __init__(
        self,
        attestation_dir: str | Path = ATTESTATION_DIR,
        private_key_path: str | Path = PRIVATE_KEY_PATH,
        public_key_path: str | Path = PUBLIC_KEY_PATH,
    ):
        self.attestation_dir = Path(attestation_dir)
        self.private_key_path = Path(private_key_path)
        self.public_key_path = Path(public_key_path)

    def _path(self, memory_id: str, version: int) -> Path:
        safe_id = hashlib.sha256(
            memory_id.encode("utf-8")
        ).hexdigest()
        return self.attestation_dir / f"{safe_id}.{version}.json"

    def create_for_record(
        self,
        record,
        source_record,
        compromised_record,
    ) -> dict:
        if not self.private_key_path.is_file():
            raise FileNotFoundError("Recovery signing key is missing.")

        destination = self._path(record.memory_id, record.version)
        if destination.exists():
            raise FileExistsError(
                f"Recovery attestation already exists for version {record.version}."
            )

        if not (
            record.memory_id == source_record.memory_id
            == compromised_record.memory_id
        ):
            raise ValueError("Recovery records must have the same memory ID.")

        if record.parent_revision_id != compromised_record.revision_id:
            raise ValueError("Recovered revision does not descend from the compromised revision.")

        if record.content != source_record.content:
            raise ValueError("Recovered content does not match the trusted source content.")

        attestation = {
            "protocol": PROTOCOL,
            "operation": "memory.recovery",
            "memory_id": record.memory_id,
            "source_revision_id": source_record.revision_id,
            "source_version": source_record.version,
            "source_content_hash": source_record.content_hash,
            "compromised_revision_id": compromised_record.revision_id,
            "compromised_version": compromised_record.version,
            "compromised_content_hash": compromised_record.content_hash,
            "recovered_revision_id": record.revision_id,
            "recovered_version": record.version,
            "recovered_content_hash": record.content_hash,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }

        private_key = serialization.load_pem_private_key(
            self.private_key_path.read_bytes(),
            password=None,
        )
        signature = private_key.sign(canonical_payload(attestation))
        attestation["signature"] = base64.b64encode(signature).decode("ascii")

        self.attestation_dir.mkdir(parents=True, exist_ok=True)
        fd, temporary_name = tempfile.mkstemp(
            prefix=".recovery-attestation-",
            suffix=".tmp",
            dir=self.attestation_dir,
        )

        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(attestation, handle, sort_keys=True, indent=2)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary_name, destination)
        except Exception:
            try:
                os.unlink(temporary_name)
            except FileNotFoundError:
                pass
            raise

        return attestation

    def load_verified_attestation(self, record) -> dict | None:
        try:
            path = self._path(record.memory_id, record.version)
            attestation = json.loads(path.read_text(encoding="utf-8"))

            if not isinstance(attestation, dict):
                return None

            if attestation.get("protocol") != PROTOCOL:
                return None

            if attestation.get("operation") != "memory.recovery":
                return None

            if (
                attestation.get("memory_id") != record.memory_id
                or attestation.get("recovered_revision_id") != record.revision_id
                or attestation.get("recovered_version") != record.version
                or attestation.get("recovered_content_hash") != record.content_hash
                or not attestation.get("source_revision_id")
                or not attestation.get("compromised_revision_id")
                or not attestation.get("created_at")
            ):
                return None

            signature = base64.b64decode(
                attestation["signature"],
                validate=True,
            )
            public_key = serialization.load_pem_public_key(
                self.public_key_path.read_bytes()
            )
            public_key.verify(
                signature,
                canonical_payload(attestation),
            )

            return attestation

        except Exception:
            return None

    def verify_record(self, record) -> bool:
        return self.load_verified_attestation(record) is not None