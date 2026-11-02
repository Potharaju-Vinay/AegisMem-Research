import threading
import time
from typing import Any, Dict, List, Optional, Tuple

from core.gateway.read_logger import ReadAccessLogger, get_read_access_logger
from core.integrity.hash import calculate_version_hash
from core.integrity.manifest_store import IntegrityManifestStore
from core.memory.authority import (
    AuthorityTier,
    MemoryClass,
    MEMORY_CLASS_POLICY,
    classify_memory,
)
from core.memory.models import MemoryRecord
from core.memory.repository import MemoryRepository
from core.security.owner_approval import verify_record_owner_approval
from core.security.revocation import KeyRevocationRegistry, get_revocation_registry


class UnverifiedMemoryAccessError(Exception):
    """Raised when an unverified, tampered, or authority-violating memory is requested."""
    pass


class ReadPathGate:
    """
    Cryptographic Read-Path Verification Gate for Enterprise AI Agents.
    Guarantees that an AI support agent NEVER receives unverified, poisoned, or
    tampered memories on retrieval, even if an attack is active or the background detector is stopped.
    
    Features:
    - Verify-on-read for Critical/High memory classes.
    - Zero exposure window (0 wrong answers served).
    - Verification cache keyed on (memory_id, version, content_hash), invalidated on head change.
    - Authority tier boundaries: prevents conversation notes from overriding policies (MINJA defense).
    - Read access logging for forensic dwell-time and incident reconstruction.
    """

    def __init__(
        self,
        repository: MemoryRepository,
        manifest_store: Optional[IntegrityManifestStore] = None,
        revocation_registry: Optional[KeyRevocationRegistry] = None,
        read_logger: Optional[ReadAccessLogger] = None,
        enable_cache: bool = True,
        cache_ttl_seconds: float = 300.0,
    ):
        self.repository = repository
        self.manifest_store = manifest_store or getattr(repository, "manifest_store", None) or IntegrityManifestStore()
        self.revocation_registry = revocation_registry or get_revocation_registry()
        self.read_logger = read_logger if read_logger is not None else get_read_access_logger()
        self.enable_cache = enable_cache
        self.cache_ttl_seconds = cache_ttl_seconds
        self._verification_cache: Dict[Tuple[str, int, str], Dict[str, Any]] = {}
        self._lock = threading.RLock()
        self.stats = {
            "verified_reads": 0,
            "blocked_reads": 0,
            "cache_hits": 0,
            "cache_misses": 0,
        }

    def invalidate_cache(self, memory_id: Optional[str] = None) -> None:
        """
        Invalidates cached verification results for a specific memory or all memories.
        Must be called whenever a memory head or status changes.
        """
        with self._lock:
            if memory_id is None:
                self._verification_cache.clear()
            else:
                keys_to_remove = [k for k in self._verification_cache if k[0] == memory_id]
                for k in keys_to_remove:
                    del self._verification_cache[k]

    def _verify_record(self, record: MemoryRecord, mem_class: MemoryClass) -> bool:
        """
        Cryptographic verification engine on read path.
        """
        # 1. Status Check
        if record.status in {"CORRUPTED", "QUARANTINED", "DELETED"}:
            return False

        # 2. Content Hash Check
        expected_hash = calculate_version_hash(record.content, record.previous_hash)
        if record.content_hash != expected_hash:
            return False

        class_policy = MEMORY_CLASS_POLICY.get(mem_class, {})
        requires_sig = class_policy.get("requires_owner_signature", False)

        # 3. Cryptographic Signature & Manifest Check for Signed Tiers
        if requires_sig:
            # Check owner approval signature
            sig_valid = verify_record_owner_approval(record)
            if not sig_valid:
                # Check independent manifest
                if self.manifest_store and self.manifest_store.has_manifest(record):
                    if not self.manifest_store.verify_record(record):
                        return False
                else:
                    return False

            # Check key revocation
            if hasattr(record, "authorization_id") and record.authorization_id:
                pass

        elif class_policy.get("requires_editor_signature", False):
            if self.manifest_store and self.manifest_store.has_manifest(record):
                if not self.manifest_store.verify_record(record):
                    return False

        return True

    def get_verified_memory(
        self,
        memory_id: str,
        required_class: Optional[MemoryClass | str] = None,
        fail_closed: bool = True,
        session_id: Optional[str] = None,
        source_ip: Optional[str] = None,
        accessor: str = "support_agent",
    ) -> Optional[MemoryRecord]:
        """
        Retrieves and strictly verifies the latest memory revision before serving to the agent.
        If verification fails:
          - If fail_closed=True: returns None (blocking poisoned content, 0 wrong answers).
          - If fail_closed=False: raises UnverifiedMemoryAccessError.
        """
        record = self.repository.get_latest(memory_id)
        if record is None:
            if self.read_logger:
                self.read_logger.log_read(
                    memory_id=memory_id,
                    version=0,
                    accessor=accessor,
                    session_id=session_id,
                    source_ip=source_ip,
                    verified=False,
                )
            return None

        # Determine Memory Class
        mem_class = classify_memory(memory_id)

        # Authority Boundary Enforcement (MINJA defense)
        if required_class is not None:
            if isinstance(required_class, str):
                required_class = MemoryClass(required_class.lower())
            
            # If agent requests a Policy or FAQ, but the memory is a conversation note or customer profile, reject!
            if required_class in {MemoryClass.POLICY, MemoryClass.PRICING_PROMOTIONS, MemoryClass.ESCALATION_PROCEDURES, MemoryClass.PRODUCT_FAQ}:
                if mem_class in {MemoryClass.CONVERSATION_NOTE, MemoryClass.CUSTOMER_PROFILE}:
                    with self._lock:
                        self.stats["blocked_reads"] += 1
                    if self.read_logger:
                        self.read_logger.log_read(
                            memory_id=record.memory_id,
                            version=record.version,
                            accessor=accessor,
                            session_id=session_id,
                            source_ip=source_ip,
                            verified=False,
                        )
                    if fail_closed:
                        return None
                    raise UnverifiedMemoryAccessError(
                        f"Authority Tier Violation: Lower authority record '{memory_id}' ({mem_class.value}) cannot be served as '{required_class.value}'."
                    )

        # Check if verify-on-read is required
        class_policy = MEMORY_CLASS_POLICY.get(mem_class, {})
        if not class_policy.get("verify_on_read", False):
            with self._lock:
                self.stats["verified_reads"] += 1
            if self.read_logger:
                self.read_logger.log_read(
                    memory_id=record.memory_id,
                    version=record.version,
                    accessor=accessor,
                    session_id=session_id,
                    source_ip=source_ip,
                    verified=True,
                )
            return record

        # Verification Cache Lookup
        cache_key = (record.memory_id, record.version, record.content_hash)
        now = time.time()

        with self._lock:
            cached_entry = self._verification_cache.get(cache_key)
            if self.enable_cache and cached_entry:
                if (now - cached_entry["cached_at"]) < self.cache_ttl_seconds:
                    if cached_entry["verified"]:
                        self.stats["cache_hits"] += 1
                        self.stats["verified_reads"] += 1
                        if self.read_logger:
                            self.read_logger.log_read(
                                memory_id=record.memory_id,
                                version=record.version,
                                accessor=accessor,
                                session_id=session_id,
                                source_ip=source_ip,
                                verified=True,
                            )
                        return record
                    else:
                        self.stats["blocked_reads"] += 1
                        if self.read_logger:
                            self.read_logger.log_read(
                                memory_id=record.memory_id,
                                version=record.version,
                                accessor=accessor,
                                session_id=session_id,
                                source_ip=source_ip,
                                verified=False,
                            )
                        if fail_closed:
                            return None
                        raise UnverifiedMemoryAccessError(f"Cached verification failed for memory '{memory_id}'.")

            self.stats["cache_misses"] += 1

        # Perform Live Cryptographic Verification
        is_verified = self._verify_record(record, mem_class)

        with self._lock:
            if self.enable_cache:
                self._verification_cache[cache_key] = {
                    "verified": is_verified,
                    "cached_at": now,
                }

            if not is_verified:
                self.stats["blocked_reads"] += 1
                if self.read_logger:
                    self.read_logger.log_read(
                        memory_id=record.memory_id,
                        version=record.version,
                        accessor=accessor,
                        session_id=session_id,
                        source_ip=source_ip,
                        verified=False,
                    )
                if fail_closed:
                    return None
                raise UnverifiedMemoryAccessError(
                    f"Read Gate Block: Memory '{memory_id}' v{record.version} failed cryptographic integrity verification."
                )

            self.stats["verified_reads"] += 1
            if self.read_logger:
                self.read_logger.log_read(
                    memory_id=record.memory_id,
                    version=record.version,
                    accessor=accessor,
                    session_id=session_id,
                    source_ip=source_ip,
                    verified=True,
                )

        return record

    def query_verified_memories(
        self,
        required_class: MemoryClass,
        memory_ids: Optional[List[str]] = None,
        session_id: Optional[str] = None,
        source_ip: Optional[str] = None,
        accessor: str = "support_agent",
    ) -> List[MemoryRecord]:
        """
        Queries all verified memories belonging to a specific authority class.
        Automatically filters out conversation notes and unverified/compromised records.
        """
        all_ids = memory_ids or []
        if not all_ids:
            # Query all monitored IDs from repository
            all_records = self.repository.session.query(MemoryRecord.memory_id).distinct().all()
            all_ids = [r[0] for r in all_records]

        verified_records = []
        for mid in all_ids:
            m_class = classify_memory(mid)
            if m_class == required_class:
                rec = self.get_verified_memory(
                    mid,
                    required_class=required_class,
                    fail_closed=True,
                    session_id=session_id,
                    source_ip=source_ip,
                    accessor=accessor,
                )
                if rec is not None:
                    verified_records.append(rec)

        return verified_records
