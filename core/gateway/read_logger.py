import json
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional
from uuid import uuid4


class ReadAccessLogger:
    """
    Forensic read-access logging for persistent agent memories.
    Records every retrieval attempt (accessor, session, source IP, timestamp, verification status)
    enabling complete post-incident session reconstruction and dwell-time calculation.
    """

    def __init__(self, log_path: Optional[Path | str] = None):
        self.log_path = Path(log_path) if log_path else Path("data/read_access_log.jsonl")
        self._events: List[Dict[str, Any]] = []
        self._lock = threading.RLock()

    def log_read(
        self,
        memory_id: str,
        version: int,
        accessor: str = "support_agent",
        session_id: Optional[str] = None,
        source_ip: Optional[str] = None,
        verified: bool = True,
        access_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        event = {
            "access_id": access_id or f"READ-{uuid4().hex[:10]}",
            "event_type": "MEMORY_READ",
            "memory_id": memory_id,
            "version": int(version),
            "accessor": accessor,
            "session_id": session_id or "anonymous-session",
            "source_ip": source_ip or "127.0.0.1",
            "timestamp": time.time(),
            "verified": verified,
        }

        with self._lock:
            self._events.append(event)
            try:
                self.log_path.parent.mkdir(parents=True, exist_ok=True)
                with open(self.log_path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(event) + "\n")
            except Exception:
                pass

        return event

    def get_session_reads(self, session_id: str) -> List[Dict[str, Any]]:
        with self._lock:
            return [e for e in self._events if e.get("session_id") == session_id]

    def list_all_reads(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._events)

    def clear(self) -> None:
        with self._lock:
            self._events.clear()


_GLOBAL_READ_LOGGER: Optional[ReadAccessLogger] = None


def get_read_access_logger(log_path: Optional[Path | str] = None) -> ReadAccessLogger:
    global _GLOBAL_READ_LOGGER
    if _GLOBAL_READ_LOGGER is None:
        _GLOBAL_READ_LOGGER = ReadAccessLogger(log_path)
    return _GLOBAL_READ_LOGGER
