import json
import logging
import threading
import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class TimelineEventType(str, Enum):
    PROBE = "PROBE"
    EXPLOIT = "EXPLOIT"
    READ_ATTEMPT = "READ_ATTEMPT"
    DETECTION = "DETECTION"
    RECOVERY = "RECOVERY"
    POST_RECOVERY_READ = "POST_RECOVERY_READ"
    VALIDATION = "VALIDATION"


@dataclass
class TimelineEvent:
    timestamp: float
    event_type: str
    session_id: str
    actor: str
    memory_id: str
    details: Dict[str, Any] = field(default_factory=dict)
    verified: bool = True
    wrong_answer_served: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class SessionTimeline:
    """
    Chronological narrative and forensic timeline for an incident session.
    Tracks adversary actions (probe, exploit) and system responses (read gate, detection, recovery).
    """

    def __init__(self, session_id: str):
        self.session_id = session_id
        self.events: List[TimelineEvent] = []

    def add_event(self, event: TimelineEvent) -> None:
        self.events.append(event)
        self.events.sort(key=lambda e: e.timestamp)

    @property
    def first_probe_time(self) -> Optional[float]:
        probes = [e.timestamp for e in self.events if e.event_type in {TimelineEventType.PROBE.value, TimelineEventType.EXPLOIT.value}]
        return min(probes) if probes else (self.events[0].timestamp if self.events else None)

    @property
    def exploit_time(self) -> Optional[float]:
        exploits = [e.timestamp for e in self.events if e.event_type == TimelineEventType.EXPLOIT.value]
        return min(exploits) if exploits else None

    @property
    def detection_time(self) -> Optional[float]:
        detections = [e.timestamp for e in self.events if e.event_type == TimelineEventType.DETECTION.value]
        return min(detections) if detections else None

    @property
    def recovery_time(self) -> Optional[float]:
        recoveries = [e.timestamp for e in self.events if e.event_type == TimelineEventType.RECOVERY.value]
        return max(recoveries) if recoveries else None

    @property
    def last_activity_time(self) -> Optional[float]:
        return max([e.timestamp for e in self.events]) if self.events else None

    @property
    def dwell_time_seconds(self) -> float:
        if not self.events or self.first_probe_time is None or self.last_activity_time is None:
            return 0.0
        return max(0.0, self.last_activity_time - self.first_probe_time)

    @property
    def time_to_detect_ms(self) -> Optional[float]:
        if self.exploit_time is not None and self.detection_time is not None:
            return max(0.0, (self.detection_time - self.exploit_time) * 1000.0)
        return None

    @property
    def time_to_recover_ms(self) -> Optional[float]:
        if self.detection_time is not None and self.recovery_time is not None:
            return max(0.0, (self.recovery_time - self.detection_time) * 1000.0)
        return None

    @property
    def exposure_window_wrong_answers(self) -> int:
        return sum(1 for e in self.events if e.wrong_answer_served)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "event_count": len(self.events),
            "first_probe_time": self.first_probe_time,
            "exploit_time": self.exploit_time,
            "detection_time": self.detection_time,
            "recovery_time": self.recovery_time,
            "last_activity_time": self.last_activity_time,
            "dwell_time_seconds": round(self.dwell_time_seconds, 4),
            "time_to_detect_ms": round(self.time_to_detect_ms, 2) if self.time_to_detect_ms is not None else None,
            "time_to_recover_ms": round(self.time_to_recover_ms, 2) if self.time_to_recover_ms is not None else None,
            "exposure_window_wrong_answers": self.exposure_window_wrong_answers,
            "events": [e.to_dict() for e in self.events],
        }

    def to_markdown(self) -> str:
        lines = [
            f"# Incident Session Timeline: `{self.session_id}`",
            "",
            f"- **Adversary Dwell Time:** {self.dwell_time_seconds:.4f} s",
            f"- **Time to Detect:** {self.time_to_detect_ms if self.time_to_detect_ms is not None else 'N/A'} ms",
            f"- **Time to Recover:** {self.time_to_recover_ms if self.time_to_recover_ms is not None else 'N/A'} ms",
            f"- **Wrong Answers Served (Exposure Window):** {self.exposure_window_wrong_answers}",
            "",
            "| Relative Time (s) | Event Type | Actor | Memory ID | Verified | Wrong Answer | Details |",
            "|---|---|---|---|---|---|---|",
        ]
        t0 = self.first_probe_time or (self.events[0].timestamp if self.events else time.time())
        for e in self.events:
            dt = e.timestamp - t0
            lines.append(
                f"| +{dt:.4f}s | `{e.event_type}` | {e.actor} | `{e.memory_id}` | "
                f"{'✅' if e.verified else '❌'} | {'⚠️ YES' if e.wrong_answer_served else '🛡️ 0'} | "
                f"{json.dumps(e.details)} |"
            )
        return "\n".join(lines)

    def export_json(self, path: Path | str) -> Path:
        out_path = Path(path)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")
        return out_path


class SessionTimelineReconstructor:
    """
    Forensic Reconstructor that aggregates events across:
    - Attacker harness (probes, exploits)
    - ReadPathGate / ReadAccessLogger (agent reads, blocked attempts)
    - Telemetry / Watcher (detection alerts)
    - TCRP Recovery Ladder (restorations, post-recovery reads)
    """

    def __init__(self):
        self._timelines: Dict[str, SessionTimeline] = {}
        self._lock = threading.RLock()

    def get_or_create(self, session_id: str) -> SessionTimeline:
        with self._lock:
            if session_id not in self._timelines:
                self._timelines[session_id] = SessionTimeline(session_id)
            return self._timelines[session_id]

    def record_probe(
        self,
        session_id: str,
        actor: str,
        memory_id: str,
        probe_type: str = "PORT_SCAN_RECON",
        timestamp: Optional[float] = None,
    ) -> TimelineEvent:
        event = TimelineEvent(
            timestamp=timestamp or time.time(),
            event_type=TimelineEventType.PROBE.value,
            session_id=session_id,
            actor=actor,
            memory_id=memory_id,
            details={"probe_type": probe_type},
            verified=True,
            wrong_answer_served=False,
        )
        self.get_or_create(session_id).add_event(event)
        return event

    def record_exploit(
        self,
        session_id: str,
        actor: str,
        memory_id: str,
        attack_type: str,
        mutation: str,
        target_version: int,
        timestamp: Optional[float] = None,
    ) -> TimelineEvent:
        event = TimelineEvent(
            timestamp=timestamp or time.time(),
            event_type=TimelineEventType.EXPLOIT.value,
            session_id=session_id,
            actor=actor,
            memory_id=memory_id,
            details={
                "attack_type": attack_type,
                "mutation": mutation,
                "target_version": target_version,
            },
            verified=False,
            wrong_answer_served=False,
        )
        self.get_or_create(session_id).add_event(event)
        return event

    def record_read_attempt(
        self,
        session_id: str,
        actor: str,
        memory_id: str,
        verified: bool,
        wrong_answer_served: bool = False,
        details: Optional[Dict[str, Any]] = None,
        timestamp: Optional[float] = None,
    ) -> TimelineEvent:
        event = TimelineEvent(
            timestamp=timestamp or time.time(),
            event_type=TimelineEventType.READ_ATTEMPT.value,
            session_id=session_id,
            actor=actor,
            memory_id=memory_id,
            details=details or {},
            verified=verified,
            wrong_answer_served=wrong_answer_served,
        )
        self.get_or_create(session_id).add_event(event)
        return event

    def record_detection(
        self,
        session_id: str,
        memory_id: str,
        reason: str,
        detector: str = "aegismem_watcher",
        timestamp: Optional[float] = None,
    ) -> TimelineEvent:
        event = TimelineEvent(
            timestamp=timestamp or time.time(),
            event_type=TimelineEventType.DETECTION.value,
            session_id=session_id,
            actor=detector,
            memory_id=memory_id,
            details={"reason": reason},
            verified=False,
            wrong_answer_served=False,
        )
        self.get_or_create(session_id).add_event(event)
        return event

    def record_recovery(
        self,
        session_id: str,
        memory_id: str,
        ladder_level: int,
        restored_version: int,
        timestamp: Optional[float] = None,
    ) -> TimelineEvent:
        event = TimelineEvent(
            timestamp=timestamp or time.time(),
            event_type=TimelineEventType.RECOVERY.value,
            session_id=session_id,
            actor="aegismem_tcrp_ladder",
            memory_id=memory_id,
            details={"ladder_level": ladder_level, "restored_version": restored_version},
            verified=True,
            wrong_answer_served=False,
        )
        self.get_or_create(session_id).add_event(event)
        return event

    def record_post_recovery_read(
        self,
        session_id: str,
        actor: str,
        memory_id: str,
        verified: bool,
        answer: str,
        timestamp: Optional[float] = None,
    ) -> TimelineEvent:
        event = TimelineEvent(
            timestamp=timestamp or time.time(),
            event_type=TimelineEventType.POST_RECOVERY_READ.value,
            session_id=session_id,
            actor=actor,
            memory_id=memory_id,
            details={"answer": answer[:80]},
            verified=verified,
            wrong_answer_served=not verified,
        )
        self.get_or_create(session_id).add_event(event)
        return event

    def clear(self) -> None:
        with self._lock:
            self._timelines.clear()


_GLOBAL_RECONSTRUCTOR: Optional[SessionTimelineReconstructor] = None


def get_session_timeline_reconstructor() -> SessionTimelineReconstructor:
    global _GLOBAL_RECONSTRUCTOR
    if _GLOBAL_RECONSTRUCTOR is None:
        _GLOBAL_RECONSTRUCTOR = SessionTimelineReconstructor()
    return _GLOBAL_RECONSTRUCTOR
