import asyncio
import os
import time
from typing import Any, Optional

from sqlalchemy import select

from core.memory.database import get_session
from core.memory.models import MemoryRecord
from core.security.monitor import AegisMemSecurityMonitor


class AegisMemWatcher:
    """
    Continuous compromise monitoring and real-time detection watcher.
    Supports both:
    1. Event-driven detection (zero 2.0s floor): immediate dispatch via store change hooks or PostgreSQL LISTEN/NOTIFY.
    2. Periodic reconciliation scan: periodic polling fallback for un-hooked direct external writes.
    """

    def __init__(
        self,
        interval_seconds: float = 2.0,
        event_driven: bool = False,
        store: Optional[Any] = None,
        session_factory: Optional[Any] = None,
    ):
        self.interval_seconds = interval_seconds
        self.event_driven = event_driven
        self.paused = False
        self._stop_event = asyncio.Event()
        self._event_queue: Optional[asyncio.Queue] = None
        self._last_seen_versions = {}
        self._last_seen_fingerprints = {}
        self.store = store
        self.session_factory = (
            session_factory
            or getattr(store, "session_factory", None)
            or getattr(store, "_session_factory", None)
        )
        if self.store is not None:
            self.store.register_change_hook(self.on_store_change)

    def on_store_change(self, memory_id: str, version: int) -> None:
        """Immediate event-driven change notification hook from storage layer."""
        t_write = time.perf_counter()
        if self._event_queue is not None:
            try:
                self._event_queue.put_nowait((memory_id, version, t_write))
            except Exception:
                pass
        else:
            try:
                self.process_memory(memory_id, t_write=t_write)
            except Exception as exc:
                print(f"[AegisMem Watcher Hook Exception] {type(exc).__name__}: {exc}")

    def trigger_event(
        self,
        memory_id: str,
        version: int = 1,
        t_write: Optional[float] = None,
    ) -> dict:
        """
        Synchronously trigger real-time detection and recovery for an incident with dynamic latency measurement.
        """
        t0 = t_write if t_write is not None else time.perf_counter()
        return self.process_memory(memory_id, t_write=t0)

    def _get_session(self):
        return self.session_factory() if self.session_factory else get_session()

    def get_memory_ids(self):
        session = self._get_session()
        try:
            return session.execute(
                select(MemoryRecord.memory_id).distinct()
            ).scalars().all()
        finally:
            session.close()

    def get_latest_record_state(self, memory_id):
        session = self._get_session()
        try:
            memory = (
                session.query(MemoryRecord)
                .filter(MemoryRecord.memory_id == memory_id)
                .order_by(MemoryRecord.version.desc())
                .first()
            )
            if memory is None:
                return None

            return {
                "version": memory.version,
                "revision_id": memory.revision_id,
                "content_hash": memory.content_hash,
                "status": memory.status,
                "content": memory.content,
            }
        finally:
            session.close()

    def get_latest_version(self, memory_id):
        state = self.get_latest_record_state(memory_id)
        return state["version"] if state else None

    @staticmethod
    def _fingerprint(state):
        return (
            state["version"],
            state["revision_id"],
            state["content_hash"],
            state["status"],
            state["content"],
        )

    def process_memory(self, memory_id: str, t_write: Optional[float] = None):
        session = self._get_session()
        try:
            monitor = AegisMemSecurityMonitor(session)
            return monitor.process(memory_id, t_write=t_write)
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def scan_once(self):
        if getattr(self, "paused", False):
            return []

        results = []

        for memory_id in self.get_memory_ids():
            state = self.get_latest_record_state(memory_id)
            if state is None:
                continue

            fingerprint = self._fingerprint(state)
            previous = self._last_seen_fingerprints.get(memory_id)

            if previous is None:
                self._last_seen_fingerprints[memory_id] = fingerprint
                self._last_seen_versions[memory_id] = state["version"]
                continue

            if previous == fingerprint:
                continue

            try:
                print(
                    f"\n[AegisMem Watcher] >>> DETECTED MEMORY MODIFICATION: '{memory_id}'"
                    f"\n[AegisMem Watcher] Observed Version : v{state['version']} (Status: {state['status']})"
                    f"\n[AegisMem Watcher] Triggering independent compromise detector & TCRP recovery engine..."
                )
                result = self.process_memory(memory_id)
                latest = self.get_latest_record_state(memory_id)

                if latest is not None:
                    self._last_seen_fingerprints[memory_id] = (
                        self._fingerprint(latest)
                    )
                    self._last_seen_versions[memory_id] = latest["version"]

                recovered = result.get("recovered", False)
                detected = result.get("detected", False)
                latest_v = latest["version"] if latest else "unknown"
                latest_s = latest["status"] if latest else "unknown"

                if detected:
                    print(
                        f"[AegisMem Watcher] Compromise confirmed on '{memory_id}'."
                        f"\n[AegisMem Watcher] Self-healing outcome: {'RECOVERED' if recovered else 'QUARANTINED/UNRECOVERED'}"
                        f"\n[AegisMem Watcher] Active memory state is now: v{latest_v} (Status: {latest_s})\n"
                    )
                else:
                    print(
                        f"[AegisMem Watcher] State change processed for '{memory_id}': No compromise detected.\n"
                    )

                results.append({
                    "memory_id": memory_id,
                    "observed_version": state["version"],
                    "latest_version": (
                        latest["version"] if latest else None
                    ),
                    "change_detected": True,
                    "result": result,
                })
            except Exception as exc:
                print(f"[AegisMem Watcher ERROR] Processing '{memory_id}': {type(exc).__name__}: {exc}")
                results.append({
                    "memory_id": memory_id,
                    "observed_version": state["version"],
                    "error": str(exc),
                })

        return results

    async def run(self):
        if self.event_driven:
            self._event_queue = asyncio.Queue()
            print("[AegisMem Watcher] Event-driven real-time detection active (no polling delay floor).")
            while not self._stop_event.is_set():
                try:
                    item = await asyncio.wait_for(
                        self._event_queue.get(),
                        timeout=self.interval_seconds,
                    )
                    memory_id, version, t_write = item
                    await asyncio.to_thread(self.process_memory, memory_id, t_write)
                    self._event_queue.task_done()
                except asyncio.TimeoutError:
                    # Reconciliation scan on timeout
                    await asyncio.to_thread(self.scan_once)
                except Exception as exc:
                    print(f"[AegisMem Watcher Event Exception] {type(exc).__name__}: {exc}")
        else:
            print(f"[AegisMem Watcher] Background continuous watcher started (interval: {self.interval_seconds}s).")
            while not self._stop_event.is_set():
                try:
                    await asyncio.to_thread(self.scan_once)
                except Exception as exc:
                    print(f"[AegisMem Watcher Exception] {type(exc).__name__}: {exc}")

                try:
                    await asyncio.wait_for(
                        self._stop_event.wait(),
                        timeout=self.interval_seconds,
                    )
                except asyncio.TimeoutError:
                    pass

    def stop(self):
        print("[AegisMem Watcher] Background watcher stopped.")
        self._stop_event.set()


if __name__ == "__main__":
    interval = float(os.getenv("AEGIS_WATCHER_INTERVAL", "2.0"))
    event_driven = os.getenv("AEGIS_WATCHER_EVENT_DRIVEN", "false").lower() in ("true", "1", "yes")
    watcher = AegisMemWatcher(interval_seconds=interval, event_driven=event_driven)
    try:
        asyncio.run(watcher.run())
    except (KeyboardInterrupt, SystemExit):
        watcher.stop()

