import asyncio

from sqlalchemy import select

from core.memory.database import get_session
from core.memory.models import MemoryRecord
from core.security.monitor import AegisMemSecurityMonitor


class AegisMemWatcher:
    def __init__(self, interval_seconds: float = 2.0):
        self.interval_seconds = interval_seconds
        self._stop_event = asyncio.Event()
        self._last_seen_versions = {}
        self._last_seen_fingerprints = {}

    def get_memory_ids(self):
        session = get_session()
        try:
            return session.execute(
                select(MemoryRecord.memory_id).distinct()
            ).scalars().all()
        finally:
            session.close()

    def get_latest_record_state(self, memory_id):
        session = get_session()
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

    def process_memory(self, memory_id):
        session = get_session()
        try:
            monitor = AegisMemSecurityMonitor(session)
            return monitor.process(memory_id)
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def scan_once(self):
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
        print("[AegisMem Watcher] Background continuous watcher started (interval: 2.0s).")
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
        print("[AegisMem Watcher] Background continuous watcher stopped.")
        self._stop_event.set()
