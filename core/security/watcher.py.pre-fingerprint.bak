import asyncio

from sqlalchemy import select

from core.memory.database import get_session
from core.memory.models import MemoryRecord
from core.security.monitor import AegisMemSecurityMonitor


class AegisMemWatcher:

    def __init__(
        self,
        interval_seconds: float = 2.0
    ):
        self.interval_seconds = interval_seconds
        self._stop_event = asyncio.Event()
        self._last_seen_versions = {}

    def get_memory_ids(self):
        session = get_session()

        try:
            memory_ids = session.execute(
                select(MemoryRecord.memory_id).distinct()
            ).scalars().all()

            return list(memory_ids)

        finally:
            session.close()

    def get_latest_version(self, memory_id):
        session = get_session()

        try:
            memory = (
                session.query(MemoryRecord)
                .filter(
                    MemoryRecord.memory_id == memory_id
                )
                .order_by(
                    MemoryRecord.version.desc()
                )
                .first()
            )

            if memory is None:
                return None

            return memory.version

        finally:
            session.close()

    def process_memory(self, memory_id):
        session = get_session()

        try:
            monitor = AegisMemSecurityMonitor(
                session
            )

            result = monitor.process(
                memory_id
            )

            return result

        except Exception:
            session.rollback()
            raise

        finally:
            session.close()

    def scan_once(self):
        memory_ids = self.get_memory_ids()

        results = []

        for memory_id in memory_ids:

            current_version = self.get_latest_version(
                memory_id
            )

            if current_version is None:
                continue

            previous_version = self._last_seen_versions.get(
                memory_id
            )

            if previous_version is None:

                self._last_seen_versions[memory_id] = (
                    current_version
                )

                continue

            if previous_version == current_version:
                continue

            try:

                result = self.process_memory(
                    memory_id
                )

                latest_version = self.get_latest_version(
                    memory_id
                )

                self._last_seen_versions[memory_id] = (
                    latest_version
                    if latest_version is not None
                    else current_version
                )

                results.append({
                    "memory_id": memory_id,
                    "observed_version": current_version,
                    "latest_version": latest_version,
                    "result": result
                })

            except Exception as exc:

                self._last_seen_versions[memory_id] = (
                    current_version
                )

                results.append({
                    "memory_id": memory_id,
                    "observed_version": current_version,
                    "error": str(exc)
                })

        return results

    async def run(self):

        while not self._stop_event.is_set():

            try:

                await asyncio.to_thread(
                    self.scan_once
                )

            except Exception:
                pass

            try:

                await asyncio.wait_for(
                    self._stop_event.wait(),
                    timeout=self.interval_seconds
                )

            except asyncio.TimeoutError:
                pass

    def stop(self):
        self._stop_event.set()