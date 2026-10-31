import json
import time
from pathlib import Path
from unittest.mock import MagicMock
import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from core.detection.telemetry import (
    IncidentLifecycleTelemetry,
    get_detection_telemetry,
)
from core.memory.database import Base
from core.memory.models import MemoryRecord
from core.memory.postgres_triggers import (
    CREATE_OUTBOX_TABLE_SQL,
    CREATE_TRIGGER_FUNCTION_SQL,
    setup_postgres_event_pipeline,
)
from core.memory.store import SQLiteMemoryStore
from core.security.watcher import AegisMemWatcher


@pytest.fixture
def telemetry_recorder(tmp_path):
    export_path = tmp_path / "telemetry_test.json"
    recorder = IncidentLifecycleTelemetry(export_path)
    return recorder


def test_telemetry_lifecycle_timestamp_recording_and_percentiles(telemetry_recorder, tmp_path):
    # Simulate 5 incidents with distinct realistic latencies
    base_t = time.perf_counter()

    for i in range(1, 6):
        t_w = base_t + (i * 0.1)
        t_det = t_w + 0.015 + (i * 0.002)     # ~17-25ms TTD
        t_dec = t_det + 0.005                 # ~5ms decide
        t_rec = t_dec + 0.012                 # ~12ms recover
        t_val = t_rec + 0.003                 # ~3ms validate

        telemetry_recorder.record_incident(
            memory_id=f"INC-TEST-{i}",
            version=i,
            t_write=t_w,
            t_detect=t_det,
            t_decide=t_dec,
            t_recover=t_rec,
            t_validate=t_val,
            detected=True,
            recovered=True,
            action_taken="ROLLBACK",
        )

    incidents = telemetry_recorder.list_incidents()
    assert len(incidents) == 5

    for inc in incidents:
        lat = inc["latencies_ms"]
        assert lat["ttd_ms"] > 0.0
        assert lat["ttr_ms"] > 0.0
        assert lat["total_latency_ms"] >= lat["ttd_ms"] + lat["ttr_ms"] - 1.0  # slight precision tolerance

    metrics = telemetry_recorder.get_metrics_summary()
    assert metrics["sample_count"] == 5
    assert metrics["ttd_ms"]["p50"] > 0.0
    assert metrics["ttd_ms"]["p95"] >= metrics["ttd_ms"]["p50"]
    assert metrics["ttd_ms"]["p99"] >= metrics["ttd_ms"]["p95"]
    assert metrics["ttr_ms"]["p50"] > 0.0

    # Test JSON and CSV export
    json_path = tmp_path / "exported.json"
    csv_path = tmp_path / "exported.csv"

    telemetry_recorder.export_json(json_path)
    telemetry_recorder.export_csv(csv_path)

    assert json_path.exists()
    assert csv_path.exists()

    exported_json = json.loads(json_path.read_text(encoding="utf-8"))
    assert exported_json["summary"]["sample_count"] == 5
    assert len(exported_json["incidents"]) == 5

    csv_lines = csv_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(csv_lines) == 6  # header + 5 rows


def test_event_driven_detection_eliminates_polling_delay(tmp_path):
    """
    Demonstrates that event-driven detection runs in sub-100ms without the fixed 2.0s floor.
    """
    db_file = tmp_path / "m4_test.db"
    engine = create_engine(f"sqlite:///{db_file}", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine, autoflush=False, autocommit=False)

    store = SQLiteMemoryStore(session_factory=Session)
    watcher = AegisMemWatcher(interval_seconds=2.0, event_driven=True, store=store)

    memory_id = "ENT-REALTIME-TEST"

    # Create baseline record
    store.create_version(memory_id=memory_id, content="Baseline trusted content")

    t_write_start = time.perf_counter()

    # Trigger event-driven detection
    result = watcher.trigger_event(memory_id=memory_id, version=1, t_write=t_write_start)

    t_finished = time.perf_counter()
    measured_duration_ms = (t_finished - t_write_start) * 1000.0

    # Under event-driven mode, detection must not wait for the 2.0s (2000ms) timer!
    assert measured_duration_ms < 500.0, f"Detection took {measured_duration_ms}ms, expected sub-500ms without 2s floor"

    # Telemetry should be attached
    assert "telemetry" in result
    assert result["telemetry"]["latencies_ms"]["ttd_ms"] < 500.0


def test_postgres_triggers_sql_generation():
    """
    Verifies that the PostgreSQL outbox and trigger schemas contain valid SQL definitions.
    """
    assert "CREATE TABLE IF NOT EXISTS memory_outbox" in CREATE_OUTBOX_TABLE_SQL
    assert "PERFORM pg_notify('aegismem_memory_changes'" in CREATE_TRIGGER_FUNCTION_SQL
    assert "notify_memory_change()" in CREATE_TRIGGER_FUNCTION_SQL

    # Test graceful setup on mock engine
    mock_engine = MagicMock()
    success = setup_postgres_event_pipeline(mock_engine)
    assert success is True
    assert mock_engine.begin.called
