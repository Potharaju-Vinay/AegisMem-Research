import csv
import json
import statistics
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional
from uuid import uuid4


class IncidentLifecycleTelemetry:
    """
    High-precision lifecycle timing and telemetry recorder for AegisMem incidents.
    Tracks every phase of the self-healing pipeline:
    T_write -> T_detect -> T_decide -> T_recover -> T_validate.
    Computes statistical percentiles (p50, p95, p99) dynamically without hardcoding.
    """

    def __init__(self, export_path: Optional[Path | str] = None):
        self.export_path = Path(export_path) if export_path else None
        self._incidents: List[Dict[str, Any]] = []
        self._lock = threading.RLock()

    def record_incident(
        self,
        memory_id: str,
        version: int,
        t_write: float,
        t_detect: float,
        t_decide: float,
        t_recover: float,
        t_validate: float,
        detected: bool = True,
        recovered: bool = True,
        action_taken: str = "ROLLBACK",
        incident_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Records high-resolution timestamps (in seconds) and computes phase latencies in milliseconds.
        """
        ttd_ms = max(0.0, (t_detect - t_write) * 1000.0)
        tt_decide_ms = max(0.0, (t_decide - t_detect) * 1000.0)
        ttr_ms = max(0.0, (t_recover - t_detect) * 1000.0)
        tt_validate_ms = max(0.0, (t_validate - t_recover) * 1000.0)
        total_latency_ms = max(0.0, (t_validate - t_write) * 1000.0)

        record = {
            "incident_id": incident_id or f"INC-{uuid4().hex[:8]}",
            "memory_id": memory_id,
            "version": int(version),
            "timestamps": {
                "t_write": float(t_write),
                "t_detect": float(t_detect),
                "t_decide": float(t_decide),
                "t_recover": float(t_recover),
                "t_validate": float(t_validate),
            },
            "latencies_ms": {
                "ttd_ms": round(ttd_ms, 3),
                "tt_decide_ms": round(tt_decide_ms, 3),
                "ttr_ms": round(ttr_ms, 3),
                "tt_validate_ms": round(tt_validate_ms, 3),
                "total_latency_ms": round(total_latency_ms, 3),
            },
            "outcomes": {
                "detected": detected,
                "recovered": recovered,
                "action_taken": action_taken,
            },
        }

        with self._lock:
            self._incidents.append(record)
            if self.export_path:
                self.export_json(self.export_path)

        return record

    def list_incidents(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._incidents)

    def clear(self) -> None:
        with self._lock:
            self._incidents.clear()

    @staticmethod
    def _calc_percentiles(values: List[float]) -> Dict[str, float]:
        if not values:
            return {"p50": 0.0, "p95": 0.0, "p99": 0.0, "mean": 0.0, "min": 0.0, "max": 0.0}

        sorted_vals = sorted(values)
        n = len(sorted_vals)

        def percentile(p: float) -> float:
            k = (n - 1) * (p / 100.0)
            f = int(k)
            c = min(f + 1, n - 1)
            d0 = sorted_vals[f] * (c - k)
            d1 = sorted_vals[c] * (k - f)
            return d0 + d1

        return {
            "p50": round(percentile(50.0), 3),
            "p95": round(percentile(95.0), 3),
            "p99": round(percentile(99.0), 3),
            "mean": round(statistics.mean(sorted_vals), 3),
            "min": round(sorted_vals[0], 3),
            "max": round(sorted_vals[-1], 3),
        }

    def get_metrics_summary(self) -> Dict[str, Any]:
        """
        Computes dynamic statistical distribution metrics across all recorded incidents.
        """
        with self._lock:
            incidents = list(self._incidents)

        sample_count = len(incidents)
        if sample_count == 0:
            return {
                "sample_count": 0,
                "ttd_ms": self._calc_percentiles([]),
                "ttr_ms": self._calc_percentiles([]),
                "total_latency_ms": self._calc_percentiles([]),
            }

        ttd_vals = [inc["latencies_ms"]["ttd_ms"] for inc in incidents]
        ttr_vals = [inc["latencies_ms"]["ttr_ms"] for inc in incidents]
        total_vals = [inc["latencies_ms"]["total_latency_ms"] for inc in incidents]

        return {
            "sample_count": sample_count,
            "ttd_ms": self._calc_percentiles(ttd_vals),
            "ttr_ms": self._calc_percentiles(ttr_vals),
            "total_latency_ms": self._calc_percentiles(total_vals),
        }

    def export_json(self, destination: Path | str) -> Path:
        path = Path(destination)
        path.parent.mkdir(parents=True, exist_ok=True)
        with self._lock:
            data = {
                "summary": self.get_metrics_summary(),
                "incidents": self._incidents,
            }
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        return path

    def export_csv(self, destination: Path | str) -> Path:
        path = Path(destination)
        path.parent.mkdir(parents=True, exist_ok=True)
        with self._lock:
            incidents = list(self._incidents)

        fieldnames = [
            "incident_id",
            "memory_id",
            "version",
            "ttd_ms",
            "tt_decide_ms",
            "ttr_ms",
            "tt_validate_ms",
            "total_latency_ms",
            "detected",
            "recovered",
            "action_taken",
        ]

        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for inc in incidents:
                row = {
                    "incident_id": inc["incident_id"],
                    "memory_id": inc["memory_id"],
                    "version": inc["version"],
                    "ttd_ms": inc["latencies_ms"]["ttd_ms"],
                    "tt_decide_ms": inc["latencies_ms"]["tt_decide_ms"],
                    "ttr_ms": inc["latencies_ms"]["ttr_ms"],
                    "tt_validate_ms": inc["latencies_ms"]["tt_validate_ms"],
                    "total_latency_ms": inc["latencies_ms"]["total_latency_ms"],
                    "detected": inc["outcomes"]["detected"],
                    "recovered": inc["outcomes"]["recovered"],
                    "action_taken": inc["outcomes"]["action_taken"],
                }
                writer.writerow(row)
        return path


_GLOBAL_TELEMETRY: Optional[IncidentLifecycleTelemetry] = None


def get_detection_telemetry(export_path: Optional[Path | str] = None) -> IncidentLifecycleTelemetry:
    global _GLOBAL_TELEMETRY
    if _GLOBAL_TELEMETRY is None:
        default_path = export_path or Path("data/detection_telemetry.json")
        _GLOBAL_TELEMETRY = IncidentLifecycleTelemetry(default_path)
    return _GLOBAL_TELEMETRY
