import csv
from pathlib import Path
import pytest

from evaluation.load_tester import (
    LoadBenchmarkRunResult,
    SupportAgentLoadTester,
    calculate_percentile,
)


def test_percentile_calculation_accuracy():
    """
    Verifies that the percentile calculation function computes standard percentiles accurately.
    """
    data = list(range(1, 101))  # 1 to 100
    p50 = calculate_percentile(data, 50)
    p95 = calculate_percentile(data, 95)
    p99 = calculate_percentile(data, 99)

    assert abs(p50 - 50.5) < 0.5
    assert abs(p95 - 95.05) < 0.5
    assert abs(p99 - 99.01) < 0.5
    assert calculate_percentile([], 50) == 0.0


def test_concurrent_load_run_zero_safety_regression_under_attack(tmp_path):
    """
    Test 10 concurrent customer sessions with mid-run attack injection.
    Verifies:
    1. Zero wrong answers served during attack.
    2. Base, attack, and recovery percentiles recorded.
    3. Added gate latency measured.
    """
    tester = SupportAgentLoadTester(concurrency_levels=[10], requests_per_worker=10, output_dir=tmp_path)
    res = tester.run_concurrency_level(concurrency=10, tmp_path=tmp_path)

    assert isinstance(res, LoadBenchmarkRunResult)
    assert res.concurrency == 10
    assert res.total_requests == 100
    assert res.exposure_window_wrong_answers == 0  # 0 wrong answers served!
    assert res.throughput_rps > 0.0
    assert res.base_p50_ms > 0.0
    assert res.recovery_duration_ms > 0.0


def test_high_concurrency_load_run(tmp_path):
    """
    Test 50 concurrent customer sessions under load.
    Verifies thread safety and zero safety regression under high concurrency.
    """
    tester = SupportAgentLoadTester(concurrency_levels=[50], requests_per_worker=5, output_dir=tmp_path)
    res = tester.run_concurrency_level(concurrency=50, tmp_path=tmp_path)

    assert res.concurrency == 50
    assert res.total_requests == 250
    assert res.exposure_window_wrong_answers == 0
    assert res.throughput_rps > 10.0


def test_load_tester_artifact_generation(tmp_path):
    """
    Verifies full benchmark artifact export (CSV and Markdown) across concurrency levels.
    """
    out_dir = tmp_path / "load_output"
    tester = SupportAgentLoadTester(concurrency_levels=[5, 10], requests_per_worker=4, output_dir=out_dir)
    report = tester.run_all(tmp_path=tmp_path)

    assert "results" in report
    assert len(report["results"]) == 2

    csv_file = Path(report["csv_path"])
    assert csv_file.exists()
    assert csv_file.stat().st_size > 0

    md_file = Path(report["md_path"])
    assert md_file.exists()
    content = md_file.read_text(encoding="utf-8")
    assert "AegisMem Concurrency & Latency Profile (Experiment 4)" in content
    assert "5 concurrent" in content
    assert "10 concurrent" in content
