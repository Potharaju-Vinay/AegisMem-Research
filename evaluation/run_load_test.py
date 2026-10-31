import argparse
import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from evaluation.load_tester import SupportAgentLoadTester


def main():
    parser = argparse.ArgumentParser(
        description="AegisMem Concurrent Load & Latency Benchmark (10, 50, 100 sessions with mid-run attack)"
    )
    parser.add_argument(
        "--concurrency",
        nargs="+",
        type=int,
        default=[10, 50, 100],
        help="Concurrent customer session levels to test (default: 10 50 100)",
    )
    parser.add_argument(
        "--requests-per-worker",
        type=int,
        default=20,
        help="Requests executed per worker session (default: 20)",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="data",
        help="Directory to save CSV and Markdown reports (default: data)",
    )

    args = parser.parse_args()

    print("\n" + "=" * 80)
    print("      AEGISMEM CONCURRENT LOAD & LATENCY BENCHMARK (EXPERIMENT 4)")
    print("=" * 80)
    print(f"Concurrency Levels: {args.concurrency}")
    print(f"Requests per worker: {args.requests_per_worker}")
    print(f"Output Directory: {args.output_dir}\n")

    tester = SupportAgentLoadTester(
        concurrency_levels=args.concurrency,
        requests_per_worker=args.requests_per_worker,
        output_dir=args.output_dir,
    )
    results = tester.run_all()

    print("\n" + "=" * 80)
    print("                           LOAD TEST SUMMARY")
    print("=" * 80 + "\n")
    print(Path(results["md_path"]).read_text(encoding="utf-8"))
    print("\n" + "=" * 80)
    print(f"Exported CSV: {results['csv_path']}")
    print(f"Exported Markdown: {results['md_path']}")
    print("=" * 80 + "\n")


if __name__ == "__main__":
    main()
