import argparse
import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from evaluation.benchmark_runner import DomainBenchmarkRunner


def main():
    parser = argparse.ArgumentParser(
        description="AegisMem Statistical Evaluation: Baseline Comparison on Enterprise AI Customer Support"
    )
    parser.add_argument(
        "--seeds",
        nargs="+",
        type=int,
        default=[42, 101, 2024, 777, 9999],
        help="Random seed list for benchmark replications (default: 42 101 2024 777 9999)",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="data",
        help="Directory to save CSV and Markdown reports (default: data)",
    )

    args = parser.parse_args()

    print("\n" + "=" * 80)
    print("      AEGISMEM STATISTICAL BENCHMARK: 5 BASELINES & PART B3 ATTACKS")
    print("=" * 80)
    print(f"Seeds: {args.seeds}")
    print(f"Output Directory: {args.output_dir}\n")

    runner = DomainBenchmarkRunner(seeds=args.seeds, output_dir=args.output_dir)
    results = runner.run_benchmark()

    print("\n" + "=" * 80)
    print("                           BENCHMARK SUMMARY")
    print("=" * 80 + "\n")
    print(Path(results["md_path"]).read_text(encoding="utf-8"))
    print("\n" + "=" * 80)
    print(f"Exported CSV: {results['csv_path']}")
    print(f"Exported Markdown: {results['md_path']}")
    print("=" * 80 + "\n")


if __name__ == "__main__":
    main()
