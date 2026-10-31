import pandas as pd

from experiments.benchmark.runner import run_benchmark


def run_multi_seed_benchmark(
    seeds=(42, 43, 44, 45, 46),
    node_counts=(10, 25, 50, 100),
    scenarios=100
):
    all_results = []

    for seed in seeds:

        for node_count in node_counts:

            output_file = (
                f"results/"
                f"benchmark_seed{seed}_nodes{node_count}.csv"
            )

            print()
            print("=" * 60)
            print(
                f"Running seed={seed}, "
                f"nodes={node_count}"
            )
            print("=" * 60)

            run_benchmark(
                scenarios=scenarios,
                node_count=node_count,
                output_file=output_file,
                seed=seed
            )

            df = pd.read_csv(output_file)

            df["seed"] = seed
            df["node_count"] = node_count

            all_results.append(df)

    combined = pd.concat(
        all_results,
        ignore_index=True
    )

    combined.to_csv(
        "results/multi_seed_benchmark.csv",
        index=False
    )

    print()
    print("=" * 60)
    print("MULTI-SEED BENCHMARK COMPLETE")
    print("=" * 60)

    print(
        f"Seeds       : {len(seeds)}"
    )

    print(
        f"Node counts : {len(node_counts)}"
    )

    print(
        f"Scenarios/configuration : {scenarios}"
    )

    print(
        f"Total rows  : {len(combined)}"
    )

    print(
        "Output      : "
        "results/multi_seed_benchmark.csv"
    )

    return combined


if __name__ == "__main__":
    run_multi_seed_benchmark()