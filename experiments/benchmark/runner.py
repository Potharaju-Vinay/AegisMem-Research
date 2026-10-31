import csv
import time
from experiments.benchmark.evidence_generator import BenchmarkEvidenceGenerator

from experiments.benchmark.graph_generator import (
    BenchmarkGraphGenerator
)

from experiments.benchmark.attack_generator import (
    BenchmarkAttackGenerator
)

from experiments.benchmark.baselines import (
    FullRollbackBaseline,
    TrustOnlyBaseline,
    DependencyOnlyBaseline,
    DetectionOnlyBaseline,
    AegisMemTCRPBaseline
)

from experiments.benchmark.metrics import (
    calculate_recovery_metrics
)


def run_benchmark(
    scenarios=100,
    node_count=10,
    output_file="results/benchmark_results.csv",
    seed=42
):

    graph_generator = BenchmarkGraphGenerator(seed=seed)
    attack_generator = BenchmarkAttackGenerator(seed=seed)
    evidence_generator = BenchmarkEvidenceGenerator(seed=seed)

    strategies = [
        FullRollbackBaseline(),
        TrustOnlyBaseline(),
        DependencyOnlyBaseline(),
        DetectionOnlyBaseline(),
        AegisMemTCRPBaseline()
    ]

    rows = []

    for scenario_index in range(
        1,
        scenarios + 1
    ):

        graph = graph_generator.generate(
            node_count=node_count
        )

        attack = attack_generator.generate(
            graph=graph,
            attack_index=scenario_index
        )

        detection_results = evidence_generator.generate(
            attack
        )

        all_memory_ids = {
            node.memory_id
            for node in graph.nodes
        }

        for strategy in strategies:

            start_time = time.perf_counter()

            plan = strategy.plan(
                graph,
                attack.root_memory_id,
                detection_results=detection_results
            )

            elapsed = (
                time.perf_counter()
                - start_time
            )

            metrics = calculate_recovery_metrics(
                recovered_memory_ids=(
                    plan.recovered_memory_ids
                ),
                contaminated_memory_ids=(
                    attack.contaminated_memory_ids
                ),
                all_memory_ids=(
                    all_memory_ids
                )
            )

            rows.append({
                "scenario": scenario_index,
                "node_count": node_count,
                "attack_id": attack.attack_id,
                "root_memory": attack.root_memory_id,
                "attack_depth": attack.attack_depth,
                "strategy": strategy.name,
                "true_positive": metrics.true_positive,
                "false_positive": metrics.false_positive,
                "false_negative": metrics.false_negative,
                "true_negative": metrics.true_negative,
                "precision": metrics.precision,
                "recall": metrics.recall,
                "f1_score": metrics.f1_score,
                "unnecessary_recovery": metrics.unnecessary_recovery,
                "residual_contamination": metrics.residual_contamination,
                "unnecessary_recovery_count": metrics.unnecessary_recovery_count,
                "residual_contamination_count": metrics.residual_contamination_count,
                "recovery_cost": metrics.recovery_cost,
                "recovered_count": len(plan.recovered_memory_ids),
                "runtime_seconds": elapsed
            })

    with open(
        output_file,
        "w",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=rows[0].keys()
        )

        writer.writeheader()
        writer.writerows(rows)

    print()
    print("==========================================")
    print("       AEGISMEM BENCHMARK COMPLETE")
    print("==========================================")

    print(
        f"Scenarios : {scenarios}"
    )

    print(
        f"Nodes     : {node_count}"
    )

    print(
        f"Rows      : {len(rows)}"
    )

    print(
        f"Output    : {output_file}"
    )


if __name__ == "__main__":

    run_benchmark()