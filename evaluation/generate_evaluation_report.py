import csv
from pathlib import Path
from statistics import mean, median


ROOT = Path(__file__).resolve().parent
BENCHMARK = ROOT / "benchmark"


LIVE_RESULTS = [
    {
        "attack_type": "content_tampering",
        "attack_id": "ATK-482077736DA4",
        "baseline_version": 113,
        "compromised_version": 114,
        "restored_version": 115,
        "action": "ROLLBACK",
        "validation": "PASS",
        "latency": 1.8243,
        "content_restored": True,
        "success": True,
    },
    {
        "attack_type": "memory_poisoning",
        "attack_id": "ATTACK-118",
        "baseline_version": 115,
        "compromised_version": 116,
        "restored_version": 117,
        "action": "ROLLBACK",
        "validation": "PASS",
        "latency": 1.9295,
        "content_restored": True,
        "success": True,
    },
    {
        "attack_type": "memory_deletion",
        "attack_id": "DEL-B7A4BA06A848",
        "baseline_version": 117,
        "compromised_version": 118,
        "restored_version": 119,
        "action": "ROLLBACK",
        "validation": "PASS",
        "latency": 1.7620,
        "content_restored": True,
        "success": True,
    },
]


def read_csv(path):
    with path.open(
        newline="",
        encoding="utf-8"
    ) as file:
        return list(csv.DictReader(file))


def main():

    parameter_file = (
        BENCHMARK
        / "tcrp_parameter_results.csv"
    )

    ablation_file = (
        BENCHMARK
        / "tcrp_large_ablation_results.csv"
    )

    parameter_rows = read_csv(
        parameter_file
    )

    ablation_rows = read_csv(
        ablation_file
    )

    print("=" * 70)
    print("AEGISMEM EVALUATION REPORT")
    print("=" * 70)

    print("\nLIVE ATTACK EVALUATION")
    print("-" * 70)

    live_latencies = [
        item["latency"]
        for item in LIVE_RESULTS
    ]

    live_successes = sum(
        item["success"]
        for item in LIVE_RESULTS
    )

    print(
        f"Trials: {len(LIVE_RESULTS)}"
    )

    print(
        f"Successful recoveries: "
        f"{live_successes}/{len(LIVE_RESULTS)}"
    )

    print(
        f"Success rate: "
        f"{live_successes / len(LIVE_RESULTS):.2%}"
    )

    print(
        f"Mean latency: "
        f"{mean(live_latencies):.4f}s"
    )

    print(
        f"Median latency: "
        f"{median(live_latencies):.4f}s"
    )

    print(
        f"Minimum latency: "
        f"{min(live_latencies):.4f}s"
    )

    print(
        f"Maximum latency: "
        f"{max(live_latencies):.4f}s"
    )

    print("\nPer-attack results:")

    for item in LIVE_RESULTS:
        print(
            f"{item['attack_type']:<25}"
            f" {item['action']:<10}"
            f" {item['latency']:.4f}s"
            f" validation={item['validation']}"
            f" restored={item['content_restored']}"
        )

    print("\nPARAMETER SWEEP")
    print("-" * 70)

    total_parameter = len(
        parameter_rows
    )

    feasibility = sum(
        row["selected_is_feasible"] == "True"
        for row in parameter_rows
    )

    unsafe_retention = sum(
        row["unsafe_retain"] == "True"
        for row in parameter_rows
    )

    print(
        f"Scenarios: {total_parameter}"
    )

    print(
        f"Feasibility compliance: "
        f"{feasibility / total_parameter:.2%}"
    )

    print(
        f"Unsafe retention: "
        f"{unsafe_retention / total_parameter:.2%}"
    )

    print("\nABLATION")
    print("-" * 70)

    total_ablation = len(
        ablation_rows
    )

    compromised = [
        row
        for row in ablation_rows
        if row["compromised"] == "True"
    ]

    policies = [
        "retain_only",
        "rule_based",
        "tcrp"
    ]

    for policy in policies:

        unsafe = sum(
            row[policy] == "RETAIN"
            for row in compromised
        )

        print(
            f"{policy:<15}"
            f" unsafe retention="
            f"{unsafe}/{len(compromised)}"
            f" ({unsafe / len(compromised):.2%})"
        )

    tcrp_feasibility = sum(
        row["tcrp"]
        in row["tcrp_feasible_actions"].split("|")
        for row in ablation_rows
    )

    print(
        f"\nTCRP feasibility compliance: "
        f"{tcrp_feasibility / total_ablation:.2%}"
    )

    print("\nTCRP ACTION DISTRIBUTION")
    print("-" * 70)

    actions = {}

    for row in ablation_rows:
        action = row["tcrp"]
        actions[action] = (
            actions.get(action, 0) + 1
        )

    for action, count in actions.items():
        print(
            f"{action:<15}"
            f"{count:>6}"
            f" ({count / total_ablation:.2%})"
        )

    print("\n" + "=" * 70)
    print("REPORT COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()