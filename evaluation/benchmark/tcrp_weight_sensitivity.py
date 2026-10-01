import sys
from pathlib import Path
import csv

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from core.recovery.tcrp import TCRPRecoveryPlanner


TRUST_VALUES = [0.1, 0.3, 0.5, 0.7, 0.9]
SUSPICION_VALUES = [0.0, 0.25, 0.5, 0.75, 1.0]
IMPACT_VALUES = [0.1, 0.5, 0.9]
EXPOSURE_VALUES = [0.0, 0.5, 1.0]
COMPROMISE_VALUES = [False, True]
DISTANCES = [0, 1, 3]


CONFIGURATIONS = {
    "baseline": {
        "trust": 0.35,
        "suspicion": 0.30,
        "impact": 0.25,
        "disruption": 0.10
    },
    "trust_heavy": {
        "trust": 0.55,
        "suspicion": 0.20,
        "impact": 0.15,
        "disruption": 0.10
    },
    "suspicion_heavy": {
        "trust": 0.20,
        "suspicion": 0.55,
        "impact": 0.15,
        "disruption": 0.10
    },
    "impact_heavy": {
        "trust": 0.20,
        "suspicion": 0.20,
        "impact": 0.50,
        "disruption": 0.10
    },
    "disruption_heavy": {
        "trust": 0.25,
        "suspicion": 0.25,
        "impact": 0.20,
        "disruption": 0.30
    }
}


def run_configuration(name, weights):

    planner = TCRPRecoveryPlanner(
        trust_weight=weights["trust"],
        suspicion_weight=weights["suspicion"],
        impact_weight=weights["impact"],
        disruption_weight=weights["disruption"]
    )

    counts = {
        "RETAIN": 0,
        "ROLLBACK": 0,
        "QUARANTINE": 0
    }

    unsafe_retention = 0
    total_compromised = 0
    feasibility_violations = 0
    total = 0

    for trust in TRUST_VALUES:
        for suspicion in SUSPICION_VALUES:
            for impact in IMPACT_VALUES:
                for exposure in EXPOSURE_VALUES:
                    for compromised in COMPROMISE_VALUES:
                        for distance in DISTANCES:

                            total += 1

                            if compromised:
                                total_compromised += 1

                            decision = planner.decide(
                                memory_id="SENSITIVITY-001",
                                trust_score=trust,
                                impact_score=impact,
                                distance=distance,
                                local_status="active",
                                local_suspicion=suspicion,
                                dependency_exposure=exposure,
                                detected_compromise=compromised
                            )

                            action = decision.action.value

                            if action in counts:
                                counts[action] += 1

                            if compromised and action == "RETAIN":
                                unsafe_retention += 1

                            if (
                                action not in decision.feasible_actions
                            ):
                                feasibility_violations += 1

    return {
        "configuration": name,
        "trust_weight": weights["trust"],
        "suspicion_weight": weights["suspicion"],
        "impact_weight": weights["impact"],
        "disruption_weight": weights["disruption"],
        "total_scenarios": total,
        "retain": counts["RETAIN"],
        "rollback": counts["ROLLBACK"],
        "quarantine": counts["QUARANTINE"],
        "retain_pct": counts["RETAIN"] / total * 100,
        "rollback_pct": counts["ROLLBACK"] / total * 100,
        "quarantine_pct": counts["QUARANTINE"] / total * 100,
        "unsafe_retention": unsafe_retention,
        "compromised_scenarios": total_compromised,
        "unsafe_retention_pct": (
            unsafe_retention / total_compromised * 100
            if total_compromised
            else 0
        ),
        "feasibility_violations": feasibility_violations
    }


def main():

    print("=" * 70)
    print("TCRP WEIGHT SENSITIVITY")
    print("=" * 70)

    results = []

    for name, weights in CONFIGURATIONS.items():

        result = run_configuration(
            name,
            weights
        )

        results.append(result)

        print("\n" + "-" * 70)
        print(f"Configuration: {name}")
        print(
            "Weights: "
            f"trust={weights['trust']}, "
            f"suspicion={weights['suspicion']}, "
            f"impact={weights['impact']}, "
            f"disruption={weights['disruption']}"
        )

        print(
            f"RETAIN: {result['retain']} "
            f"({result['retain_pct']:.2f}%)"
        )

        print(
            f"ROLLBACK: {result['rollback']} "
            f"({result['rollback_pct']:.2f}%)"
        )

        print(
            f"QUARANTINE: {result['quarantine']} "
            f"({result['quarantine_pct']:.2f}%)"
        )

        print(
            f"Unsafe retention: "
            f"{result['unsafe_retention']}/"
            f"{result['compromised_scenarios']}"
        )

        print(
            f"Feasibility violations: "
            f"{result['feasibility_violations']}"
        )

    output_path = (
        Path(__file__).resolve().parent
        / "tcrp_weight_sensitivity_results.csv"
    )

    fieldnames = list(results[0].keys())

    with open(
        output_path,
        "w",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames
        )

        writer.writeheader()
        writer.writerows(results)

    print("\n" + "=" * 70)
    print("RESULTS SAVED")
    print("=" * 70)
    print(output_path)


if __name__ == "__main__":
    main()