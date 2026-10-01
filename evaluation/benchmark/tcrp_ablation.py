import sys
from pathlib import Path
import csv
import itertools
from collections import Counter

sys.path.insert(
    0,
    str(Path(__file__).resolve().parents[2])
)

from core.recovery.tcrp import TCRPRecoveryPlanner


def retain_only(scenario):
    return "RETAIN"


def rule_based(scenario):
    if scenario["detected_compromise"]:
        return "ROLLBACK"

    return "RETAIN"


def tcrp(scenario, planner):
    decision = planner.decide(
        memory_id=scenario["memory_id"],
        trust_score=scenario["trust_score"],
        impact_score=scenario["impact_score"],
        distance=scenario["distance"],
        local_status=scenario["local_status"],
        local_suspicion=scenario["local_suspicion"],
        dependency_exposure=scenario["dependency_exposure"],
        detected_compromise=scenario["detected_compromise"]
    )

    return decision


def main():
    planner = TCRPRecoveryPlanner()

    trusts = [
        0.0,
        0.25,
        0.5,
        0.75,
        1.0
    ]

    suspicions = [
        0.0,
        0.25,
        0.5,
        0.75,
        1.0
    ]

    impacts = [
        0.0,
        0.5,
        1.0
    ]

    dependency_exposures = [
        0.0,
        0.5,
        1.0
    ]

    compromise_states = [
        False,
        True
    ]

    distances = [
        0,
        1,
        2
    ]

    rows = []

    scenario_id = 0

    for (
        trust,
        suspicion,
        impact,
        exposure,
        compromised,
        distance
    ) in itertools.product(
        trusts,
        suspicions,
        impacts,
        dependency_exposures,
        compromise_states,
        distances
    ):

        scenario_id += 1

        status = (
            "CORRUPTED"
            if compromised and trust <= 0.25
            else "active"
        )

        scenario = {
            "memory_id": f"ABL-{scenario_id:05d}",
            "trust_score": trust,
            "impact_score": impact,
            "distance": distance,
            "local_status": status,
            "local_suspicion": suspicion,
            "dependency_exposure": exposure,
            "detected_compromise": compromised
        }

        decision = tcrp(
            scenario,
            planner
        )

        tcrp_action = decision.action.value

        rows.append({
            "scenario_id": scenario_id,
            "trust": trust,
            "suspicion": suspicion,
            "impact": impact,
            "dependency_exposure": exposure,
            "distance": distance,
            "compromised": compromised,
            "status": status,
            "retain_only": retain_only(scenario),
            "rule_based": rule_based(scenario),
            "tcrp": tcrp_action,
            "tcrp_feasible_actions": "|".join(
                decision.feasible_actions or []
            ),
            "tcrp_selected_cost": decision.action_cost,
            "tcrp_min_feasible_cost": min(
                decision.candidate_costs[action]
                for action in decision.feasible_actions
            ),
        })

    output = (
        Path(__file__).resolve().parent
        / "tcrp_large_ablation_results.csv"
    )

    with output.open(
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

    total = len(rows)

    compromised_rows = [
        row
        for row in rows
        if row["compromised"]
    ]

    non_compromised_rows = [
        row
        for row in rows
        if not row["compromised"]
    ]

    print("=" * 70)
    print("LARGE-SCALE TCRP ABLATION")
    print("=" * 70)

    print(f"Total scenarios: {total}")
    print(
        f"Compromised scenarios: "
        f"{len(compromised_rows)}"
    )
    print(
        f"Non-compromised scenarios: "
        f"{len(non_compromised_rows)}"
    )

    print("\n" + "-" * 70)

    policies = [
        "retain_only",
        "rule_based",
        "tcrp"
    ]

    for policy in policies:

        unsafe_retention = sum(
            row[policy] == "RETAIN"
            for row in compromised_rows
        )

        rollback = sum(
            row[policy] == "ROLLBACK"
            for row in rows
        )

        quarantine = sum(
            row[policy] == "QUARANTINE"
            for row in rows
        )

        retain = sum(
            row[policy] == "RETAIN"
            for row in rows
        )

        print(f"\nPolicy: {policy}")

        print(
            f"Unsafe retention: "
            f"{unsafe_retention}/"
            f"{len(compromised_rows)} "
            f"("
            f"{unsafe_retention / len(compromised_rows):.2%}"
            f")"
        )

        print(
            f"RETAIN: {retain} "
            f"({retain / total:.2%})"
        )

        print(
            f"ROLLBACK: {rollback} "
            f"({rollback / total:.2%})"
        )

        print(
            f"QUARANTINE: {quarantine} "
            f"({quarantine / total:.2%})"
        )

    tcrp_infeasible = sum(
        row["tcrp"]
        not in row["tcrp_feasible_actions"].split("|")
        for row in rows
    )

    print("\n" + "-" * 70)

    print(
        "TCRP feasibility violations: "
        f"{tcrp_infeasible}/{total}"
    )

    regrets = [
        float(row["tcrp_selected_cost"])
        - float(row["tcrp_min_feasible_cost"])
        for row in rows
    ]

    print(
        "TCRP mean cost regret: "
        f"{sum(regrets) / len(regrets):.8f}"
    )

    print(
        "TCRP maximum cost regret: "
        f"{max(regrets):.8f}"
    )

    print("\nTCRP action distribution:")

    distribution = Counter(
        row["tcrp"]
        for row in rows
    )

    for action, count in distribution.items():
        print(
            f"{action:<12}"
            f"{count:>6}"
            f" ({count / total:.2%})"
        )

    print("\n" + "=" * 70)

    print(
        f"Results saved to:\n{output}"
    )


if __name__ == "__main__":
    main()