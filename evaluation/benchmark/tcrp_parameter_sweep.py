import sys
from pathlib import Path
import itertools
import csv

sys.path.insert(
    0,
    str(Path(__file__).resolve().parents[2])
)

from core.recovery.tcrp import TCRPRecoveryPlanner


def main():
    planner = TCRPRecoveryPlanner()

    trusts = [0.0, 0.25, 0.5, 0.75, 1.0]
    suspicions = [0.0, 0.25, 0.5, 0.75, 1.0]
    impacts = [0.0, 0.5, 1.0]
    exposures = [0.0, 0.5, 1.0]
    compromise_states = [False, True]

    rows = []

    scenario_id = 0

    for trust, suspicion, impact, exposure, compromised in itertools.product(
        trusts,
        suspicions,
        impacts,
        exposures,
        compromise_states
    ):
        scenario_id += 1

        decision = planner.decide(
            memory_id=f"BENCH-{scenario_id:04d}",
            trust_score=trust,
            impact_score=impact,
            distance=0,
            local_status="active",
            local_suspicion=suspicion,
            dependency_exposure=exposure,
            detected_compromise=compromised
        )

        feasible = decision.feasible_actions or []

        selected_is_feasible = (
            decision.action.value in feasible
        )

        unsafe_retain = (
            compromised
            and decision.action.value == "RETAIN"
        )

        feasible_costs = {
            action: decision.candidate_costs[action]
            for action in feasible
        }

        minimum_feasible_cost = (
            min(feasible_costs.values())
            if feasible_costs
            else None
        )

        cost_regret = (
            decision.action_cost - minimum_feasible_cost
            if minimum_feasible_cost is not None
            else None
        )

        rows.append({
            "scenario_id": scenario_id,
            "trust": trust,
            "suspicion": suspicion,
            "impact": impact,
            "dependency_exposure": exposure,
            "detected_compromise": compromised,
            "selected_action": decision.action.value,
            "feasible_actions": "|".join(feasible),
            "selected_cost": decision.action_cost,
            "minimum_feasible_cost": minimum_feasible_cost,
            "cost_regret": cost_regret,
            "selected_is_feasible": selected_is_feasible,
            "unsafe_retain": unsafe_retain
        })

    output = Path(__file__).resolve().parent / "tcrp_parameter_results.csv"

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

    feasibility_compliance = sum(
        row["selected_is_feasible"]
        for row in rows
    ) / total

    unsafe_retain_rate = sum(
        row["unsafe_retain"]
        for row in rows
    ) / sum(
        row["detected_compromise"]
        for row in rows
    )

    print(f"Total scenarios: {total}")
    print(
        f"Feasibility compliance: "
        f"{feasibility_compliance:.4f}"
    )
    print(
        f"Unsafe retention rate: "
        f"{unsafe_retain_rate:.4f}"
    )
    print(f"Results: {output}")


if __name__ == "__main__":
    main()