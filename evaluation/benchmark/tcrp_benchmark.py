import sys
from pathlib import Path

sys.path.insert(
    0,
    str(Path(__file__).resolve().parents[2])
)

from core.recovery.tcrp import TCRPRecoveryPlanner


def run_case(name, **kwargs):
    planner = TCRPRecoveryPlanner()

    decision = planner.decide(
        memory_id=name,
        **kwargs
    )

    return {
        "scenario": name,
        "action": decision.action.value,
        "trust": decision.trust_score,
        "suspicion": decision.local_suspicion,
        "impact": decision.impact_score,
        "dependency_exposure": decision.dependency_exposure,
        "selected_cost": decision.action_cost,
        "feasible_actions": decision.feasible_actions,
        "candidate_costs": decision.candidate_costs,
    }


def main():
    cases = [
        (
            "clean_memory",
            dict(
                trust_score=1.0,
                impact_score=0.0,
                distance=0,
                local_status="active",
                local_suspicion=0.0,
                dependency_exposure=0.0,
                detected_compromise=False,
            )
        ),
        (
            "direct_compromise",
            dict(
                trust_score=0.0,
                impact_score=1.0,
                distance=0,
                local_status="active",
                local_suspicion=0.7,
                dependency_exposure=0.0,
                detected_compromise=True,
            )
        ),
        (
            "high_dependency_exposure",
            dict(
                trust_score=0.72,
                impact_score=0.28,
                distance=2,
                local_status="active",
                local_suspicion=0.72,
                dependency_exposure=0.72,
                detected_compromise=True,
            )
        ),
        (
            "corrupted_memory",
            dict(
                trust_score=0.2,
                impact_score=0.8,
                distance=1,
                local_status="CORRUPTED",
                local_suspicion=0.8,
                dependency_exposure=0.5,
                detected_compromise=True,
            )
        ),
        (
            "high_suspicion",
            dict(
                trust_score=0.4,
                impact_score=0.5,
                distance=1,
                local_status="active",
                local_suspicion=0.8,
                dependency_exposure=0.3,
                detected_compromise=True,
            )
        ),
    ]

    results = []

    for name, parameters in cases:
        results.append(
            run_case(
                name,
                **parameters
            )
        )

    for result in results:
        print("=" * 60)
        print(f"Scenario: {result['scenario']}")
        print(f"Action: {result['action']}")
        print(f"Trust: {result['trust']:.2f}")
        print(f"Suspicion: {result['suspicion']:.2f}")
        print(f"Impact: {result['impact']:.2f}")
        print(
            f"Dependency exposure: "
            f"{result['dependency_exposure']:.2f}"
        )
        print(
            f"Selected cost: "
            f"{result['selected_cost']:.4f}"
        )
        print(
            f"Feasible actions: "
            f"{result['feasible_actions']}"
        )
        print(
            f"Candidate costs: "
            f"{result['candidate_costs']}"
        )


if __name__ == "__main__":
    main()