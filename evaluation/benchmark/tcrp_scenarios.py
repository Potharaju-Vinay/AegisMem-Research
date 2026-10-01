import sys
from pathlib import Path

sys.path.insert(
    0,
    str(Path(__file__).resolve().parents[2])
)

from core.recovery.tcrp import TCRPRecoveryPlanner


def run():
    planner = TCRPRecoveryPlanner()

    scenarios = [
        {
            "name": "trusted_memory",
            "trust_score": 1.0,
            "impact_score": 0.0,
            "distance": 0,
            "local_status": "active",
            "local_suspicion": 0.0,
            "dependency_exposure": 0.0,
            "detected_compromise": False,
        },
        {
            "name": "mild_suspicion",
            "trust_score": 0.8,
            "impact_score": 0.1,
            "distance": 0,
            "local_status": "active",
            "local_suspicion": 0.25,
            "dependency_exposure": 0.1,
            "detected_compromise": False,
        },
        {
            "name": "high_suspicion",
            "trust_score": 0.6,
            "impact_score": 0.3,
            "distance": 0,
            "local_status": "active",
            "local_suspicion": 0.75,
            "dependency_exposure": 0.2,
            "detected_compromise": False,
        },
        {
            "name": "direct_compromise",
            "trust_score": 0.0,
            "impact_score": 1.0,
            "distance": 0,
            "local_status": "active",
            "local_suspicion": 0.7,
            "dependency_exposure": 0.0,
            "detected_compromise": True,
        },
        {
            "name": "high_dependency_exposure",
            "trust_score": 0.7,
            "impact_score": 0.5,
            "distance": 2,
            "local_status": "active",
            "local_suspicion": 0.6,
            "dependency_exposure": 0.9,
            "detected_compromise": True,
        },
        {
            "name": "corrupted_memory",
            "trust_score": 0.2,
            "impact_score": 0.8,
            "distance": 1,
            "local_status": "CORRUPTED",
            "local_suspicion": 0.8,
            "dependency_exposure": 0.5,
            "detected_compromise": True,
        },
        {
            "name": "low_trust_with_history",
            "trust_score": 0.2,
            "impact_score": 0.6,
            "distance": 0,
            "local_status": "active",
            "local_suspicion": 0.7,
            "dependency_exposure": 0.2,
            "detected_compromise": True,
        },
        {
            "name": "no_trusted_history",
            "trust_score": 0.0,
            "impact_score": 0.9,
            "distance": 0,
            "local_status": "DELETED",
            "local_suspicion": 1.0,
            "dependency_exposure": 0.8,
            "detected_compromise": True,
        },
    ]

    print("=" * 70)
    print("TCRP CONTROLLED SCENARIO BENCHMARK")
    print("=" * 70)

    for scenario in scenarios:
        name = scenario.pop("name")

        decision = planner.decide(
            memory_id=name,
            **scenario
        )

        print("\n" + "-" * 70)
        print(f"Scenario: {name}")
        print(f"Selected action: {decision.action.value}")
        print(f"Trust: {decision.trust_score:.2f}")
        print(f"Suspicion: {decision.local_suspicion:.2f}")
        print(f"Impact: {decision.impact_score:.2f}")
        print(
            f"Dependency exposure: "
            f"{decision.dependency_exposure:.2f}"
        )
        print(f"Feasible: {decision.feasible_actions}")
        print(f"Costs: {decision.candidate_costs}")
        print(f"Selected cost: {decision.action_cost:.4f}")


if __name__ == "__main__":
    run()