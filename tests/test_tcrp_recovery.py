from core.recovery.models import RecoveryAction
from core.recovery.tcrp import TCRPRecoveryPlanner


class MockImpact:
    def __init__(self, trust, impact_score, distance):
        self.trust = trust
        self.impact_score = impact_score
        self.distance = distance


def test_tcrp_recovery_plan():

    planner = TCRPRecoveryPlanner()

    impacted = {
        "M001": MockImpact(
            trust=0.0,
            impact_score=1.0,
            distance=0
        ),
        "M002": MockImpact(
            trust=0.2,
            impact_score=0.8,
            distance=1
        ),
        "M003": MockImpact(
            trust=0.72,
            impact_score=0.28,
            distance=2
        )
    }

    decisions = planner.plan(impacted)

    decision_map = {
        decision.memory_id: decision
        for decision in decisions
    }

    assert (
        decision_map["M001"].action
        == RecoveryAction.QUARANTINE
    )

    assert (
        decision_map["M002"].action
        == RecoveryAction.QUARANTINE
    )

    assert (
        decision_map["M003"].action
        == RecoveryAction.RETAIN
    )


def test_tcrp_detected_compromise_without_resolver_quarantines():
    planner = TCRPRecoveryPlanner()

    impacted = {
        "M001": MockImpact(
            trust=0.8,
            impact_score=0.2,
            distance=0
        )
    }

    detection_results = {
        "M001": type(
            "Detection",
            (),
            {
                "compromised": True,
                "suspicion_score": 1.0
            }
        )()
    }

    decisions = planner.plan(
        impacted_memories=impacted,
        detection_results=detection_results
    )

    assert decisions[0].action == RecoveryAction.QUARANTINE
    assert RecoveryAction.ROLLBACK.value not in decisions[0].feasible_actions

def test_tcrp_clean_memory_is_retained():

    planner = TCRPRecoveryPlanner()

    impacted = {
        "M001": MockImpact(
            trust=0.9,
            impact_score=0.1,
            distance=2
        )
    }

    detection_results = {
        "M001": type(
            "Detection",
            (),
            {
                "compromised": False,
                "suspicion_score": 0.0
            }
        )()
    }

    decisions = planner.plan(
        impacted_memories=impacted,
        detection_results=detection_results
    )

    assert (
        decisions[0].action
        == RecoveryAction.RETAIN
    )

def test_tcrp_quarantines_compromised_memory_without_trusted_history():
    planner = TCRPRecoveryPlanner()

    impacted = {
        "M-NO-TRUSTED-POINT": MockImpact(
            trust=0.0,
            impact_score=1.0,
            distance=0,
        )
    }

    detection_results = {
        "M-NO-TRUSTED-POINT": type(
            "Detection",
            (),
            {
                "compromised": True,
                "suspicion_score": 1.0,
            },
        )()
    }

    
    class EmptyHistoryRepository:
        def get_latest(self, memory_id):
            return type(
                "Memory",
                (),
                {
                    "status": "CORRUPTED",
                    "suspicion_score": 1.0,
                },
            )()

        def get_history(self, memory_id):
            return []


    decisions = planner.plan(
        impacted_memories=impacted,
        repository=EmptyHistoryRepository(),
        detection_results=detection_results,
    )

    assert decisions[0].action == RecoveryAction.QUARANTINE
    assert "QUARANTINE" in decisions[0].feasible_actions
    assert "ROLLBACK" not in decisions[0].feasible_actions
