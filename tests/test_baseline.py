from dataclasses import dataclass

from attack_lab.baseline import PropagationBaseline


@dataclass
class MockImpact:
    impact_score: float


def test_propagation_baseline():

    baseline_result = {
        "M001": MockImpact(0.0),
        "M002": MockImpact(0.2),
        "M003": MockImpact(0.4)
    }

    aegismem_result = {
        "M001": MockImpact(0.0),
        "M002": MockImpact(0.1),
        "M003": MockImpact(0.28)
    }

    comparison = PropagationBaseline().compare(
        baseline_result,
        aegismem_result
    )

    assert comparison.baseline_impact == 0.6
    assert comparison.aegismem_impact == 0.38
    assert comparison.improvement == 0.22
