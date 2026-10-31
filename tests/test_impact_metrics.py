from attack_lab.metrics import ImpactMetricCalculator
from attack_lab.impact import ImpactedMemory


def test_impact_metrics():

    result = {
        "M001": ImpactedMemory(
            memory_id="M001",
            trust=0.0,
            distance=0,
            parent_memory_id=None,
            impact_score=0.0
        ),
        "M002": ImpactedMemory(
            memory_id="M002",
            trust=0.9,
            distance=1,
            parent_memory_id="M001",
            impact_score=0.1
        ),
        "M003": ImpactedMemory(
            memory_id="M003",
            trust=0.72,
            distance=2,
            parent_memory_id="M002",
            impact_score=0.28
        )
    }

    calculator = ImpactMetricCalculator()

    metrics = calculator.calculate(result)

    assert metrics.total_memories == 3
    assert metrics.affected_memories == 2
    assert metrics.maximum_distance == 2
    assert metrics.average_impact == 0.19
    assert metrics.cumulative_impact == 0.38
