from dataclasses import dataclass

from core.revision.planner import DependencyAwareRevisionPlanner


@dataclass
class MockImpact:
    memory_id: str
    trust: float
    impact_score: float
    distance: int
    parent_memory_id: str | None


def test_temporal_provenance_revision_planner():

    impact_result = {
        "M001": MockImpact(
            memory_id="M001",
            trust=0.0,
            impact_score=0.0,
            distance=0,
            parent_memory_id=None
        ),
        "M002": MockImpact(
            memory_id="M002",
            trust=0.9,
            impact_score=0.1,
            distance=1,
            parent_memory_id="M001"
        ),
        "M003": MockImpact(
            memory_id="M003",
            trust=0.72,
            impact_score=0.28,
            distance=2,
            parent_memory_id="M002"
        )
    }

    planner = DependencyAwareRevisionPlanner()

    candidates = planner.rank(
        impact_result,
        provenance_weights={
            "M002": 0.8,
            "M003": 1.0
        },
        temporal_weights={
            "M002": 0.9,
            "M003": 1.0
        }
    )

    assert len(candidates) == 2

    assert candidates[0].memory_id == "M003"
    assert candidates[1].memory_id == "M002"

    assert candidates[0].provenance_weight == 1.0
    assert candidates[1].provenance_weight == 0.8

    assert candidates[0].temporal_weight == 1.0
    assert candidates[1].temporal_weight == 0.9

    assert candidates[0].priority_score == 0.14
    assert candidates[1].priority_score == 0.072

    assert candidates[0].requires_revision is True
    assert candidates[1].requires_revision is True
