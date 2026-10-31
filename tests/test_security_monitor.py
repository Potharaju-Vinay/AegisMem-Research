
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from core.security.monitor import AegisMemSecurityMonitor
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from core.memory.database import Base
from core.graph.dependency.repository import DependencyRepository


def test_monitor_returns_no_compromise_when_detection_is_clean():
    session = MagicMock()

    with patch(
        "core.security.monitor.MemoryCompromiseDetector"
    ) as detector_class:
        detector_class.return_value.detect.return_value = SimpleNamespace(
            compromised=False
        )

        monitor = AegisMemSecurityMonitor(session)
        monitor.build_graph = MagicMock()
        result = monitor.process("TEST-MEMORY-001")

    assert result["detected"] is False
    assert result["recovered"] is False
    assert result["message"] == "No compromise detected."


def test_monitor_returns_successful_recovery_details():
    session = MagicMock()

    detection = SimpleNamespace(
        compromised=True,
        suspicion_score=0.95,
        reason="Content integrity check failed",
        attribution="controlled_test",
        attribution_evidence={"source": "test"},
        evidence=SimpleNamespace(
            integrity_anchor_status="INVALID"
        ),
    )

    current = SimpleNamespace(
        version=3,
        content="Restored content",
        status="active",
        trust_score=0.95,
    )

    recovery_result = {
    "success": True,
    "results": [
        {
            "action": "ROLLBACK",
            "success": True,
            "content_recovered": True,
            "recovery_provenance_verified": True,
            "authorization_valid": False,
            "fully_verified": False,
        }
    ],
}

    with (
        patch(
            "core.security.monitor.MemoryCompromiseDetector"
        ) as detector_class,
        patch(
            "core.security.monitor.AttackImpactAnalyzer"
        ),
        patch(
            "core.security.monitor.AegisMemRecoveryOrchestrator"
        ) as orchestrator_class,
    ):
        detector_class.return_value.detect.return_value = detection
        orchestrator_class.return_value.recover_from_attack.return_value = (
            recovery_result
        )

        monitor = AegisMemSecurityMonitor(session)
        monitor.build_graph = MagicMock()

        with patch.object(
            monitor.repository,
            "get_latest",
            return_value=current,
        ):
            result = monitor.process("TEST-MEMORY-001")

    assert result["detected"] is True
    assert result["recovered"] is True
    assert result["recovery"] == recovery_result
    assert result["current_version"] == 3
    assert result["current_content"] == "Restored content"
    assert result["current_status"] == "active"
    assert result["current_trust_score"] == 0.95
    assert result["detection"]["integrity_anchor_status"] == "INVALID"


def test_monitor_reports_recovery_failure():
    session = MagicMock()

    detection = SimpleNamespace(
        compromised=True,
        suspicion_score=0.9,
        reason="Test compromise",
        attribution="unknown",
        attribution_evidence={},
        evidence=SimpleNamespace(
            integrity_anchor_status="INVALID"
        ),
    )

    with (
        patch(
            "core.security.monitor.MemoryCompromiseDetector"
        ) as detector_class,
        patch(
            "core.security.monitor.AttackImpactAnalyzer"
        ),
        patch(
            "core.security.monitor.AegisMemRecoveryOrchestrator"
        ) as orchestrator_class,
    ):
        detector_class.return_value.detect.return_value = detection
        orchestrator_class.return_value.recover_from_attack.return_value = {
            "success": False,
            "reason": "No trusted version available",
        }

        monitor = AegisMemSecurityMonitor(session)
        monitor.build_graph = MagicMock()

        with patch.object(
            monitor.repository,
            "get_latest",
            return_value=None,
        ):
            result = monitor.process("TEST-MEMORY-001")

    assert result["detected"] is True
    assert result["recovered"] is False
    assert result["current_version"] is None
    assert result["current_content"] is None
    assert result["current_status"] is None
    assert result["current_trust_score"] is None

def test_build_graph_creates_default_dependencies_when_missing():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    TestSession = sessionmaker(bind=engine)

    try:
        with TestSession() as session:
            monitor = AegisMemSecurityMonitor(session)

            graph = monitor.build_graph()

            repository = DependencyRepository(session)
            dependencies = repository.get_dependencies("POLICY-001")

            assert len(dependencies) == 1
            assert graph.edge_strength("POLICY-001", "POLICY-002") == 0.9
            assert graph.edge_strength("POLICY-002", "SOP-003") == 0.8
            assert graph.edge_type("POLICY-001", "POLICY-002") == "derived_from"
            assert graph.edge_type("POLICY-002", "SOP-003") == "derived_from"
    finally:
        engine.dispose()


def test_build_graph_does_not_duplicate_existing_dependencies():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    TestSession = sessionmaker(bind=engine)

    try:
        with TestSession() as session:
            repository = DependencyRepository(session)

            repository.add_dependency(
                source_memory_id="POLICY-001",
                target_memory_id="EXISTING-POLICY",
                dependency_type="test_dependency",
                strength=0.7,
            )

            monitor = AegisMemSecurityMonitor(session)
            graph = monitor.build_graph()

            dependencies = repository.get_dependencies("POLICY-001")

            assert len(dependencies) == 1
            assert graph.edge_strength("POLICY-001", "EXISTING-POLICY") == 0.7
            assert not graph.graph.has_edge("POLICY-001", "POLICY-002")
            assert not graph.graph.has_edge("POLICY-002", "SOP-003")
    finally:
        engine.dispose()

