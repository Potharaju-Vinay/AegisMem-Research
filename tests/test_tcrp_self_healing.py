from tests.owner_approval_test_utils import sign_test_approval
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from core.graph.dependency.engine import DependencyGraph
from core.graph.dependency.repository import DependencyRepository
from core.memory.database import Base
from core.memory.repository import MemoryRepository
from core.integrity.manifest_store import IntegrityManifestStore
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from core.recovery.orchestrator import (
    AegisMemRecoveryOrchestrator
)
from core.trust.propagation import TemporalTrustPropagator
from unittest.mock import patch
from core.security.authorization import verify_authorization
from core.provenance.manager import ProvenanceManager
from core.provenance.checkpoint import ProvenanceCheckpointStore
from core.provenance.trusted_head import TrustedCheckpointHeadStore


def test_tcrp_automatic_self_healing(tmp_path):

    engine = create_engine(
        "sqlite:///:memory:"
    )

    Base.metadata.create_all(engine)

    session = Session(engine)

    test_private_key = Ed25519PrivateKey.generate()
    private_path = tmp_path / "test_anchor_private.pem"
    public_path = tmp_path / "test_anchor_public.pem"

    private_path.write_bytes(
        test_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

    public_path.write_bytes(
        test_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )

    manifest_store = IntegrityManifestStore(
        manifest_dir=tmp_path / "integrity_manifests",
        private_key_path=private_path,
        public_key_path=public_path,
    )

    
    

    

    memory_repo = MemoryRepository(
        session,
        manifest_store=manifest_store,
    )

    # ---------------------------------------------
    # Trusted memory
    # ---------------------------------------------

    
    
    with patch(
        "core.memory.repository.verify_and_register_nonce",
        return_value=True
    ):
        memory = memory_repo.create_owner_authorized(
            memory_id="M001",
            content="Refunds are allowed within 30 days.",
            source="policy",
            authorization_id="TEST-AUTH-M001-V1",
            nonce="TEST-NONCE-M001-V1", authorization_signature=sign_test_approval("M001", "Refunds are allowed within 30 days.", "TEST-AUTH-M001-V1", "TEST-NONCE-M001-V1")
        )

    
    
    provenance_manager = ProvenanceManager(session)

    provenance_dir = tmp_path / "provenance"
    checkpoint_store = ProvenanceCheckpointStore(
    checkpoint_dir=provenance_dir / "checkpoints",
    private_key_path=private_path,
    public_key_path=public_path,
)

    trusted_head_store = TrustedCheckpointHeadStore(
    head_dir=provenance_dir / "trusted_heads",
    private_key_path=private_path,
    public_key_path=public_path,
    checkpoint_store=checkpoint_store,
)

    provenance_manager.record(
    memory_record_id=memory.id,
    memory_id=memory.memory_id,
    version=memory.version,
    actor="controlled_test",
    operation="CREATE",
    source=memory.source,
    source_type=memory.source_type,
)

    events = provenance_manager.get_events(memory.memory_id)
    checkpoint_store.create_checkpoint(events)
    trusted_head_store.advance(events)

    # ---------------------------------------------
    # Poisoned version
    # ---------------------------------------------

    poisoned = memory_repo.create(
        memory_id="M001",
        content=(
            "Refunds are allowed within 180 days."
        ),
        source="attacker",
        source_type="memory_poisoning"
    )

    poisoned.trust_score = 0.0
    poisoned.suspicion_score = 1.0
    poisoned.status = "CORRUPTED"

    session.commit()

    # ---------------------------------------------
    # Build graph
    # ---------------------------------------------

    dependency_repo = DependencyRepository(
        session
    )

    dependency_repo.add_dependency(
        source_memory_id="M001",
        target_memory_id="M002",
        dependency_type="derived_from",
        strength=0.9
    )

    dependency_repo.add_dependency(
        source_memory_id="M002",
        target_memory_id="M003",
        dependency_type="derived_from",
        strength=0.8
    )

    graph = DependencyGraph(
        dependency_repo
    )

    impact_analyzer = __import__(
        "attack_lab.impact",
        fromlist=["AttackImpactAnalyzer"]
    ).AttackImpactAnalyzer(
        graph
    )
    
    orchestrator = AegisMemRecoveryOrchestrator(
    repository=memory_repo,
    impact_analyzer=impact_analyzer,
    manifest_store=manifest_store,
    provenance_manager=provenance_manager,
    checkpoint_store=checkpoint_store,
    trusted_head_store=trusted_head_store,
)

    # ---------------------------------------------
    # AegisMem orchestrator
    # ---------------------------------------------

    

    result = orchestrator.recover_from_attack(
        compromised_memory_id="M001"
    )

    assert result["success"] is True
    assert result["results"][0]["success"] is True
    assert result["results"][0]["details"]["content_valid"] is True
    assert result["results"][0]["details"]["authorization_valid"] is False
    assert result["results"][0]["details"]["recovery_authorization_valid"] is True
    assert result["results"][0]["details"]["recovery_fully_verified"] is True
    assert result["results"][0]["details"]["fully_verified"] is True

    recovered = memory_repo.get_latest(
        "M001"
    )

    assert recovered.content == (
        "Refunds are allowed within 30 days."
    )

    assert recovered.trust_score == 1.0

    assert recovered.suspicion_score == 0.0

    assert recovered.status == "active"

    session.close()

def test_tcrp_quarantines_memory_when_no_trusted_version_exists(tmp_path):
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)

    try:
        with Session(engine) as session:
            repository = MemoryRepository(session)
            memory_id = "M-NO-TRUSTED-POINT"

            repository.create(
                memory_id=memory_id,
                content="Unverified original content",
                source="controlled_test",
                source_type="controlled_test",
            )

            compromised = repository.create(
                memory_id=memory_id,
                content="Unverified modified content",
                source="controlled_test",
                source_type="memory_poisoning",
            )
            compromised.trust_score = 0.0
            compromised.suspicion_score = 1.0
            compromised.status = "CORRUPTED"
            session.commit()

            dependency_repo = DependencyRepository(session)
            graph = DependencyGraph(dependency_repo)

            class TestImpactAnalyzer:
                def __init__(self, dependency_graph):
                    self.graph = dependency_graph

                def analyze(self, compromised_memory_id, timestamp=None):
                    from types import SimpleNamespace

                    return {
                        compromised_memory_id: SimpleNamespace(
                            trust=0.0,
                            impact_score=1.0,
                            distance=0,
                        )
                    }

            orchestrator = AegisMemRecoveryOrchestrator(
                repository=repository,
                impact_analyzer=TestImpactAnalyzer(graph),
                manifest_store=IntegrityManifestStore(
                    manifest_dir=tmp_path / "manifests",
                    private_key_path=tmp_path / "missing_private.pem",
                    public_key_path=tmp_path / "missing_public.pem",
                ),
            )

            result = orchestrator.recover_from_attack(memory_id)

            latest = repository.get_latest(memory_id)

            assert latest.status.upper() == "QUARANTINED"
            assert latest.content == "Unverified modified content"
            assert result["success"] is True
            assert any(
                item["action"] == "QUARANTINE"
                and item["success"] is True
                and item["recovery_verified"] is False
                for item in result["results"]
            )
    finally:
        engine.dispose()

