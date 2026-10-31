
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from attack_lab.external_attack import ExternalMemoryAttacker
from core.provenance.models import ProvenanceEvent
from tests.owner_approval_test_utils import sign_test_approval
from core.memory.database import Base
from core.memory.repository import MemoryRepository
from core.graph.dependency.repository import DependencyRepository
from core.graph.dependency.engine import DependencyGraph
from core.integrity.manifest_store import IntegrityManifestStore
from core.provenance.manager import ProvenanceManager
from core.provenance.checkpoint import ProvenanceCheckpointStore
from core.provenance.trusted_head import TrustedCheckpointHeadStore
from core.detection.detector import MemoryCompromiseDetector
from core.recovery.orchestrator import AegisMemRecoveryOrchestrator
from attack_lab.corruption import MemoryCorruptionAttack
from attack_lab.impact import AttackImpactAnalyzer
from unittest.mock import patch
from core.security.monitor import AegisMemSecurityMonitor
from unittest.mock import patch
from core.recovery.executor import RecoveryExecutor


def test_end_to_end_detect_and_recover_poisoned_memory(tmp_path):
    engine = create_engine("sqlite:///:memory:")

    try:
        Base.metadata.create_all(engine)

        with Session(engine) as session:
            private_key = Ed25519PrivateKey.generate()
            private_path = tmp_path / "private.pem"
            public_path = tmp_path / "public.pem"

            private_path.write_bytes(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )

            public_path.write_bytes(
                private_key.public_key().public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            )

            manifest_store = IntegrityManifestStore(
                manifest_dir=tmp_path / "manifests",
                private_key_path=private_path,
                public_key_path=public_path,
            )

            repository = MemoryRepository(
                session,
                manifest_store=manifest_store,
            )

            memory_id = "E2E-REFUND-POLICY"
            original_content = "Customer refunds are allowed within 30 days."
            poisoned_content = "Customer refunds are allowed within 180 days."

            with patch(
                "core.memory.repository.verify_and_register_nonce",
                return_value=True,
            ):
                original = repository.create_owner_authorized(
                    memory_id=memory_id,
                    content=original_content,
                    source="controlled_test",
                    authorization_id="E2E-AUTH-001",
                    nonce="E2E-NONCE-001",
                    authorization_signature=sign_test_approval(
                        memory_id,
                        original_content,
                        "E2E-AUTH-001",
                        "E2E-NONCE-001",
                    ),
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
                memory_record_id=original.id,
                memory_id=memory_id,
                version=original.version,
                actor="controlled_test",
                operation="CREATE",
                source=original.source,
                source_type=original.source_type,
            )

            events = provenance_manager.get_events(memory_id)
            checkpoint_store.create_checkpoint(events)
            trusted_head_store.advance(events)

            attack_result = ExternalMemoryAttacker(session).modify_memory(
    memory_id=memory_id,
    modified_content=poisoned_content,
    attacker="controlled-kali-lab",
    attack_type="content_tampering",
    source_ip="192.168.56.101",
    source_port=54321,
    entry_point="/attacker/memory/write",
    access_method="HTTP",
)

            assert attack_result["status"] == "CORRUPTED"

            attack_event = session.query(ProvenanceEvent).filter_by(
    memory_id=memory_id,
    version=attack_result["target_version"],
).one()

            assert attack_event.operation == "MEMORY_WRITE"
            assert attack_event.actor == "controlled-kali-lab"
            dependency_repository = DependencyRepository(session)

            dependency_repository.add_dependency(
    source_memory_id=memory_id,
    target_memory_id="E2E-DOWNSTREAM-POLICY",
    dependency_type="depends_on",
    strength=1.0,
)

            dependency_repository.add_dependency(
    source_memory_id="E2E-DOWNSTREAM-POLICY",
    target_memory_id="E2E-DOWNSTREAM-SOP",
    dependency_type="depends_on",
    strength=1.0,
)

            graph = DependencyGraph(dependency_repository)
            graph.load()

            assert memory_id in graph.graph
            assert graph.descendants(memory_id) == {
                "E2E-DOWNSTREAM-POLICY",
                "E2E-DOWNSTREAM-SOP",
            }

            detector = MemoryCompromiseDetector(
                repository=repository,
                dependency_graph=graph,
                manifest_store=manifest_store,
            )

            detection = detector.detect(memory_id)

            assert detection.compromised is True

            impact_analyzer = AttackImpactAnalyzer(graph)

            orchestrator = AegisMemRecoveryOrchestrator(
                repository=repository,
                impact_analyzer=impact_analyzer,
                manifest_store=manifest_store,
                provenance_manager=provenance_manager,
                checkpoint_store=checkpoint_store,
                trusted_head_store=trusted_head_store,
            )

            result = orchestrator.recover_from_attack(memory_id)
            
            print("\n=== RECOVERY RESULT ===")
            print(result)
            print("\n=== MEMORY VERSIONS ===")
            for record in repository.get_history(memory_id):
                print({
        "version": record.version,
        "content": record.content,
        "status": record.status,
        "trust_score": record.trust_score,
        "suspicion_score": record.suspicion_score,
    })

            recovered = repository.get_latest(memory_id)

            assert recovered is not None
            assert recovered.content == original_content
            assert recovered.status == "active"
            assert recovered.trust_score >= 0.8
            assert recovered.suspicion_score <= 0.2

            assert result["results"]
            rollback_results = [
                item for item in result["results"]
                if item.get("action") == "ROLLBACK"
            ]
            assert rollback_results

            recovery_details = rollback_results[0]["details"]
            validation = recovery_details.get("validation", {})

            assert recovery_details.get("content_valid") is True
            assert validation.get("integrity") is True
            assert validation.get("integrity_manifest") is True
            assert validation.get("recovery_attestation_valid") is True
            assert validation.get("provenance_verified") is True
            assert validation.get("recovery_provenance_verified") is True

    finally:
        engine.dispose()
        

def test_tampered_attack_provenance_blocks_recovery(tmp_path):
    engine = create_engine("sqlite:///:memory:")

    try:
        Base.metadata.create_all(engine)

        with Session(engine) as session:
            private_key = Ed25519PrivateKey.generate()
            private_path = tmp_path / "private.pem"
            public_path = tmp_path / "public.pem"

            private_path.write_bytes(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )

            public_path.write_bytes(
                private_key.public_key().public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            )

            manifest_store = IntegrityManifestStore(
                manifest_dir=tmp_path / "manifests",
                private_key_path=private_path,
                public_key_path=public_path,
            )

            repository = MemoryRepository(
                session,
                manifest_store=manifest_store,
            )

            memory_id = "E2E-PROVENANCE-TAMPER"
            original_content = "Refunds are allowed within 30 days."
            poisoned_content = "Refunds are allowed within 180 days."

            with patch(
                "core.memory.repository.verify_and_register_nonce",
                return_value=True,
            ):
                original = repository.create_owner_authorized(
                    memory_id=memory_id,
                    content=original_content,
                    source="controlled_test",
                    authorization_id="TAMPER-AUTH-001",
                    nonce="TAMPER-NONCE-001",
                    authorization_signature=sign_test_approval(
                        memory_id,
                        original_content,
                        "TAMPER-AUTH-001",
                        "TAMPER-NONCE-001",
                    ),
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
                memory_record_id=original.id,
                memory_id=memory_id,
                version=original.version,
                actor="controlled_test",
                operation="CREATE",
                source=original.source,
                source_type=original.source_type,
            )

            events = provenance_manager.get_events(memory_id)
            checkpoint_store.create_checkpoint(events)
            trusted_head_store.advance(events)

            attack_result = ExternalMemoryAttacker(session).modify_memory(
                memory_id=memory_id,
                modified_content=poisoned_content,
                attacker="controlled-kali-lab",
                attack_type="content_tampering",
                source_ip="192.168.56.101",
                source_port=54321,
                entry_point="/attacker/memory/write",
                access_method="HTTP",
            )

            assert attack_result["status"] == "CORRUPTED"

            attack_event = session.query(ProvenanceEvent).filter_by(
                memory_id=memory_id,
                version=attack_result["target_version"],
            ).one()

            assert attack_event.operation == "MEMORY_WRITE"

            attack_event.event_metadata = '{"tampered":true}'
            session.commit()

            events = provenance_manager.get_events(memory_id)

            assert (
                trusted_head_store.verify_trusted_prefix(events)
                == "CHAIN_TAMPERED"
            )

            executor = RecoveryExecutor(
                repository=repository,
                manifest_store=manifest_store,
                provenance_manager=provenance_manager,
                checkpoint_store=checkpoint_store,
                trusted_head_store=trusted_head_store,
            )

            result = executor.rollback(memory_id, original.version)

            assert result.success is False
            assert "CHAIN_TAMPERED" in result.message

            latest = repository.get_latest(memory_id)

            assert latest.content == poisoned_content
            assert latest.status == "CORRUPTED"

    finally:
        engine.dispose()


def test_security_monitor_real_recovery_integration(tmp_path):
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session
    from core.memory.database import Base

    engine = create_engine("sqlite:///:memory:")

    try:
        Base.metadata.create_all(engine)

        with Session(engine) as session:
            monitor = AegisMemSecurityMonitor(session)

            assert monitor.repository is not None
            assert monitor.manifest_store is not None

            graph = monitor.build_graph()

            assert graph.graph.has_edge("POLICY-001", "POLICY-002")
            assert graph.graph.has_edge("POLICY-002", "SOP-003")

    finally:
        engine.dispose()
