from datetime import datetime, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from attack_lab.impact import AttackImpactAnalyzer
from attack_lab.models import AttackEvent

from core.integrity.hash import calculate_content_hash
from core.provenance.manager import ProvenanceManager

from core.graph.dependency.engine import DependencyGraph
from core.graph.dependency.repository import DependencyRepository

from core.memory.database import Base
from core.memory.repository import MemoryRepository

from core.detection.detector import MemoryCompromiseDetector


from core.recovery.orchestrator import (
    AegisMemRecoveryOrchestrator
)


def show_memory(repository, memory_id, label):

    memory = repository.get_latest(memory_id)

    print()
    print("------------------------------------------")
    print(label)
    print("------------------------------------------")

    if memory is None:
        print("Memory not found.")
        return

    print(f"Memory ID : {memory.memory_id}")
    print(f"Version   : v{memory.version}")
    print(f"Content   : {memory.content}")
    print(f"Trust     : {memory.trust_score:.2f}")
    print(f"Suspicion : {memory.suspicion_score:.2f}")
    print(f"Status    : {memory.status}")


def main():

    print()
    print("==================================================")
    print("       AEGISMEM DEPENDENCY SELF-HEALING LAB")
    print("==================================================")

    engine = create_engine(
        "sqlite:///:memory:"
    )

    Base.metadata.create_all(engine)

    session = Session(engine)

    repository = MemoryRepository(session)

    # =================================================
    # 1. ORIGINAL TRUSTED MEMORY CHAIN
    # =================================================

    policy = repository.create(
        memory_id="POLICY-001",
        content=(
            "Customer refunds are permitted within "
            "30 calendar days of the transaction."
        ),
        source="customer_refund_policy",
        source_type="enterprise_policy"
    )

    procedure = repository.create(
        memory_id="POLICY-002",
        content=(
            "Eligible refund requests received within "
            "30 calendar days should be processed "
            "according to the refund procedure."
        ),
        source="refund_processing_procedure",
        source_type="enterprise_procedure"
    )

    sop = repository.create(
        memory_id="SOP-003",
        content=(
            "Customer support should inform customers "
            "that refund requests are eligible when "
            "submitted within 30 calendar days."
        ),
        source="customer_support_sop",
        source_type="security_procedure"
    )

    print()
    print("TRUSTED MEMORY CHAIN")
    print("==========================================")

    show_memory(
        repository,
        "POLICY-001",
        "ROOT POLICY"
    )

    show_memory(
        repository,
        "POLICY-002",
        "DEPENDENT PROCEDURE"
    )

    show_memory(
        repository,
        "SOP-003",
        "DEPENDENT SOP"
    )

    # =================================================
    # 2. DEPENDENCY GRAPH
    # =================================================

    dependency_repo = DependencyRepository(
        session
    )

    dependency_repo.add_dependency(
        source_memory_id="POLICY-001",
        target_memory_id="POLICY-002",
        dependency_type="derived_from",
        strength=0.9
    )

    dependency_repo.add_dependency(
        source_memory_id="POLICY-002",
        target_memory_id="SOP-003",
        dependency_type="derived_from",
        strength=0.8
    )

    graph = DependencyGraph(
        dependency_repo
    )

    # Load dependency edges into the in-memory graph
    
    graph.load()

    impact_analyzer = AttackImpactAnalyzer(
        graph
    )

    # =================================================
    # 3. ATTACK ROOT MEMORY
    # =================================================

    print()
    print("==================================================")
    print("                 ATTACK PHASE")
    print("==================================================")

    print()
    print("[ATTACK] Root memory POLICY-001 compromised.")

    poisoned_policy = repository.create(
        memory_id="POLICY-001",
        content=(
            "Customer refunds are permitted within "
            "180 calendar days of the transaction."
        ),
        source="prompt_injection_attack",
        source_type="memory_poisoning"
    )

    poisoned_policy.trust_score = 0.0
    poisoned_policy.suspicion_score = 1.0
    poisoned_policy.status = "CORRUPTED"

    session.commit()

    # =================================================
    # RECORD ATTACK EVENT
    # =================================================

    attack_event = AttackEvent(
        attack_id="ATTACK-001",
        memory_record_id=poisoned_policy.id,
        memory_id="POLICY-001",
        original_content=policy.content,
        modified_content=poisoned_policy.content,
        original_version=policy.version,
        target_version=poisoned_policy.version,
        original_content_hash=calculate_content_hash(
            policy.content
        ),
        observed_content_hash=calculate_content_hash(
            poisoned_policy.content
        ),
        attack_type="prompt_injection_memory_poisoning",
        mutation_description=(
            "Persistent refund policy changed from "
            "30 calendar days to 180 calendar days."
        ),
        attacker="controlled_kali_lab",
        attack_time=datetime.now(timezone.utc),
        integrity_compromised=True,
        status="DETECTED"
    )

    session.add(attack_event)
    session.commit()

    print()
    print("------------------------------------------")
    print("ATTACK EVENT RECORDED")
    # =================================================
    # RECORD PROVENANCE EVENT
    # =================================================

    provenance_manager = ProvenanceManager(session)

    provenance_event = provenance_manager.record(
        memory_record_id=poisoned_policy.id,
        memory_id=poisoned_policy.memory_id,
        version=poisoned_policy.version,
        actor="controlled_kali_lab",
        operation="MEMORY_POISON",
        source="prompt_injection_attack",
        source_type="memory_poisoning",
        metadata={
            "attack_id": attack_event.attack_id,
            "attack_type": attack_event.attack_type,
            "original_version": policy.version,
            "target_version": poisoned_policy.version,
            "integrity_compromised": True
        }
    )

    print()
    print("------------------------------------------")
    print("PROVENANCE EVENT RECORDED")
    print("------------------------------------------")
    print(
        f"Provenance ID : {provenance_event.id}"
    )
    print(
        f"Memory        : {provenance_event.memory_id}"
    )
    print(
        f"Version       : v{provenance_event.version}"
    )
    print(
        f"Actor         : {provenance_event.actor}"
    )
    print(
        f"Operation     : {provenance_event.operation}"
    )
    print(
        f"Source        : {provenance_event.source}"
    )
    print(
        f"Source Type   : {provenance_event.source_type}"
    )
    print(
        f"Event Hash    : {provenance_event.event_hash}"
    )
    print("------------------------------------------")
    print(f"Attack ID        : {attack_event.attack_id}")
    print(f"Attack Type      : {attack_event.attack_type}")
    print(f"Attacker         : {attack_event.attacker}")
    print(f"Target Memory    : {attack_event.memory_id}")
    print(f"Original Version : v{attack_event.original_version}")
    print(f"Target Version   : v{attack_event.target_version}")
    print(
        f"Integrity        : "
        f"{'COMPROMISED' if attack_event.integrity_compromised else 'VALID'}"
    )
    print(f"Status           : {attack_event.status}")

    show_memory(
        repository,
        "POLICY-001",
        "POISONED ROOT MEMORY"
    )

    # =================================================
    # 4. SIMULATE DERIVED MEMORY CONTAMINATION
    # =================================================
    #
    # These records represent controlled attack ground
    # truth. Their contents are changed because the
    # compromised root policy is assumed to have been
    # consumed by downstream knowledge processes.
    #
    # IMPORTANT:
    # We do NOT manually assign trust/suspicion/status
    # to these dependent memories. AegisMem must derive
    # their risk from dependency propagation and local
    # evidence.
    # =================================================

    print()
    print("==================================================")
    print("          CASCADING MEMORY CONTAMINATION")
    print("==================================================")

    poisoned_procedure = repository.create(
        memory_id="POLICY-002",
        content=(
            "Eligible refund requests received within "
            "180 calendar days should be processed "
            "according to the refund procedure."
        ),
        source="derived_from_compromised_policy",
        source_type="derived_memory"
    )

    poisoned_sop = repository.create(
        memory_id="SOP-003",
        content=(
            "Customer support should inform customers "
            "that refund requests are eligible when "
            "submitted within 180 calendar days."
        ),
        source="derived_from_compromised_procedure",
        source_type="derived_memory"
    )

    session.commit()

    show_memory(
        repository,
        "POLICY-002",
        "DERIVED PROCEDURE AFTER ROOT COMPROMISE"
    )

    show_memory(
        repository,
        "SOP-003",
        "DERIVED SOP AFTER ROOT COMPROMISE"
    )


    # ==================================================
    # AEGISMEM DETECTION
    # ==================================================

    print()
    print("=" * 50)
    print("          AEGISMEM DETECTION")
    print("=" * 50)

    detector = MemoryCompromiseDetector(
        repository,
        dependency_graph=graph
    )


    detected_memories = []

    for memory_id in [
        "POLICY-001",
        "POLICY-002",
        "SOP-003"
    ]:

        detection = detector.detect(memory_id)

        detected_memories.append(detection)

        evidence = detection.evidence

        print()
        print("------------------------------------------")
        print(f"Memory              : {memory_id}")

        print(
            f"Integrity Evidence  : "
            f"{'COMPROMISED' if evidence.integrity_compromised else 'VALID'}"
        )

        print(
            f"Provenance Evidence : "
            f"{'SUSPICIOUS' if evidence.provenance_suspicious else 'NORMAL'}"
        )

        print(
            f"Attack Evidence     : "
            f"{'DETECTED' if evidence.attack_detected else 'NONE'}"
        )

        print(
            f"Status Evidence     : "
            f"{'CORRUPTED' if evidence.status_corrupted else 'ACTIVE'}"
        )

        print(
            f"Dependency Exposure : "
            f"{evidence.dependency_exposure:.2f}"
        )

        print(
            f"Dependency Evidence : "
            f"{'CONTAMINATED' if evidence.dependency_contamination else 'NONE'}"
        )

        print(
            f"Local Suspicion     : "
            f"{detection.suspicion_score:.2f}"
        )

        print(
            f"Detection Result    : "
            f"{'COMPROMISED ✓' if detection.compromised else 'NO CONFIRMED COMPROMISE'}"
        )

        print(
            f"Reason              : "
            f"{detection.reason}"
        )

    print()
    print("------------------------------------------")

    compromised_count = sum(
        1 for detection in detected_memories
        if detection.compromised
    )

    print(
        f"Confirmed compromised memories : "
        f"{compromised_count}"
    )

    # =================================================
    # 5. RUN AEGISMEM
    # =================================================

    print()
    print("==================================================")
    print("              AEGISMEM RECOVERY")
    print("==================================================")

    orchestrator = AegisMemRecoveryOrchestrator(
        repository=repository,
        impact_analyzer=impact_analyzer
    )

    result = orchestrator.recover_from_attack(
        compromised_memory_id="POLICY-001"
    )

    # =================================================
    # 6. FINAL STATE
    # =================================================

    print()
    print("==================================================")
    print("              FINAL MEMORY STATE")
    print("==================================================")

    show_memory(
        repository,
        "POLICY-001",
        "POLICY-001 AFTER RECOVERY"
    )

    show_memory(
        repository,
        "POLICY-002",
        "POLICY-002 AFTER RECOVERY"
    )

    show_memory(
        repository,
        "SOP-003",
        "SOP-003 AFTER RECOVERY"
    )

    print()

    if result["success"]:

        print("==================================================")
        print("        ✓ AEGISMEM SELF-HEALING COMPLETE")
        print("==================================================")

    else:

        print("==================================================")
        print("        ✗ RECOVERY INCOMPLETE")
        print("==================================================")

    session.close()


if __name__ == "__main__":
    main()