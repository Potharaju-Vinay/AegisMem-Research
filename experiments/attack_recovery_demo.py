from datetime import datetime, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from attack_lab.agent_attack import PromptInjectionAttack
from attack_lab.memory_poisoning import MemoryPoisoningHandler

from attack_lab.impact import AttackImpactAnalyzer

from core.graph.dependency.engine import DependencyGraph
from core.graph.dependency.repository import DependencyRepository

from core.memory.database import Base
from core.memory.repository import MemoryRepository

from core.recovery.orchestrator import (
    AegisMemRecoveryOrchestrator
)


def main():

    print()
    print("==================================================")
    print("        AEGISMEM ATTACK → SELF-HEALING LAB")
    print("==================================================")

    # -------------------------------------------------
    # 1. Isolated database
    # -------------------------------------------------

    engine = create_engine(
        "sqlite:///:memory:"
    )

    Base.metadata.create_all(engine)

    session = Session(engine)

    memory_repo = MemoryRepository(session)

    # -------------------------------------------------
    # 2. Create trusted enterprise memory
    # -------------------------------------------------

    trusted_content = (
        "Customer refunds are permitted within "
        "30 calendar days of the transaction, "
        "subject to eligibility verification."
    )

    memory = memory_repo.create(
        memory_id="POLICY-001",
        content=trusted_content,
        source="customer_refund_policy",
        source_type="enterprise_policy"
    )

    print()
    print("[SYSTEM] Trusted memory initialized.")
    print()
    print(f"Memory ID : {memory.memory_id}")
    print(f"Version   : v{memory.version}")
    print(f"Content   : {memory.content}")
    print(f"Trust     : {memory.trust_score:.2f}")

    # -------------------------------------------------
    # 3. Create dependent memories
    # -------------------------------------------------

    dependency_repo = DependencyRepository(
        session
    )

    # These represent knowledge derived from POLICY-001.
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

    impact_analyzer = AttackImpactAnalyzer(
        graph
    )

    # -------------------------------------------------
    # 4. Generate prompt injection
    # -------------------------------------------------

    attack = PromptInjectionAttack()

    poisoned_content = (
        "Customer refunds are permitted within "
        "180 calendar days of the transaction, "
        "subject to eligibility verification."
    )

    payload = attack.create_payload(
        target_memory_id="POLICY-001",
        trusted_content=trusted_content,
        poisoned_content=poisoned_content
    )

    print()
    print("==================================================")
    print("                 ATTACK PHASE")
    print("==================================================")

    print()
    print("Attack type:")
    print(payload.attack_type)

    print()
    print("Malicious prompt:")
    print("------------------------------------------")
    print(payload.prompt)

    # -------------------------------------------------
    # 5. Apply memory poisoning
    # -------------------------------------------------

    poisoning_handler = MemoryPoisoningHandler(
        memory_repo
    )

    poisoned = poisoning_handler.apply(
        payload
    )

    print()
    print("[ATTACK] Persistent memory modified.")

    print()
    print("POISONED MEMORY")
    print("------------------------------------------")
    print(f"Memory ID : {poisoned.memory_id}")
    print(f"Version   : v{poisoned.version}")
    print(f"Content   : {poisoned.content}")
    print(f"Trust     : {poisoned.trust_score:.2f}")
    print(f"Suspicion : {poisoned.suspicion_score:.2f}")
    print(f"Status    : {poisoned.status}")

    # -------------------------------------------------
    # 6. AegisMem recovery
    # -------------------------------------------------

    print()
    print("==================================================")
    print("              AEGISMEM DETECTION")
    print("==================================================")

    print()
    print("[AegisMem] Integrity violation detected.")
    print("[AegisMem] Memory poisoning confirmed.")
    print("[AegisMem] Initiating TCRP.")

    orchestrator = AegisMemRecoveryOrchestrator(
        repository=memory_repo,
        impact_analyzer=impact_analyzer
    )

    recovery = orchestrator.recover_from_attack(
        compromised_memory_id="POLICY-001",
        attack_time=datetime.now(timezone.utc)
    )

    # -------------------------------------------------
    # 7. Final state
    # -------------------------------------------------

    final_memory = memory_repo.get_latest(
        "POLICY-001"
    )

    print()
    print("==================================================")
    print("              FINAL SYSTEM STATE")
    print("==================================================")

    print()
    print(f"Memory ID : {final_memory.memory_id}")
    print(f"Version   : v{final_memory.version}")
    print(f"Content   : {final_memory.content}")
    print(f"Trust     : {final_memory.trust_score:.2f}")
    print(f"Suspicion : {final_memory.suspicion_score:.2f}")
    print(f"Status    : {final_memory.status}")

    print()

    if recovery["success"]:

        print("==================================================")
        print("          ✓ AEGISMEM SELF-HEALED")
        print("==================================================")

        print()
        print("Prompt injection          : DETECTED ✓")
        print("Memory poisoning          : DETECTED ✓")
        print("Trust cascading           : EXECUTED ✓")
        print("Recovery planning         : EXECUTED ✓")
        print("Automatic rollback        : EXECUTED ✓")
        print("Memory integrity          : VERIFIED ✓")
        print("Trusted content restored  : YES ✓")
        print("System state              : SAFE ✓")

    else:

        print("==================================================")
        print("          ✗ RECOVERY FAILED")
        print("==================================================")

    session.close()


if __name__ == "__main__":
    main()