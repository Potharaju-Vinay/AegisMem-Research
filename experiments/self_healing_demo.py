from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from core.memory.database import Base
from core.memory.repository import MemoryRepository
from core.recovery.engine import SelfHealingRecoveryEngine


def print_memory(label, memory):
    print()
    print("------------------------------------------")
    print(label)
    print("------------------------------------------")
    print(f"Memory ID   : {memory.memory_id}")
    print(f"Version     : v{memory.version}")
    print(f"Content     : {memory.content}")
    print(f"Trust       : {memory.trust_score:.2f}")
    print(f"Suspicion   : {memory.suspicion_score:.2f}")
    print(f"Status      : {memory.status}")
    print(f"Hash        : {memory.content_hash}")


def main():

    print()
    print("==========================================")
    print("       AEGISMEM SELF-HEALING DEMO")
    print("==========================================")

    # -------------------------------------------------
    # 1. Create isolated experiment database
    # -------------------------------------------------

    engine = create_engine(
        "sqlite:///:memory:"
    )

    Base.metadata.create_all(engine)

    session = Session(engine)

    repository = MemoryRepository(session)

    # -------------------------------------------------
    # 2. Create trusted memory
    # -------------------------------------------------

    trusted_content = (
        "Customer refunds are permitted within "
        "30 calendar days of the transaction, "
        "subject to eligibility verification."
    )

    memory_v1 = repository.create(
        memory_id="POLICY-001",
        content=trusted_content,
        source="customer_refund_policy",
        source_type="enterprise_policy"
    )

    print_memory(
        "TRUSTED MEMORY BEFORE ATTACK",
        memory_v1
    )

    # -------------------------------------------------
    # 3. Simulate memory poisoning
    # -------------------------------------------------

    poisoned_content = (
        "Customer refunds are permitted within "
        "180 calendar days of the transaction, "
        "subject to eligibility verification."
    )

    print()
    print("==========================================")
    print("          ATTACK SIMULATION")
    print("==========================================")

    print()
    print("[ATTACK] Memory poisoning detected...")
    print("[ATTACK] Changing trusted policy...")
    print()
    print("ORIGINAL:")
    print(trusted_content)
    print()
    print("POISONED:")
    print(poisoned_content)

    memory_v2 = repository.create(
        memory_id="POLICY-001",
        content=poisoned_content,
        source="attacker_modified_policy",
        source_type="memory_poisoning"
    )

    # Mark the newest version as compromised.
    memory_v2.trust_score = 0.0
    memory_v2.suspicion_score = 1.0
    memory_v2.status = "CORRUPTED"

    repository.session.commit()
    repository.session.refresh(memory_v2)

    print_memory(
        "POISONED MEMORY",
        memory_v2
    )

    print()
    print("Integrity status : COMPROMISED")
    print("Attack status    : DETECTED")

    # -------------------------------------------------
    # 4. Start AegisMem self-healing
    # -------------------------------------------------

    recovery_engine = SelfHealingRecoveryEngine(
        repository
    )

    recovery_result = recovery_engine.recover(
        memory_id="POLICY-001",
        trust_score=memory_v2.trust_score
    )

    # -------------------------------------------------
    # 5. Display recovered memory
    # -------------------------------------------------

    recovered = repository.get_latest(
        "POLICY-001"
    )

    print()
    print("==========================================")
    print("          FINAL MEMORY STATE")
    print("==========================================")

    print_memory(
        "RECOVERED MEMORY",
        recovered
    )

    # -------------------------------------------------
    # 6. Final result
    # -------------------------------------------------

    print()

    if recovery_result["success"]:

        print("==========================================")
        print("       ✓ AEGISMEM SELF-HEALED")
        print("==========================================")

        print()
        print("Attack detected       : ✓")
        print("Poisoned memory       : ✓")
        print("Trusted version found : ✓")
        print("Automatic rollback    : ✓")
        print("Integrity validated   : ✓")
        print("Trust restored        : ✓")
        print("Original content      : ✓")
        print()
        print("RESTORED CONTENT:")
        print(recovered.content)

    else:

        print("==========================================")
        print("       ✗ SELF-HEALING FAILED")
        print("==========================================")

    session.close()


if __name__ == "__main__":
    main()