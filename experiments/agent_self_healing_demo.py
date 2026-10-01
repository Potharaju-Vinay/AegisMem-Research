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
from core.recovery.orchestrator import AegisMemRecoveryOrchestrator


class RefundDecisionAgent:

    def __init__(self, repository):
        self.repository = repository

    def decide(self, customer_days: int):

        memory = self.repository.get_latest(
            "POLICY-001"
        )

        if memory is None:
            raise ValueError("Refund policy not found.")

        content = memory.content

        if "180 calendar days" in content:
            policy_limit = 180
        elif "30 calendar days" in content:
            policy_limit = 30
        else:
            raise ValueError(
                "Unable to determine refund policy."
            )

        decision = (
            "REFUND ALLOWED"
            if customer_days <= policy_limit
            else "REFUND DENIED"
        )

        return {
            "memory_version": memory.version,
            "policy_limit": policy_limit,
            "customer_days": customer_days,
            "decision": decision,
            "memory_status": memory.status,
            "trust_score": memory.trust_score
        }


def show_decision(label, result):

    print()
    print("------------------------------------------")
    print(label)
    print("------------------------------------------")
    print(
        f"Memory Version : v{result['memory_version']}"
    )
    print(
        f"Policy Limit   : {result['policy_limit']} days"
    )
    print(
        f"Customer Days  : {result['customer_days']} days"
    )
    print(
        f"Memory Status  : {result['memory_status']}"
    )
    print(
        f"Trust Score    : {result['trust_score']:.2f}"
    )
    print(
        f"Agent Decision : {result['decision']}"
    )


def main():

    print()
    print("==================================================")
    print("       AEGISMEM AGENT SELF-HEALING LAB")
    print("==================================================")

    engine = create_engine(
        "sqlite:///:memory:"
    )

    Base.metadata.create_all(engine)

    session = Session(engine)

    repository = MemoryRepository(session)

    # -------------------------------------------------
    # 1. TRUSTED MEMORY
    # -------------------------------------------------

    trusted_content = (
        "Customer refunds are permitted within "
        "30 calendar days of the transaction, "
        "subject to eligibility verification."
    )

    repository.create(
    memory_id="POLICY-001",
    content=trusted_content,
    source="customer_refund_policy",
    source_type="enterprise_policy"
)

    repository.create(
        memory_id="POLICY-002",
        content=(
            "Eligible refund requests received within "
            "30 calendar days should be processed "
            "according to the refund procedure."
        ),
        source="refund_procedure",
        source_type="enterprise_procedure"
    )

    repository.create(
        memory_id="SOP-003",
        content=(
            "Customer support should inform customers "
            "that refund requests are eligible when "
            "submitted within 30 calendar days."
        ),
        source="customer_support_sop",
        source_type="enterprise_sop"
    )

    # -------------------------------------------------
    # 2. DEPENDENCY GRAPH
    # -------------------------------------------------

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

    graph.load()

    impact_analyzer = AttackImpactAnalyzer(
        graph
    )

    # -------------------------------------------------
    # 3. AI AGENT
    # -------------------------------------------------

    agent = RefundDecisionAgent(
        repository
    )

    customer_days = 45

    print()
    print("==================================================")
    print("              TRUSTED AGENT STATE")
    print("==================================================")

    trusted_decision = agent.decide(
        customer_days
    )

    show_decision(
        "AGENT DECISION BEFORE ATTACK",
        trusted_decision
    )

    # -------------------------------------------------
    # 4. PROMPT INJECTION ATTACK
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
    print("                ATTACK PHASE")
    print("==================================================")

    print()
    print("Attack Type:")
    print(payload.attack_type)

    print()
    print("Injected Instruction:")
    print("------------------------------------------")
    print(payload.prompt)

    poisoning_handler = MemoryPoisoningHandler(
        repository
    )

    poisoned = poisoning_handler.apply(
        payload
    )

    print()
    print("Poisoned Memory:")
    print("------------------------------------------")
    print(
        f"Memory ID : {poisoned.memory_id}"
    )
    print(
        f"Version   : v{poisoned.version}"
    )
    print(
        f"Content   : {poisoned.content}"
    )
    print(
        f"Trust     : {poisoned.trust_score:.2f}"
    )
    print(
        f"Status    : {poisoned.status}"
    )

    # -------------------------------------------------
    # 5. AGENT BEHAVIOR AFTER ATTACK
    # -------------------------------------------------

    print()
    print("==================================================")
    print("          AGENT AFTER MEMORY POISONING")
    print("==================================================")

    poisoned_decision = agent.decide(
        customer_days
    )

    show_decision(
        "AGENT DECISION AFTER ATTACK",
        poisoned_decision
    )

    # -------------------------------------------------
    # 6. AEGISMEM RECOVERY
    # -------------------------------------------------

    print()
    print("==================================================")
    print("             AEGISMEM SELF-HEALING")
    print("==================================================")

    orchestrator = AegisMemRecoveryOrchestrator(
        repository=repository,
        impact_analyzer=impact_analyzer
    )

    recovery = orchestrator.recover_from_attack(
        compromised_memory_id="POLICY-001",
        attack_time=datetime.now(timezone.utc)
    )

    # -------------------------------------------------
    # 7. AGENT AFTER RECOVERY
    # -------------------------------------------------

    print()
    print("==================================================")
    print("          AGENT AFTER SELF-HEALING")
    print("==================================================")

    recovered_decision = agent.decide(
        customer_days
    )

    show_decision(
        "AGENT DECISION AFTER RECOVERY",
        recovered_decision
    )

    # -------------------------------------------------
    # 8. BEHAVIORAL VALIDATION
    # -------------------------------------------------

    print()
    print("==================================================")
    print("              BEHAVIORAL VALIDATION")
    print("==================================================")

    behavior_restored = (
        trusted_decision["decision"]
        == recovered_decision["decision"]
    )

    attack_changed_behavior = (
        trusted_decision["decision"]
        != poisoned_decision["decision"]
    )

    memory_restored = (
        recovered_decision["policy_limit"]
        == trusted_decision["policy_limit"]
    )

    primary_memory_recovered = (
        recovered_decision["memory_status"] == "active"
        and recovered_decision["trust_score"] >= 0.8
        and recovered_decision["policy_limit"]
        == trusted_decision["policy_limit"]
    )

    print()
    print(
        f"Attack changed agent behavior : "
        f"{'YES' if attack_changed_behavior else 'NO'}"
    )

    print(
        f"Trusted memory restored       : "
        f"{'YES' if memory_restored else 'NO'}"
    )

    print(
        f"Agent behavior restored       : "
        f"{'YES' if behavior_restored else 'NO'}"
    )

    print(
        f"Primary memory recovered      : "
        f"{'YES' if primary_memory_recovered else 'NO'}"
    )

    print(
        f"AegisMem recovery executed    : "
        f"{'YES' if recovery['success'] or primary_memory_recovered else 'NO'}"
    )

    print()

    if (
        attack_changed_behavior
        and memory_restored
        and behavior_restored
        and primary_memory_recovered
    ):
        print("==================================================")
        print("       ✓ END-TO-END SELF-HEALING VERIFIED")
        print("==================================================")
    else:
        print("==================================================")
        print("       ✗ END-TO-END VALIDATION FAILED")
        print("==================================================")

    session.close()


if __name__ == "__main__":
    main()