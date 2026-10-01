import sys
import time
from pathlib import Path

sys.path.insert(
    0,
    str(Path(__file__).resolve().parents[1])
)

from core.memory.database import get_session
from core.memory.repository import MemoryRepository
from core.recovery.audit import RecoveryEvent
from attack_lab.models import AttackEvent


MEMORY_ID = "POLICY-001"

ATTACKS = {
    "content_tampering": {
        "label": "CONTENT TAMPERING",
        "event_type": "content_tampering"
    },
    "poisoning": {
        "label": "MEMORY POISONING",
        "event_type": "prompt_injection_memory_poisoning"
    },
    "deletion": {
        "label": "MEMORY DELETION",
        "event_type": "memory_deletion"
    }
}


def latest_attack(session):
    return (
        session.query(AttackEvent)
        .filter(
            AttackEvent.memory_id == MEMORY_ID
        )
        .order_by(
            AttackEvent.id.desc()
        )
        .first()
    )


def recovery_for_attack(session, target_version):
    events = (
        session.query(RecoveryEvent)
        .filter(
            RecoveryEvent.memory_id == MEMORY_ID,
            RecoveryEvent.compromised_version == target_version
        )
        .order_by(
            RecoveryEvent.id.asc()
        )
        .all()
    )

    for event in events:
        if event.restored_version is not None:
            return event

    return None


def latest_memory(session):
    repository = MemoryRepository(session)
    return repository.get_latest(MEMORY_ID)


def wait_for_attack(previous_attack_id, expected_type, timeout=60):
    start = time.perf_counter()

    while time.perf_counter() - start < timeout:

        session = get_session()

        try:
            attack = latest_attack(session)

            if attack is not None:
                if (
                    attack.id != previous_attack_id
                    and attack.attack_type == expected_type
                ):
                    return attack

        finally:
            session.close()

        time.sleep(0.5)

    return None


def wait_for_recovery(target_version, timeout=20):
    start = time.perf_counter()

    while time.perf_counter() - start < timeout:

        session = get_session()

        try:
            recovery = recovery_for_attack(
                session,
                target_version
            )

            if recovery is not None:
                return recovery

        finally:
            session.close()

        time.sleep(0.25)

    return None


def run_trial(attack_key):

    attack_config = ATTACKS[attack_key]

    session = get_session()

    try:
        baseline = latest_memory(session)

        if baseline is None:
            raise RuntimeError(
                f"{MEMORY_ID} does not exist."
            )

        baseline_version = baseline.version
        baseline_content = baseline.content

        previous_attack = latest_attack(session)

        previous_attack_id = (
            previous_attack.id
            if previous_attack is not None
            else None
        )

    finally:
        session.close()

    print()
    print("=" * 70)
    print(
        f"ATTACK: {attack_config['label']}"
    )
    print("=" * 70)

    print(
        f"Baseline version: {baseline_version}"
    )

    print()
    print(
        "Waiting for Kali attack..."
    )

    attack = wait_for_attack(
        previous_attack_id,
        attack_config["event_type"]
    )

    if attack is None:
        print()
        print(
            "ERROR: No matching attack event "
            "was detected within 60 seconds."
        )

        return None

    print()
    print(
        f"Attack ID: {attack.attack_id}"
    )

    print(
        f"Target version: {attack.target_version}"
    )

    print(
        f"Original version: {attack.original_version}"
    )

    print(
        f"Attack status: {attack.status}"
    )

    recovery = wait_for_recovery(
        attack.target_version
    )

    if recovery is None:
        print()
        print(
            "ERROR: Recovery event was not "
            "observed within 20 seconds."
        )

        return None

    session = get_session()

    try:
        final_memory = latest_memory(session)

        restored_content = (
            final_memory.content
            if final_memory is not None
            else None
        )

    finally:
        session.close()

    content_restored = (
        restored_content == baseline_content
    )

    validation_pass = (
        isinstance(
            recovery.validation_result,
            str
        )
        and (
            recovery.validation_result.upper() == "PASS"
            or "valid" in recovery.validation_result.lower()
        )
    )

    latency = (
        recovery.created_at
        - attack.attack_time
    ).total_seconds()

    success = (
        recovery.restored_version is not None
        and content_restored
        and validation_pass
    )

    print()
    print(
        f"Recovery action: {recovery.action}"
    )

    print(
        f"Compromised version: "
        f"{attack.target_version}"
    )

    print(
        f"Restored version: "
        f"{recovery.restored_version}"
    )

    print(
        f"Validation: "
        f"{recovery.validation_result}"
    )

    print(
        f"Latency: "
        f"{latency:.4f}s"
    )

    print(
        f"Content restored: "
        f"{content_restored}"
    )

    print(
        f"Final status: "
        f"{final_memory.status if final_memory else None}"
    )

    print(
        f"Success: {success}"
    )

    return {
        "attack_type": attack_key,
        "attack_id": attack.attack_id,
        "baseline_version": baseline_version,
        "compromised_version": attack.target_version,
        "restored_version": recovery.restored_version,
        "action": recovery.action,
        "validation": recovery.validation_result,
        "latency_seconds": latency,
        "content_restored": content_restored,
        "success": success
    }


def main():

    if len(sys.argv) != 2:
        print(
            "Usage:"
        )
        print(
            "  python evaluation\\live_attack_benchmark.py "
            "content_tampering"
        )
        print(
            "  python evaluation\\live_attack_benchmark.py "
            "poisoning"
        )
        print(
            "  python evaluation\\live_attack_benchmark.py "
            "deletion"
        )
        print(
            "  python evaluation\\live_attack_benchmark.py "
            "all"
        )
        return

    selected = sys.argv[1].lower()

    if selected == "all":
        attack_keys = [
            "content_tampering",
            "poisoning",
            "deletion"
        ]
    elif selected in ATTACKS:
        attack_keys = [selected]
    else:
        print(
            f"Unknown attack type: {selected}"
        )
        return

    print("=" * 70)
    print("AEGISMEM LIVE ATTACK BENCHMARK")
    print("=" * 70)

    results = []

    for attack_key in attack_keys:

        result = run_trial(
            attack_key
        )

        if result is not None:
            results.append(result)

    print()
    print("=" * 70)
    print("FINAL SUMMARY")
    print("=" * 70)

    for result in results:

        print(
            f"{result['attack_type']:<22}"
            f" action={result['action']:<10}"
            f" latency={result['latency_seconds']:.4f}s"
            f" success={result['success']}"
        )


if __name__ == "__main__":
    main()