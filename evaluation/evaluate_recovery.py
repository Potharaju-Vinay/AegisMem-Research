import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.memory.database import get_session
from attack_lab.models import AttackEvent
from core.recovery.audit import RecoveryEvent


def evaluate():
    session = get_session()

    try:
        attacks = (
            session.query(AttackEvent)
            .order_by(AttackEvent.attack_time.asc())
            .all()
        )

        print()
        print("=" * 110)
        print("AEGISMEM RECOVERY EVALUATION")
        print("=" * 110)

        measured = []
        unmeasured = []

        for attack in attacks:
            recovery = (
                session.query(RecoveryEvent)
                .filter(
                    RecoveryEvent.memory_id == attack.memory_id,
                    RecoveryEvent.compromised_version == attack.target_version,
                    RecoveryEvent.event_type == "RECOVERY",
                    RecoveryEvent.created_at >= attack.attack_time
                )
                .order_by(RecoveryEvent.created_at.asc())
                .first()
            )

            if recovery is None:
                unmeasured.append(attack)
                continue

            latency = (
                recovery.created_at - attack.attack_time
            ).total_seconds()

            measured.append({
                "attack_id": attack.attack_id,
                "attack_type": attack.attack_type,
                "original_version": attack.original_version,
                "compromised_version": attack.target_version,
                "restored_version": recovery.restored_version,
                "action": recovery.action,
                "latency_seconds": latency,
                "validation": recovery.validation_result,
                "status": recovery.status
            })

        print()
        print("MEASURED TRIALS")
        print("-" * 110)

        for item in measured:
            print(
                f"{item['attack_id']:<18}"
                f"{item['attack_type']:<35}"
                f"v{item['compromised_version']} -> v{item['restored_version']:<5}"
                f"{item['action']:<12}"
                f"{item['latency_seconds']:.3f}s   "
                f"{item['validation']}"
            )

        print()
        print("SUMMARY")
        print("-" * 110)

        total = len(measured)

        if total:
            successful = sum(
                1
                for item in measured
                if item["validation"] == "PASS"
                and item["status"] == "success"
            )

            latencies = [
                item["latency_seconds"]
                for item in measured
            ]

            print(f"Measured trials       : {total}")
            print(f"Successful recoveries : {successful}")
            print(
                f"Recovery success rate : "
                f"{(successful / total) * 100:.2f}%"
            )
            print(
                f"Mean latency          : "
                f"{sum(latencies) / len(latencies):.3f}s"
            )
            print(
                f"Minimum latency       : "
                f"{min(latencies):.3f}s"
            )
            print(
                f"Maximum latency       : "
                f"{max(latencies):.3f}s"
            )

        print()
        print("UNMEASURED HISTORICAL ATTACKS")
        print("-" * 110)

        for attack in unmeasured:
            print(
                f"{attack.attack_id:<18}"
                f"{attack.attack_type:<35}"
                f"v{attack.target_version}"
            )

        print()
        print(
            "Unmeasured attacks are excluded from quantitative "
            "recovery metrics because they lack structured recovery evidence."
        )
        print("=" * 110)

    finally:
        session.close()


if __name__ == "__main__":
    evaluate()