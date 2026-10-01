import matplotlib

matplotlib.use("Agg")

import pandas as pd
import matplotlib.pyplot as plt
from pathlib import Path


BASE = Path(__file__).resolve().parent
BENCHMARK = BASE / "benchmark"
FIGURES = BASE / "figures"

FIGURES.mkdir(exist_ok=True)


# ============================================================
# 1. LIVE ATTACK RECOVERY LATENCY
# ============================================================

live_data = pd.DataFrame([
    {
        "attack_type": "Content tampering",
        "latency": 1.8243
    },
    {
        "attack_type": "Memory poisoning",
        "latency": 1.9295
    },
    {
        "attack_type": "Memory deletion",
        "latency": 1.7620
    }
])

plt.figure(figsize=(8, 5))

plt.bar(
    live_data["attack_type"],
    live_data["latency"]
)

plt.ylabel("Attack-to-validated-recovery latency (s)")
plt.xlabel("Attack type")
plt.title("Live Attack Recovery Latency")

plt.tight_layout()

plt.savefig(
    FIGURES / "live_recovery_latency.png",
    dpi=300,
    bbox_inches="tight"
)

plt.close()


# ============================================================
# 2. ABLATION — UNSAFE RETENTION
# ============================================================

ablation_data = pd.DataFrame([
    {
        "method": "Retain-only",
        "unsafe_retention": 100.0
    },
    {
        "method": "Rule-based",
        "unsafe_retention": 0.0
    },
    {
        "method": "TCRP",
        "unsafe_retention": 0.0
    }
])

plt.figure(figsize=(8, 5))

plt.bar(
    ablation_data["method"],
    ablation_data["unsafe_retention"]
)

plt.ylabel("Unsafe retention (%)")
plt.xlabel("Recovery strategy")
plt.title("Ablation Study: Unsafe Retention")

plt.ylim(0, 110)

plt.tight_layout()

plt.savefig(
    FIGURES / "ablation_unsafe_retention.png",
    dpi=300,
    bbox_inches="tight"
)

plt.close()


# ============================================================
# 3. TCRP ACTION DISTRIBUTION
# ============================================================

action_data = pd.DataFrame([
    {
        "action": "RETAIN",
        "count": 72
    },
    {
        "action": "ROLLBACK",
        "count": 489
    },
    {
        "action": "QUARANTINE",
        "count": 789
    }
])

plt.figure(figsize=(8, 5))

plt.bar(
    action_data["action"],
    action_data["count"]
)

plt.ylabel("Number of scenarios")
plt.xlabel("TCRP action")
plt.title("TCRP Action Distribution Across 1,350 Scenarios")

plt.tight_layout()

plt.savefig(
    FIGURES / "tcrp_action_distribution.png",
    dpi=300,
    bbox_inches="tight"
)

plt.close()


# ============================================================
# 4. TCRP WEIGHT SENSITIVITY
# ============================================================

sensitivity_path = (
    BENCHMARK
    / "tcrp_weight_sensitivity_results.csv"
)

sensitivity = pd.read_csv(sensitivity_path)

plt.figure(figsize=(10, 5.5))

plt.plot(
    sensitivity["configuration"],
    sensitivity["retain_pct"],
    marker="o",
    label="RETAIN"
)

plt.plot(
    sensitivity["configuration"],
    sensitivity["rollback_pct"],
    marker="o",
    label="ROLLBACK"
)

plt.plot(
    sensitivity["configuration"],
    sensitivity["quarantine_pct"],
    marker="o",
    label="QUARANTINE"
)

plt.ylabel("Scenario proportion (%)")
plt.xlabel("Weight configuration")
plt.title("TCRP Weight Sensitivity")

plt.xticks(
    rotation=20,
    ha="right"
)

plt.ylim(0, 70)

plt.legend()

plt.tight_layout()

plt.savefig(
    FIGURES / "tcrp_weight_sensitivity.png",
    dpi=300,
    bbox_inches="tight"
)

plt.close()


# ============================================================
# COMPLETE
# ============================================================

print("=" * 70)
print("AEGISMEM FIGURE GENERATION")
print("=" * 70)

for filename in [
    "live_recovery_latency.png",
    "ablation_unsafe_retention.png",
    "tcrp_action_distribution.png",
    "tcrp_weight_sensitivity.png"
]:

    path = FIGURES / filename

    print(
        f"{filename:<40} "
        f"{path.stat().st_size:,} bytes"
    )

print("=" * 70)
print("ALL FIGURES GENERATED SUCCESSFULLY")
print("=" * 70)