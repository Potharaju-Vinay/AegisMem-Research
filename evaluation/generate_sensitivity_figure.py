import matplotlib

matplotlib.use("Agg")

import pandas as pd
import matplotlib.pyplot as plt
from pathlib import Path


base = Path(__file__).resolve().parent

csv_path = (
    base
    / "benchmark"
    / "tcrp_weight_sensitivity_results.csv"
)

output_dir = base / "figures"
output_dir.mkdir(exist_ok=True)

df = pd.read_csv(csv_path)

configurations = df["configuration"]

plt.figure(figsize=(9, 5))

plt.plot(
    configurations,
    df["retain_pct"],
    marker="o",
    label="RETAIN"
)

plt.plot(
    configurations,
    df["rollback_pct"],
    marker="o",
    label="ROLLBACK"
)

plt.plot(
    configurations,
    df["quarantine_pct"],
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

output_path = (
    output_dir
    / "tcrp_weight_sensitivity.png"
)

plt.savefig(
    output_path,
    dpi=300,
    bbox_inches="tight"
)

plt.close()

print(f"Figure saved to: {output_path}")