import csv
from pathlib import Path
from collections import Counter


def main():
    path = (
        Path(__file__).resolve().parent
        / "tcrp_parameter_results.csv"
    )

    with path.open(
        newline="",
        encoding="utf-8"
    ) as file:
        rows = list(csv.DictReader(file))

    actions = Counter(
        row["selected_action"]
        for row in rows
    )

    compromised = [
        row
        for row in rows
        if row["detected_compromise"] == "True"
    ]

    clean = [
        row
        for row in rows
        if row["detected_compromise"] == "False"
    ]

    compromised_actions = Counter(
        row["selected_action"]
        for row in compromised
    )

    clean_actions = Counter(
        row["selected_action"]
        for row in clean
    )

    regrets = [
        float(row["cost_regret"])
        for row in rows
        if row["cost_regret"] != ""
    ]

    print("=" * 60)
    print("TCRP PARAMETER-SWEEP ANALYSIS")
    print("=" * 60)

    print(f"Total scenarios: {len(rows)}")

    print("\nOverall action distribution:")
    for action, count in actions.items():
        print(
            f"{action:<12} "
            f"{count:>4} "
            f"({count / len(rows):.2%})"
        )

    print("\nClean-memory actions:")
    for action, count in clean_actions.items():
        print(
            f"{action:<12} "
            f"{count:>4} "
            f"({count / len(clean):.2%})"
        )

    print("\nCompromised-memory actions:")
    for action, count in compromised_actions.items():
        print(
            f"{action:<12} "
            f"{count:>4} "
            f"({count / len(compromised):.2%})"
        )

    print("\nCost regret:")
    print(
        f"Mean: "
        f"{sum(regrets) / len(regrets):.6f}"
    )

    print(
        f"Maximum: "
        f"{max(regrets):.6f}"
    )

    zero_regret = sum(
        regret == 0.0
        for regret in regrets
    )

    print(
        f"Zero-regret scenarios: "
        f"{zero_regret}/{len(regrets)} "
        f"({zero_regret / len(regrets):.2%})"
    )


if __name__ == "__main__":
    main()