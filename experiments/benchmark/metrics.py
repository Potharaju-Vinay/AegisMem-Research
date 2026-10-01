from dataclasses import dataclass


@dataclass(frozen=True)
class RecoveryMetrics:
    true_positive: int
    false_positive: int
    false_negative: int
    true_negative: int
    precision: float
    recall: float
    f1_score: float
    unnecessary_recovery: float
    residual_contamination: float
    unnecessary_recovery_count: int
    residual_contamination_count: int
    recovery_cost: int


def calculate_recovery_metrics(
    recovered_memory_ids,
    contaminated_memory_ids,
    all_memory_ids
):
    recovered_memory_ids = set(recovered_memory_ids)
    contaminated_memory_ids = set(contaminated_memory_ids)
    all_memory_ids = set(all_memory_ids)

    true_positive = len(
        recovered_memory_ids & contaminated_memory_ids
    )

    false_positive = len(
        recovered_memory_ids - contaminated_memory_ids
    )

    false_negative = len(
        contaminated_memory_ids - recovered_memory_ids
    )

    true_negative = len(
        all_memory_ids
        - recovered_memory_ids
        - contaminated_memory_ids
    )

    precision = (
        true_positive / (true_positive + false_positive)
        if true_positive + false_positive > 0
        else 0.0
    )

    recall = (
        true_positive / (true_positive + false_negative)
        if true_positive + false_negative > 0
        else 0.0
    )

    f1_score = (
        2 * precision * recall / (precision + recall)
        if precision + recall > 0
        else 0.0
    )

    unnecessary_recovery_count = false_positive

    residual_contamination_count = false_negative

    unnecessary_recovery = (
        false_positive / len(all_memory_ids)
        if all_memory_ids
        else 0.0
    )

    residual_contamination = (
        false_negative / len(contaminated_memory_ids)
        if contaminated_memory_ids
        else 0.0
    )

    recovery_cost = len(recovered_memory_ids)

    return RecoveryMetrics(
        true_positive=true_positive,
        false_positive=false_positive,
        false_negative=false_negative,
        true_negative=true_negative,
        precision=round(precision, 6),
        recall=round(recall, 6),
        f1_score=round(f1_score, 6),
        unnecessary_recovery=round(
            unnecessary_recovery,
            6
        ),
        residual_contamination=round(
            residual_contamination,
            6
        ),
        unnecessary_recovery_count=unnecessary_recovery_count,
        residual_contamination_count=residual_contamination_count,
        recovery_cost=recovery_cost
    )


def print_metrics(metrics: RecoveryMetrics):
    print()
    print("=" * 50)
    print("RECOVERY METRICS")
    print("=" * 50)

    print(f"True Positive              : {metrics.true_positive}")
    print(f"False Positive             : {metrics.false_positive}")
    print(f"False Negative             : {metrics.false_negative}")
    print(f"True Negative              : {metrics.true_negative}")
    print(f"Precision                  : {metrics.precision:.4f}")
    print(f"Recall                     : {metrics.recall:.4f}")
    print(f"F1 Score                   : {metrics.f1_score:.4f}")
    print(
        f"Unnecessary Recovery      : "
        f"{metrics.unnecessary_recovery:.4f}"
    )
    print(
        f"Residual Contamination    : "
        f"{metrics.residual_contamination:.4f}"
    )
    print(
        f"Unnecessary Recovery Count: "
        f"{metrics.unnecessary_recovery_count}"
    )
    print(
        f"Residual Contamination Count: "
        f"{metrics.residual_contamination_count}"
    )
    print(f"Recovery Cost             : {metrics.recovery_cost}")