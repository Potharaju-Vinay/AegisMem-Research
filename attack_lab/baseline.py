from dataclasses import dataclass


@dataclass
class PropagationComparison:
    baseline_impact: float
    aegismem_impact: float
    improvement: float


class PropagationBaseline:

    def compare(
        self,
        baseline_result,
        aegismem_result
    ) -> PropagationComparison:

        baseline_impact = round(
            sum(
                state.impact_score
                for state in baseline_result.values()
            ),
            10
        )

        aegismem_impact = round(
            sum(
                state.impact_score
                for state in aegismem_result.values()
            ),
            10
        )

        improvement = round(
            baseline_impact - aegismem_impact,
            10
        )

        return PropagationComparison(
            baseline_impact=baseline_impact,
            aegismem_impact=aegismem_impact,
            improvement=improvement
        )
