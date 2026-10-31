import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from agent.runtime.support_agent import EnterpriseSupportAgent
from domain.customer_support.dataset import BenchmarkQuery, generate_benchmark_queries


class DomainBenchmarkEvaluator:
    """
    Evaluates enterprise customer support agent accuracy and security compliance
    across the standard 300+ query benchmark dataset.
    """

    def __init__(self, agent: EnterpriseSupportAgent, queries: Optional[List[BenchmarkQuery]] = None):
        self.agent = agent
        self.queries = queries or generate_benchmark_queries(330)

    def evaluate(self) -> Dict[str, Any]:
        total = len(self.queries)
        correct = 0
        gate_blocked = 0
        wrong_answers = 0

        details = []
        for q in self.queries:
            resp = self.agent.answer_query(q.query_text, q.target_memory_id)

            is_correct = False
            if resp.get("gate_verified"):
                # Check decision match
                decision_match = (q.expected_decision == "FACTUAL") or (resp.get("decision") == q.expected_decision)
                # Check keyword presence
                kw_match = q.expected_answer_keyword.lower() in resp.get("answer", "").lower()

                if decision_match and kw_match:
                    is_correct = True
                    correct += 1
                else:
                    wrong_answers += 1
            else:
                gate_blocked += 1

            details.append({
                "query_id": q.query_id,
                "intent": q.intent,
                "query": q.query_text,
                "target_memory_id": q.target_memory_id,
                "expected_decision": q.expected_decision,
                "actual_decision": resp.get("decision"),
                "expected_keyword": q.expected_answer_keyword,
                "is_correct": is_correct,
                "gate_verified": resp.get("gate_verified", False),
            })

        accuracy_percent = round((correct / total) * 100.0, 2) if total > 0 else 0.0

        report = {
            "total_queries": total,
            "correct_answers": correct,
            "wrong_answers": wrong_answers,
            "gate_blocked": gate_blocked,
            "accuracy_percent": accuracy_percent,
            "backend": self.agent.backend_type.value,
            "sample_details": details[:10],
        }

        return report

    def export_report(self, destination: Path | str = "data/domain_evaluation_results.json") -> Path:
        path = Path(destination)
        path.parent.mkdir(parents=True, exist_ok=True)
        report = self.evaluate()
        path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        return path
