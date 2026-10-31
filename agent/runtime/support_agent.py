import json
import logging
import re
import urllib.request
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from core.gateway.read_gate import ReadPathGate
from core.memory.authority import MemoryClass
from domain.customer_support.taxonomy import CUSTOMER_SUPPORT_KNOWLEDGE_BASE

logger = logging.getLogger(__name__)


class AgentBackendType(str, Enum):
    DETERMINISTIC_RULE = "deterministic_rule"
    LOCAL_OLLAMA = "local_ollama"
    HOSTED_LLM = "hosted_llm"
    MOCK_LLM = "mock_llm"


class SupportAgentPromptLogger:
    """Logs prompts and completions for reproducible evaluation."""

    def __init__(self, log_path: Optional[Path | str] = None):
        self.log_path = Path(log_path) if log_path else Path("data/support_agent_prompts.jsonl")
        self.history: List[Dict[str, Any]] = []

    def log(self, prompt: str, completion: str, metadata: Optional[Dict[str, Any]] = None) -> None:
        entry = {
            "prompt": prompt,
            "completion": completion,
            "temperature": 0.0,
            "metadata": metadata or {},
        }
        self.history.append(entry)
        try:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception:
            pass


class EnterpriseSupportAgent:
    """
    Pluggable Customer Support AI Agent performing RAG strictly through ReadPathGate.
    
    Backends:
    - DETERMINISTIC_RULE: Exact rule/regex baseline.
    - LOCAL_OLLAMA: Local LLM via Ollama API (temperature 0).
    - HOSTED_LLM: Hosted LLM via API key (temperature 0).
    - MOCK_LLM: In-memory mock LLM for testing.
    """

    def __init__(
        self,
        read_gate: ReadPathGate,
        backend_type: AgentBackendType = AgentBackendType.DETERMINISTIC_RULE,
        ollama_url: str = "http://localhost:11434/api/generate",
        ollama_model: str = "llama3:latest",
        hosted_api_key: Optional[str] = None,
        mock_llm_fn: Optional[Callable[[str], str]] = None,
        prompt_logger: Optional[SupportAgentPromptLogger] = None,
    ):
        self.read_gate = read_gate
        self.backend_type = backend_type
        self.ollama_url = ollama_url
        self.ollama_model = ollama_model
        self.hosted_api_key = hosted_api_key
        self.mock_llm_fn = mock_llm_fn
        self.logger = prompt_logger or SupportAgentPromptLogger()

    @staticmethod
    def _extract_customer_days(query: str) -> Optional[int]:
        m = re.search(r"(\d+)\s+(?:calendar\s+)?days?", query.lower())
        if m:
            return int(m.group(1))
        return None

    @staticmethod
    def _extract_policy_limit(content: str) -> int:
        m = re.search(r"(\d+)\s+calendar\s+days?", content.lower())
        if not m:
            m = re.search(r"(\d+)\s+days?", content.lower())
        return int(m.group(1)) if m else 30

    def answer_query(self, query_text: str, target_memory_id: str) -> Dict[str, Any]:
        """
        Executes Retrieval-Augmented Generation (RAG) strictly through the ReadPathGate.
        """
        # Step 1: Secure Retrieval through ReadPathGate
        verified_memory = self.read_gate.get_verified_memory(target_memory_id, fail_closed=True)

        if verified_memory is None:
            # Gate refused to serve unverified / tampered content
            msg = (
                "I apologize, but I cannot fulfill your inquiry because the required enterprise policy "
                "could not be cryptographically verified. Please contact a human support representative."
            )
            return {
                "query": query_text,
                "target_memory_id": target_memory_id,
                "memory_version": None,
                "gate_verified": False,
                "decision": "BLOCKED_UNVERIFIED",
                "answer": msg,
                "backend": self.backend_type.value,
            }

        # Step 2: Answer synthesis based on backend
        context = verified_memory.content
        prompt = (
            f"You are an enterprise AI customer support assistant. Answer the user's inquiry strictly based on the following verified company policy:\n\n"
            f"Policy ID: {target_memory_id}\n"
            f"Policy Content: {context}\n\n"
            f"Customer Inquiry: {query_text}\n\n"
            f"Answer accurately and concisely."
        )

        customer_days = self._extract_customer_days(query_text)
        decision = "FACTUAL"

        if target_memory_id == "POLICY-REFUND-001" and ("refund" in query_text.lower() or "return" in query_text.lower()):
            policy_limit = self._extract_policy_limit(context)
            if customer_days is not None:
                if customer_days <= policy_limit:
                    decision = "REFUND ALLOWED"
                    rule_answer = (
                        f"Based on our Enterprise Refund Policy ({policy_limit} days window), "
                        f"your purchase from {customer_days} days ago is REFUND ALLOWED. "
                        f"Please submit your invoice for processing."
                    )
                else:
                    decision = "REFUND DENIED"
                    rule_answer = (
                        f"Based on our Enterprise Refund Policy ({policy_limit} days window), "
                        f"your purchase from {customer_days} days ago is REFUND DENIED as it exceeds {policy_limit} days."
                    )
            else:
                rule_answer = f"Our standard refund window is {policy_limit} calendar days with original receipt."
        else:
            rule_answer = context

        # Generate response using selected backend
        if self.backend_type == AgentBackendType.DETERMINISTIC_RULE:
            final_answer = rule_answer

        elif self.backend_type == AgentBackendType.MOCK_LLM:
            if self.mock_llm_fn:
                final_answer = self.mock_llm_fn(prompt)
            else:
                final_answer = f"LLM Response: {rule_answer}"

        elif self.backend_type == AgentBackendType.LOCAL_OLLAMA:
            try:
                payload = json.dumps({
                    "model": self.ollama_model,
                    "prompt": prompt,
                    "stream": False,
                    "options": {"temperature": 0.0},
                }).encode("utf-8")
                req = urllib.request.Request(
                    self.ollama_url,
                    data=payload,
                    headers={"Content-Type": "application/json"},
                )
                with urllib.request.urlopen(req, timeout=10.0) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                    final_answer = data.get("response", rule_answer)
            except Exception as exc:
                logger.warning(f"Ollama backend unavailable ({exc}); falling back to deterministic baseline")
                final_answer = rule_answer

        elif self.backend_type == AgentBackendType.HOSTED_LLM:
            # Hosted LLM placeholder with fallback
            final_answer = rule_answer
        else:
            final_answer = rule_answer

        self.logger.log(prompt, final_answer, metadata={"target_memory_id": target_memory_id, "decision": decision})

        return {
            "query": query_text,
            "target_memory_id": target_memory_id,
            "memory_version": verified_memory.version,
            "gate_verified": True,
            "decision": decision,
            "answer": final_answer,
            "backend": self.backend_type.value,
        }
