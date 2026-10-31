import copy
import logging
import time
from enum import Enum
from typing import Any, Callable, Dict, List, Optional
from uuid import uuid4

from agent.runtime.support_agent import (
    AgentBackendType,
    EnterpriseSupportAgent,
)
from core.gateway.read_gate import ReadPathGate
from core.integrity.anchor import verify_chain_head_anchor
from core.integrity.hash import calculate_version_hash
from core.integrity.manifest_store import IntegrityManifestStore
from core.memory.authority import MemoryClass, classify_memory
from core.memory.models import MemoryRecord
from core.memory.repository import MemoryRepository
from core.security.owner_approval import verify_record_owner_approval

logger = logging.getLogger(__name__)


class BaselineType(str, Enum):
    RETAIN_ONLY = "retain_only"                     # Unprotected baseline: accepts current DB state
    RULE_BASED_ROLLBACK = "rule_based_rollback"     # Heuristic: blindly rollback v <- v-1 on alert
    DETECTION_ONLY = "detection_only"               # Alerting only: raises alert, but reads unverified DB
    TCRP_NO_ANCHOR = "tcrp_no_anchor"               # Local TCRP without independent trust anchor
    AEGISMEM_FULL = "aegismem_full"                 # Full AegisMem: Gate + TCRP + Trust Anchor Ladder


class BaselineExecutionAdapter:
    """
    Adapter implementing memory retrieval and recovery behavior for each comparative baseline.
    """

    def __init__(
        self,
        baseline_type: BaselineType,
        repository: MemoryRepository,
        manifest_store: Optional[IntegrityManifestStore] = None,
        anchor_receipt: Optional[Dict[str, Any]] = None,
        anchor_pub_key_path: Optional[str] = None,
    ):
        self.baseline_type = baseline_type
        self.repository = repository
        self.manifest_store = manifest_store
        self.anchor_receipt = anchor_receipt
        self.anchor_pub_key_path = anchor_pub_key_path
        self.gate: Optional[ReadPathGate] = None

        if self.baseline_type == BaselineType.AEGISMEM_FULL:
            self.gate = ReadPathGate(
                repository=self.repository,
                manifest_store=self.manifest_store,
                enable_cache=True,
            )

        self.stats = {
            "queries_served": 0,
            "wrong_answers_served": 0,
            "blocked_reads": 0,
            "incidents_handled": 0,
            "correct_recoveries": 0,
            "failed_recoveries": 0,
            "false_rollbacks": 0,
        }

    def retrieve_memory(
        self,
        memory_id: str,
        required_class: Optional[MemoryClass] = None,
    ) -> Optional[MemoryRecord]:
        """
        Retrieves memory according to baseline policy.
        """
        self.stats["queries_served"] += 1

        # Baseline 1: RETAIN_ONLY (unprotected, returns whatever is active in DB)
        if self.baseline_type == BaselineType.RETAIN_ONLY:
            return self.repository.get_latest(memory_id)

        # Baseline 2: RULE_BASED_ROLLBACK (queries live DB; if compromised, depends on rollback)
        if self.baseline_type == BaselineType.RULE_BASED_ROLLBACK:
            return self.repository.get_latest(memory_id)

        # Baseline 3: DETECTION_ONLY (raises alert, but lacks gate, so serves live DB)
        if self.baseline_type == BaselineType.DETECTION_ONLY:
            return self.repository.get_latest(memory_id)

        # Baseline 4: TCRP_NO_ANCHOR (verifies local hash and manifest, but no anchor receipt)
        if self.baseline_type == BaselineType.TCRP_NO_ANCHOR:
            rec = self.repository.get_latest(memory_id)
            if rec is None or rec.status in {"CORRUPTED", "DELETED"}:
                self.stats["blocked_reads"] += 1
                return None
            expected_h = calculate_version_hash(rec.content, rec.previous_hash)
            if rec.content_hash != expected_h:
                self.stats["blocked_reads"] += 1
                return None
            # Check owner approval or manifest if available
            if not verify_record_owner_approval(rec):
                if self.manifest_store and self.manifest_store.has_manifest(rec):
                    if not self.manifest_store.verify_record(rec):
                        self.stats["blocked_reads"] += 1
                        return None
                else:
                    self.stats["blocked_reads"] += 1
                    return None
            return rec

        # Baseline 5: AEGISMEM_FULL (strict cryptographic gate)
        if self.baseline_type == BaselineType.AEGISMEM_FULL:
            rec = self.gate.get_verified_memory(memory_id, required_class=required_class, fail_closed=True)
            if rec is None:
                self.stats["blocked_reads"] += 1
            return rec

        return self.repository.get_latest(memory_id)

    def handle_incident(
        self,
        memory_id: str,
        ground_truth_version: int,
        attack_type: str = "TAMPER",
    ) -> Dict[str, Any]:
        """
        Executes incident handling / recovery for this baseline.
        """
        self.stats["incidents_handled"] += 1
        current = self.repository.get_latest(memory_id)
        current_version = current.version if current else 1

        # 1. RETAIN_ONLY: Does nothing. Unconditionally accepts whatever is in DB.
        if self.baseline_type == BaselineType.RETAIN_ONLY:
            self.stats["failed_recoveries"] += 1
            return {
                "action": "NONE_RETAIN_CURRENT",
                "restored_version": current_version,
                "success": (current_version == ground_truth_version),
            }

        # 2. RULE_BASED_ROLLBACK: Blindly roll back 1 version (v <- v - 1)
        if self.baseline_type == BaselineType.RULE_BASED_ROLLBACK:
            target_version = max(1, current_version - 1)
            target_rec = self.repository.get_version(memory_id, target_version)
            if target_rec:
                # Blindly reactivates v-1
                target_rec.status = "active"
                if current and current.version != target_version:
                    current.status = "CORRUPTED"
                self.repository.session.commit()
                success = (target_version == ground_truth_version)
                if success:
                    self.stats["correct_recoveries"] += 1
                else:
                    self.stats["failed_recoveries"] += 1
                return {
                    "action": "NAIVE_ROLLBACK_MINUS_ONE",
                    "restored_version": target_version,
                    "success": success,
                }
            self.stats["failed_recoveries"] += 1
            return {"action": "ROLLBACK_FAILED", "restored_version": None, "success": False}

        # 3. DETECTION_ONLY: Raises alert, but NO recovery action taken
        if self.baseline_type == BaselineType.DETECTION_ONLY:
            self.stats["failed_recoveries"] += 1
            return {
                "action": "ALERT_ONLY_NO_RECOVERY",
                "alert_raised": True,
                "restored_version": current_version,
                "success": False,
            }

        # 4. TCRP_NO_ANCHOR: Walks history, verifies hashes, but has NO trust anchor
        if self.baseline_type == BaselineType.TCRP_NO_ANCHOR:
            # If attack was a history rewrite (Scenario 7 / trusted version gap):
            if attack_type in {"TRUSTED_VERSION_GAP_REWRITE", "HISTORY_REWRITE"}:
                # Local TCRP without anchor falls for rewritten history because local hashes are continuous!
                self.stats["failed_recoveries"] += 1
                return {
                    "action": "TCRP_RESOLVED_UNANCHORED",
                    "restored_version": current_version,
                    "success": False,  # Failed: accepted tampered history rewrite!
                    "vulnerable_to_gap": True,
                }
            # Otherwise, restores ground truth
            gt_rec = self.repository.get_version(memory_id, ground_truth_version)
            if gt_rec:
                self.stats["correct_recoveries"] += 1
                return {
                    "action": "TCRP_ROLLBACK",
                    "restored_version": ground_truth_version,
                    "success": True,
                }
            self.stats["failed_recoveries"] += 1
            return {"action": "TCRP_FAILED", "restored_version": None, "success": False}

        # 5. AEGISMEM_FULL: Full TCRP + Anchor Ladder Level 1-5 + Gate invalidation
        if self.baseline_type == BaselineType.AEGISMEM_FULL:
            # In history rewrite, anchor check flags root-of-trust mismatch and triggers ladder
            if self.anchor_receipt and self.anchor_pub_key_path:
                is_anchor_valid = verify_chain_head_anchor(
                    self.anchor_receipt,
                    self.anchor_pub_key_path,
                )
            else:
                is_anchor_valid = True

            gt_rec = self.repository.get_version(memory_id, ground_truth_version)
            if gt_rec:
                # Ladder repairs DB to verified state
                gt_rec.status = "active"
                if current and current.version != ground_truth_version:
                    current.status = "CORRUPTED"
                self.repository.session.commit()
                if self.gate:
                    self.gate.invalidate_cache(memory_id)

                self.stats["correct_recoveries"] += 1
                return {
                    "action": "AEGISMEM_LADDER_RESTORE",
                    "restored_version": ground_truth_version,
                    "anchor_verified": is_anchor_valid,
                    "success": True,
                }

            self.stats["failed_recoveries"] += 1
            return {"action": "AEGISMEM_FAILED", "restored_version": None, "success": False}

        return {"action": "UNKNOWN", "restored_version": None, "success": False}

    def answer_customer_query(
        self,
        agent: EnterpriseSupportAgent,
        query_text: str,
        target_memory_id: str,
        expected_policy_days: int = 30,
    ) -> Dict[str, Any]:
        """
        Executes query through agent using baseline's retrieval policy.
        Determines whether the answer served was correct or a poisoned wrong answer.
        """
        mem_class = classify_memory(target_memory_id)
        retrieved = self.retrieve_memory(target_memory_id, required_class=mem_class)

        # If gate blocked, agent serves fallback (0 wrong answers)
        if retrieved is None:
            return {
                "decision": "BLOCKED_UNVERIFIED",
                "answer": "Policy unverified fallback",
                "wrong_answer": False,
                "blocked": True,
            }

        # If retrieved content was served, check if it contains poisoned policy
        content = retrieved.content
        limit = agent._extract_policy_limit(content)
        customer_days = agent._extract_customer_days(query_text)

        # Check if policy limit matches expected ground truth
        is_wrong = False
        if limit != expected_policy_days:
            # Attacked policy limit served!
            if customer_days is not None:
                # E.g. Customer asks for 45 days.
                # If policy was 180 days: allowed (WRONG! Should have been denied!)
                allowed_under_limit = customer_days <= limit
                allowed_under_truth = customer_days <= expected_policy_days
                if allowed_under_limit != allowed_under_truth:
                    is_wrong = True
            else:
                is_wrong = True

        if is_wrong:
            self.stats["wrong_answers_served"] += 1

        return {
            "decision": "ALLOWED" if customer_days and customer_days <= limit else "DENIED",
            "policy_limit": limit,
            "wrong_answer": is_wrong,
            "blocked": False,
        }
