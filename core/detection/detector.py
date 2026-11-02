from sqlalchemy import select

from core.integrity.hash import calculate_version_hash
from core.integrity.manifest_store import IntegrityManifestStore
from core.memory.models import MemoryRecord
from core.memory.repository import MemoryRepository
from core.provenance.models import ProvenanceEvent
from core.security.owner_approval import verify_record_owner_approval

from attack_lab.models import AttackEvent

from core.detection.models import (
    DetectionEvidence,
    DetectionResult
)


class MemoryCompromiseDetector:

    def __init__(
        self,
        repository: MemoryRepository,
        dependency_graph=None,
        manifest_store=None
    ):

        self.repository = repository
        self.session = repository.session
        self.dependency_graph = dependency_graph
        self.manifest_store = manifest_store

    # ==================================================
    # ATTACK EVENT EVIDENCE
    # ==================================================

    def _has_attack_evidence(
    self,
    memory: MemoryRecord
) -> bool:

        statement = (
        select(AttackEvent)
        .where(
            AttackEvent.memory_id == memory.memory_id,
            AttackEvent.target_version == memory.version
        )
        .limit(1)
    )

        event = self.session.scalars(
        statement
    ).first()

        return event is not None

        # ==================================================
    # PROVENANCE EVIDENCE
    # ==================================================

    def _has_provenance_evidence(
        self,
        memory: MemoryRecord
    ) -> bool:

        statement = (
            select(ProvenanceEvent)
            .where(
                ProvenanceEvent.memory_id == memory.memory_id,
                ProvenanceEvent.version == memory.version
            )
            .order_by(
                ProvenanceEvent.id.desc()
            )
            .limit(1)
        )

        event = self.session.scalars(
            statement
        ).first()

        if event is None:
            return False

        suspicious_operations = {
            "MEMORY_POISON",
            "MEMORY_MODIFY",
            "MEMORY_TAMPER"
        }

        suspicious_sources = {
            "external_attack",
            "external_memory_write",
            "prompt_injection_attack",
            "memory_poisoning"
        }

        operation_suspicious = (
            event.operation.upper()
            in suspicious_operations
        )

        source_suspicious = (
            event.source
            in suspicious_sources
            or event.source_type
            in suspicious_sources
        )

        actor_suspicious = (
            str(event.actor).lower()
            in {
                "kali-attacker",
                "controlled_kali_lab",
                "research-attacker",
                "aegismem-attacker",
                "adversary",
                "unknown",
            }
            or "attacker" in str(event.actor).lower()
            or "adversary" in str(event.actor).lower()
        )

        # Milestone M2: Cryptographic Signature Verification for Owner Provenance
        # If the provenance event claims to be an authorized owner write, but the
        # Ed25519 signature fails verification, flag as suspicious signature forgery.
        signature_spoofed = (
            str(event.actor).lower() in {"enterprise_owner", "owner", "admin"}
            and not verify_record_owner_approval(memory)
        )

        return (
            operation_suspicious
            or source_suspicious
            or actor_suspicious
            or signature_spoofed
        )

    def _content_change_evidence(
        self,
        memory: MemoryRecord
    ) -> tuple[bool, bool, list]:

        history = self.repository.get_history(
            memory.memory_id
        )

        previous = None

        for record in history:
            if record.version == memory.version - 1:
                previous = record
                break

        if previous is None:
            return False, False, []

        content_changed = (
            previous.content != memory.content
        )

        if not content_changed:
            return False, False, []

        import re

        previous_numbers = [
            float(value)
            for value in re.findall(
                r"\d+(?:\.\d+)?",
                previous.content
            )
        ]

        current_numbers = [
            float(value)
            for value in re.findall(
                r"\d+(?:\.\d+)?",
                memory.content
            )
        ]

        numeric_changes = []

        for previous_value, current_value in zip(
            previous_numbers,
            current_numbers
        ):
            if previous_value != current_value:
                numeric_changes.append(
                    {
                        "previous": previous_value,
                        "current": current_value,
                        "delta": current_value - previous_value
                    }
                )

        return (
            True,
            bool(numeric_changes),
            numeric_changes
        )

        # ==================================================
    # DIRECT COMPROMISE EVIDENCE
    # ==================================================

    def _has_direct_compromise_evidence(
        self,
        memory: MemoryRecord
    ) -> bool:
        """
        Determine whether the memory itself has direct
        compromise evidence.

        Dependency exposure is deliberately excluded here
        so that direct evidence and dependency-derived
        evidence remain separate.
        """

        return (
            self._has_attack_evidence(memory)
            or self._has_provenance_evidence(memory)
            or memory.status.upper() in {"CORRUPTED", "DELETED"}
            or float(memory.suspicion_score) >= 0.50
        )

    # ==================================================
    # DEPENDENCY-DERIVED EXPOSURE
    # ==================================================

    # ==================================================
    # DIRECT COMPROMISE EVIDENCE
    # ==================================================

    def _has_direct_compromise_evidence(
        self,
        memory: MemoryRecord
    ) -> bool:
        """
        Determine whether the memory itself has direct
        compromise evidence.

        Dependency exposure is deliberately excluded here
        so that direct evidence and dependency-derived
        evidence remain separate.
        """

        return (
            self._has_attack_evidence(memory)
            or self._has_provenance_evidence(memory)
            or memory.status.upper() in {"CORRUPTED", "DELETED"}
            or float(memory.suspicion_score) >= 0.50
        )

    # ==================================================
    # DEPENDENCY-DERIVED EXPOSURE
    # ==================================================

    def _dependency_exposure(
        self,
        memory_id: str
    ) -> float:
        """
        Calculate the strongest dependency exposure from
        any directly compromised upstream ancestor.

        For a path:

            A -> B -> C

        with strengths:

            A->B = 0.90
            B->C = 0.80

        exposure to C is:

            0.90 * 0.80 = 0.72
        """

        if self.dependency_graph is None:
            return 0.0

        graph = self.dependency_graph.graph

        if memory_id not in graph:
            return 0.0

        # --------------------------------------------------
        # Find ALL upstream ancestors.
        # --------------------------------------------------

        try:

            networkx_module = __import__(
                "networkx"
            )

            ancestors = list(
                networkx_module.ancestors(
                    graph,
                    memory_id
                )
            )

        except Exception:

            return 0.0

        compromised_ancestors = []

        # --------------------------------------------------
        # Identify ancestors that have DIRECT evidence.
        # --------------------------------------------------

        for ancestor_id in ancestors:

            ancestor_memory = (
                self.repository.get_latest(
                    ancestor_id
                )
            )

            if ancestor_memory is None:
                continue

            if self._has_direct_compromise_evidence(
                ancestor_memory
            ):

                compromised_ancestors.append(
                    ancestor_id
                )

        if not compromised_ancestors:
            return 0.0

        # --------------------------------------------------
        # Calculate exposure across every path.
        # --------------------------------------------------

        exposures = []

        for ancestor_id in compromised_ancestors:

            try:

                paths = (
                    networkx_module.all_simple_paths(
                        graph,
                        ancestor_id,
                        memory_id
                    )
                )

            except Exception:

                paths = []

            for path in paths:

                exposure = 1.0

                for source, target in zip(
                    path,
                    path[1:]
                ):

                    strength = (
                        self.dependency_graph
                        .edge_strength(
                            source,
                            target
                        )
                    )

                    exposure *= strength

                exposures.append(
                    exposure
                )

        if not exposures:
            return 0.0

        return round(
            min(
                max(exposures),
                1.0
            ),
            12
        )

    # ==================================================
    # DETECTION
    # ==================================================

    def detect(
        self,
        memory_id: str
    ) -> DetectionResult:

        memory = self.repository.get_latest(
            memory_id
        )

        if memory is None:
            raise ValueError(
                f"Memory '{memory_id}' not found."
            )

        # --------------------------------------------------
        # 1. Integrity evidence
        # --------------------------------------------------

        expected_hash = calculate_version_hash(
            memory.content,
            memory.previous_hash
        )

        content_hash_valid = expected_hash == memory.content_hash
        integrity_compromised = not content_hash_valid

        integrity_anchor_status = "UNANCHORED"

        if self.manifest_store is not None:
            manifest_present = self.manifest_store.has_manifest(memory)

            if manifest_present:
                manifest_valid = self.manifest_store.verify_record(memory)

                if not content_hash_valid or not manifest_valid:
                    integrity_anchor_status = "TAMPERED"
                    integrity_compromised = True
                else:
                    integrity_anchor_status = "VALID"
            else:
                integrity_anchor_status = "UNANCHORED"

        # --------------------------------------------------
        # 2. Status evidence
        # --------------------------------------------------

        status_corrupted = (
            memory.status.upper()
            in {"CORRUPTED", "DELETED"}
        )

        # --------------------------------------------------
        # 3. Stored local suspicion
        # --------------------------------------------------

        suspicion_score = float(
            memory.suspicion_score
        )
        
        content_changed, numeric_change_detected, numeric_changes = (
            self._content_change_evidence(memory)
        )

        # --------------------------------------------------
        # 4. AttackEvent evidence
        # --------------------------------------------------

        attack_detected = (
            self._has_attack_evidence(
                memory
            )
        )

        # --------------------------------------------------
        # 5. Provenance evidence
        # --------------------------------------------------

        provenance_suspicious = (
            self._has_provenance_evidence(
                memory
            )
        )

        # --------------------------------------------------
        # 6. Dependency-derived exposure
        # --------------------------------------------------

        dependency_exposure = (
            self._dependency_exposure(
                memory_id
            )
        )

        dependency_contamination = (
            dependency_exposure > 0.0
        )
        
        authorization_valid = verify_record_owner_approval(memory)
        # --------------------------------------------------
        # Evidence object
        # --------------------------------------------------

        evidence = DetectionEvidence(
            authorization_valid=authorization_valid,
            integrity_compromised=integrity_compromised,
            provenance_suspicious=provenance_suspicious,
            attack_detected=attack_detected,
            status_corrupted=status_corrupted,
            suspicion_score=suspicion_score,
            dependency_exposure=dependency_exposure,
            dependency_contamination=dependency_contamination,
            content_changed=content_changed,
            numeric_change_detected=numeric_change_detected,
            numeric_changes=numeric_changes,
            integrity_anchor_status=integrity_anchor_status
        )

        # --------------------------------------------------
        # Evidence aggregation
        # --------------------------------------------------

        independent_evidence = sum(
            [
                integrity_compromised,
                provenance_suspicious,
                attack_detected,
                status_corrupted,
                suspicion_score >= 0.50,
                not (authorization_valid or integrity_anchor_status == "VALID"),
                numeric_change_detected,
            ]
        )

        compromised = (
            independent_evidence >= 2
            or provenance_suspicious
            or not (authorization_valid or integrity_anchor_status == "VALID")
            or integrity_compromised
        )

        dependency_exposed = (
            dependency_exposure >= 0.70
        )

        # --------------------------------------------------
        # Calculated suspicion
        # --------------------------------------------------

        calculated_suspicion = (
            suspicion_score
        )

        calculated_suspicion = max(
            calculated_suspicion,
            dependency_exposure
        )

        if integrity_compromised:

            calculated_suspicion = max(
                calculated_suspicion,
                1.0
            )

        elif (
            attack_detected
            and provenance_suspicious
        ):

            calculated_suspicion = max(
                calculated_suspicion,
                0.9
            )

        elif (
            attack_detected
            or provenance_suspicious
        ):

            calculated_suspicion = max(
                calculated_suspicion,
                0.7
            )

        elif status_corrupted:

            calculated_suspicion = max(
                calculated_suspicion,
                0.8
            )

        calculated_suspicion = min(
            calculated_suspicion,
            1.0
        )

        # --------------------------------------------------
        # Explanation
        # --------------------------------------------------

        if provenance_suspicious:

            reason = (
                "Unauthorized memory-write provenance "
                "indicates direct compromise."
            )

        elif integrity_compromised:

            reason = (
                "Memory integrity verification failed."
            )

        elif status_corrupted:

            reason = (
                "Memory is marked as corrupted or deleted, "
                "indicating direct local compromise evidence."
            )

        elif compromised:

            reason = (
                "Multiple independent evidence signals "
                "indicate memory compromise."
            )

        elif dependency_exposed:

            reason = (
                "Memory is strongly exposed to a confirmed "
                "compromised upstream dependency, but direct "
                "compromise evidence is unavailable."
            )
            
        elif content_changed and numeric_change_detected:

            reason = (
                "Memory content changed from the previous version "
                "and numeric values were modified."
            )

        elif content_changed:

            reason = (
                "Memory content differs from the previous version."
            )

        else:

            reason = (
                "Insufficient evidence to confirm "
                "memory compromise."
            )

        # Attribution is evidence-based; absence of evidence is not proof.
        
        if (
            authorization_valid
            and integrity_anchor_status == "VALID"
            and not integrity_compromised
            and not provenance_suspicious
            and not attack_detected
            and not status_corrupted
            and suspicion_score < 0.50
        ):
            attribution = "OWNER_AUTHORIZED"
            attribution_evidence = [
                "The stored owner-approval signature verifies for this revision.",
                "The integrity manifest is present and valid.",
                "No direct compromise indicators were found."
            ]
        elif attack_detected and provenance_suspicious:
            attribution = "UNAUTHORIZED_MODIFICATION"
            attribution_evidence = [
                "An attack event matches the detected memory revision.",
                "Suspicious provenance also matches the detected memory revision."
            ]
        else:
            attribution = "INCONCLUSIVE"
            attribution_evidence = [
                "Current evidence cannot reliably establish owner authorization or attribute the modification to an attacker."
            ]

        return DetectionResult(

            memory_id=memory_id,

            compromised=compromised,

            suspicion_score=(
                calculated_suspicion
            ),

            evidence=evidence,

            reason=reason,

            attribution=attribution,

            attribution_evidence=attribution_evidence
        )

