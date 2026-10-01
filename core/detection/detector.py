from sqlalchemy import select

from core.integrity.hash import calculate_version_hash
from core.memory.models import MemoryRecord
from core.memory.repository import MemoryRepository
from core.provenance.models import ProvenanceEvent

from attack_lab.models import AttackEvent

from core.detection.models import (
    DetectionEvidence,
    DetectionResult
)


class MemoryCompromiseDetector:

    def __init__(
        self,
        repository: MemoryRepository,
        dependency_graph=None
    ):

        self.repository = repository
        self.session = repository.session
        self.dependency_graph = dependency_graph

    # ==================================================
    # ATTACK EVENT EVIDENCE
    # ==================================================

    def _has_attack_evidence(
        self,
        memory: MemoryRecord
    ) -> bool:
        return False

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
            "MEMORY_TAMPER",
            "MEMORY_WRITE"
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
                "research-attacker"
            }
        )

        return (
            operation_suspicious
            or source_suspicious
            or actor_suspicious
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

        integrity_compromised = (
            expected_hash != memory.content_hash
        )

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

        # --------------------------------------------------
        # Evidence object
        # --------------------------------------------------

        evidence = DetectionEvidence(

            integrity_compromised=(
                integrity_compromised
            ),

            provenance_suspicious=(
                provenance_suspicious
            ),

            attack_detected=(
                attack_detected
            ),

            status_corrupted=(
                status_corrupted
            ),

            suspicion_score=(
                suspicion_score
            ),

            dependency_exposure=(
                dependency_exposure
            ),

            dependency_contamination=(
                dependency_contamination
            )
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
                suspicion_score >= 0.50
            ]
        )

        compromised = (
            independent_evidence >= 2
            or provenance_suspicious
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

        else:

            reason = (
                "Insufficient evidence to confirm "
                "memory compromise."
            )

        return DetectionResult(

            memory_id=memory_id,

            compromised=compromised,

            suspicion_score=(
                calculated_suspicion
            ),

            evidence=evidence,

            reason=reason
        )
