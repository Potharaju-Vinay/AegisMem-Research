
from core.provenance.checkpoint import ProvenanceCheckpointStore
from core.provenance.trusted_head import TrustedCheckpointHeadStore


class ProvenanceRecoveryVerifier:
    def __init__(
        self,
        checkpoint_store=None,
        trusted_head_store=None,
    ):
        self.checkpoint_store = (
            checkpoint_store or ProvenanceCheckpointStore()
        )
        self.trusted_head_store = trusted_head_store or TrustedCheckpointHeadStore(
    checkpoint_store=self.checkpoint_store
)

    def verify(self, events: list) -> dict:
        if not events:
            return {
                "verified": False,
                "checkpoint_status": "CHECKPOINT_MISSING",
                "trusted_head_status": "CHECKPOINT_MISSING",
                "reason": "No provenance events are available.",
            }

        checkpoint_status = self.checkpoint_store.verify_checkpoint(
            events
        )

        trusted_head_status = self.trusted_head_store.verify_events(
            events
        )

        verified = (
            checkpoint_status == "VALID"
            and trusted_head_status == "VALID"
        )

        return {
            "verified": verified,
            "checkpoint_status": checkpoint_status,
            "trusted_head_status": trusted_head_status,
            "reason": (
                "Provenance verified."
                if verified
                else "Provenance checkpoint or trusted head verification failed."
            ),
        }

    
    def initialize_trusted_head(self, events: list) -> dict:
        if not events:
            raise ValueError(
                "Cannot initialize from empty provenance history"
            )

        checkpoint_status = self.checkpoint_store.verify_checkpoint(
            events
        )

        if checkpoint_status != "VALID":
            raise ValueError(
                f"Cannot initialize trusted head: {checkpoint_status}"
            )

        return self.trusted_head_store.advance(events)
