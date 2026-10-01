from core.memory.models import MemoryRecord
from core.memory.repository import MemoryRepository


class TrustedVersionResolver:

    def __init__(
        self,
        repository: MemoryRepository
    ):
        self.repository = repository

    def find_trusted_version(
        self,
        memory_id: str
    ) -> MemoryRecord | None:

        history = self.repository.get_history(
            memory_id
        )

        if not history:
            return None

        # --------------------------------------------------
        # The latest version is the state currently being
        # evaluated/recovered. It must not be selected as
        # its own recovery target.
        # --------------------------------------------------

        if len(history) == 1:
            return None

        historical_versions = history[:-1]

        # --------------------------------------------------
        # Search from newest historical version to oldest.
        #
        # This preserves the principle of minimum rollback:
        # select the most recent version that was trusted
        # before the current state.
        # --------------------------------------------------

        for record in reversed(
            historical_versions
        ):

            if (
                record.status == "active"
                and record.trust_score >= 0.8
                and record.suspicion_score <= 0.2
            ):
                return record

        return None