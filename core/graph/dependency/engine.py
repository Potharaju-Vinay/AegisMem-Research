from datetime import datetime, timezone

import networkx as nx

from core.graph.dependency.repository import DependencyRepository


class DependencyGraph:

    def __init__(self, repository: DependencyRepository):
        self.repository = repository
        self.graph = nx.DiGraph()

    @staticmethod
    def _normalize_timestamp(timestamp: datetime) -> datetime:
        if timestamp.tzinfo is None:
            return timestamp.replace(tzinfo=timezone.utc)

        return timestamp.astimezone(timezone.utc)

    def load(self):
        self.graph.clear()

        dependencies = self.repository.get_all()

        for dependency in dependencies:
            self.graph.add_edge(
                dependency.source_memory_id,
                dependency.target_memory_id,
                dependency_type=dependency.dependency_type,
                strength=dependency.strength,
                valid_from=dependency.valid_from,
                valid_until=dependency.valid_until,
                observed_at=dependency.observed_at
            )

    def load_at(self, timestamp: datetime):

        timestamp = self._normalize_timestamp(timestamp)

        self.graph.clear()

        dependencies = self.repository.get_all()

        for dependency in dependencies:

            valid_from = self._normalize_timestamp(
                dependency.valid_from
            )

            valid_until = (
                self._normalize_timestamp(
                    dependency.valid_until
                )
                if dependency.valid_until is not None
                else None
            )

            if valid_from > timestamp:
                continue

            if valid_until is not None and valid_until < timestamp:
                continue

            self.graph.add_edge(
                dependency.source_memory_id,
                dependency.target_memory_id,
                dependency_type=dependency.dependency_type,
                strength=dependency.strength,
                valid_from=valid_from,
                valid_until=valid_until,
                observed_at=dependency.observed_at
            )

    def add_edge(
        self,
        source: str,
        target: str,
        dependency_type: str,
        strength: float
    ):

        if not 0.0 <= strength <= 1.0:
            raise ValueError(
                "Dependency strength must be between 0 and 1."
            )

        self.graph.add_edge(
            source,
            target,
            dependency_type=dependency_type,
            strength=strength
        )

    def descendants(self, memory_id: str) -> set[str]:

        if memory_id not in self.graph:
            return set()

        return set(
            nx.descendants(
                self.graph,
                memory_id
            )
        )

    def ancestors(self, memory_id: str) -> set[str]:

        if memory_id not in self.graph:
            return set()

        return set(
            nx.ancestors(
                self.graph,
                memory_id
            )
        )

    def temporal_descendants(
        self,
        memory_id: str,
        timestamp: datetime
    ) -> set[str]:

        self.load_at(timestamp)

        return self.descendants(memory_id)

    def edge_strength(
        self,
        source: str,
        target: str
    ) -> float:

        if not self.graph.has_edge(source, target):
            return 0.0

        return self.graph[source][target]["strength"]

    def edge_type(
        self,
        source: str,
        target: str
    ) -> str | None:

        if not self.graph.has_edge(source, target):
            return None

        return self.graph[source][target]["dependency_type"]
