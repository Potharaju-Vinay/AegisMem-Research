from dataclasses import dataclass
import random

from experiments.benchmark.graph_generator import BenchmarkGraph


@dataclass(frozen=True)
class AttackScenario:
    attack_id: str
    root_memory_id: str
    contaminated_memory_ids: set[str]
    exposed_memory_ids: set[str]
    unaffected_memory_ids: set[str]
    attack_type: str
    attack_depth: str


class BenchmarkAttackGenerator:
    def __init__(
        self,
        seed: int = 42,
        contamination_probability: float = 0.70
    ):
        if not 0.0 < contamination_probability <= 1.0:
            raise ValueError(
                "Contamination probability must be between 0 and 1."
            )

        self.random = random.Random(seed)
        self.contamination_probability = contamination_probability

    def _descendant_distances(
        self,
        graph: BenchmarkGraph,
        root: str
    ) -> dict[str, int]:

        distances = {root: 0}
        queue = [root]

        while queue:
            current = queue.pop(0)

            for child in graph.successors(current):
                if child not in distances:
                    distances[child] = distances[current] + 1
                    queue.append(child)

        return distances

    def _select_root(
        self,
        graph: BenchmarkGraph,
        attack_index: int
    ) -> str:

        distance_map = {}

        for node in graph.nodes:
            distances = self._descendant_distances(
                graph,
                node.memory_id
            )

            max_depth = max(distances.values())

            distance_map[node.memory_id] = max_depth

        candidates = list(distance_map.items())

        if attack_index % 10 in (1, 2):
            preferred = [
                memory_id
                for memory_id, depth in candidates
                if depth == 0
            ]

        elif attack_index % 10 in (3, 4, 5):
            preferred = [
                memory_id
                for memory_id, depth in candidates
                if 1 <= depth <= 2
            ]

        else:
            preferred = [
                memory_id
                for memory_id, depth in candidates
                if depth >= 3
            ]

        if not preferred:
            preferred = [
                memory_id
                for memory_id, _ in candidates
            ]

        return self.random.choice(preferred)

    def generate(
        self,
        graph: BenchmarkGraph,
        attack_index: int = 1
    ) -> AttackScenario:

        all_nodes = {
            node.memory_id
            for node in graph.nodes
        }

        root_memory_id = self._select_root(
            graph,
            attack_index
        )

        distances = self._descendant_distances(
            graph,
            root_memory_id
        )

        exposed_memory_ids = (
            set(distances.keys()) - {root_memory_id}
        )

        contaminated_memory_ids = {
            root_memory_id
        }

        for memory_id in sorted(exposed_memory_ids):
            parents = graph.predecessors(memory_id)

            contaminated_parents = [
                parent
                for parent in parents
                if parent in contaminated_memory_ids
            ]

            if not contaminated_parents:
                continue

            max_strength = max(
                graph.edge_strength(
                    parent,
                    memory_id
                )
                for parent in contaminated_parents
            )

            probability = (
                self.contamination_probability
                * max_strength
            )

            if self.random.random() < probability:
                contaminated_memory_ids.add(
                    memory_id
                )

        unaffected_memory_ids = (
            all_nodes
            - contaminated_memory_ids
            - exposed_memory_ids
        )

        max_distance = max(distances.values())

        if max_distance == 0:
            attack_depth = "root_only"
        elif max_distance <= 2:
            attack_depth = "shallow"
        else:
            attack_depth = "deep"

        return AttackScenario(
            attack_id=f"ATTACK-{attack_index:04d}",
            root_memory_id=root_memory_id,
            contaminated_memory_ids=contaminated_memory_ids,
            exposed_memory_ids=exposed_memory_ids,
            unaffected_memory_ids=unaffected_memory_ids,
            attack_type="memory_poisoning",
            attack_depth=attack_depth
        )


def print_attack_scenario(
    scenario: AttackScenario
) -> None:

    exposed_clean = (
        scenario.exposed_memory_ids
        - scenario.contaminated_memory_ids
    )

    print()
    print("=" * 50)
    print("ATTACK SCENARIO")
    print("=" * 50)

    print(
        f"Attack ID                 : "
        f"{scenario.attack_id}"
    )

    print(
        f"Attack Type               : "
        f"{scenario.attack_type}"
    )

    print(
        f"Attack Depth              : "
        f"{scenario.attack_depth}"
    )

    print(
        f"Root Memory               : "
        f"{scenario.root_memory_id}"
    )

    print(
        f"Ground Truth Contaminated : "
        f"{len(scenario.contaminated_memory_ids)}"
    )

    print(
        f"Exposed but Clean         : "
        f"{len(exposed_clean)}"
    )

    print(
        f"Unaffected                : "
        f"{len(scenario.unaffected_memory_ids)}"
    )

    print(
        f"Contaminated Memories     : "
        f"{sorted(scenario.contaminated_memory_ids)}"
    )

    print(
        f"Exposed Memories          : "
        f"{sorted(scenario.exposed_memory_ids)}"
    )

    print(
        f"Unaffected Memories       : "
        f"{sorted(scenario.unaffected_memory_ids)}"
    )