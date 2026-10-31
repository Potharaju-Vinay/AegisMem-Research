from dataclasses import dataclass
import random


@dataclass(frozen=True)
class BenchmarkNode:
    memory_id: str


@dataclass(frozen=True)
class BenchmarkEdge:
    source: str
    target: str
    strength: float


@dataclass
class BenchmarkGraph:
    nodes: list[BenchmarkNode]
    edges: list[BenchmarkEdge]

    def successors(self, memory_id: str) -> list[str]:
        return [
            edge.target
            for edge in self.edges
            if edge.source == memory_id
        ]

    def predecessors(self, memory_id: str) -> list[str]:
        return [
            edge.source
            for edge in self.edges
            if edge.target == memory_id
        ]

    def edge_strength(
        self,
        source: str,
        target: str
    ) -> float:

        for edge in self.edges:

            if (
                edge.source == source
                and edge.target == target
            ):
                return edge.strength

        raise KeyError(
            f"Dependency edge not found: "
            f"{source} -> {target}"
        )


class BenchmarkGraphGenerator:

    def __init__(self, seed: int = 42):
        self.random = random.Random(seed)

    def generate(
        self,
        node_count: int,
        max_parents: int = 2
    ) -> BenchmarkGraph:

        if node_count < 2:
            raise ValueError(
                "node_count must be at least 2."
            )

        if max_parents < 1:
            raise ValueError(
                "max_parents must be at least 1."
            )

        nodes = [
            BenchmarkNode(
                memory_id=f"M-{index:04d}"
            )
            for index in range(1, node_count + 1)
        ]

        edges = []

        for index in range(1, node_count):

            possible_parents = list(
                range(index)
            )

            parent_count = self.random.randint(
                1,
                min(
                    max_parents,
                    len(possible_parents)
                )
            )

            parents = self.random.sample(
                possible_parents,
                parent_count
            )

            target = nodes[index].memory_id

            for parent_index in parents:

                source = nodes[
                    parent_index
                ].memory_id

                strength = round(
                    self.random.uniform(
                        0.50,
                        1.00
                    ),
                    3
                )

                edges.append(
                    BenchmarkEdge(
                        source=source,
                        target=target,
                        strength=strength
                    )
                )

        return BenchmarkGraph(
            nodes=nodes,
            edges=edges
        )


def print_graph_summary(
    graph: BenchmarkGraph
) -> None:

    print()
    print("------------------------------------------")
    print("BENCHMARK GRAPH")
    print("------------------------------------------")

    print(
        f"Nodes : {len(graph.nodes)}"
    )

    print(
        f"Edges : {len(graph.edges)}"
    )

    print()
    print("Sample dependencies:")

    for edge in graph.edges[:10]:

        print(
            f"{edge.source} -> "
            f"{edge.target} "
            f"(strength={edge.strength:.3f})"
        )