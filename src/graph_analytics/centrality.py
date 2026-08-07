"""
Graph Centrality Algorithms

Pure functions operating on a plain adjacency mapping, deliberately kept free of
any GraphStore dependency so they can be tested against hand-computed reference
graphs and reused by any caller holding a different graph representation.

Every measure returns values normalised to [0, 1] and keyed by node id, and every
function tolerates empty graphs, isolated nodes, self-loops and graphs split into
disconnected components.
"""

from __future__ import annotations

from collections import deque
from typing import Dict, Iterable, List, Mapping, Optional, Sequence, Set

# Adjacency is expressed as node id -> set of neighbour ids.
Adjacency = Mapping[str, Set[str]]

DEFAULT_DAMPING = 0.85
DEFAULT_TOLERANCE = 1e-6
DEFAULT_MAX_ITERATIONS = 100


def _undirected_view(adjacency: Adjacency, nodes: Sequence[str]) -> Dict[str, Set[str]]:
    """Build a symmetric adjacency view, excluding self-loops.

    Shortest-path measures treat the fraud graph as undirected: a transfer from
    A to B still places B one hop from A for reachability purposes. Self-loops
    are dropped because they contribute no path between distinct nodes and would
    otherwise inflate degree.
    """
    known = set(nodes)
    view: Dict[str, Set[str]] = {node: set() for node in nodes}

    for source, targets in adjacency.items():
        if source not in known:
            continue
        for target in targets:
            if target not in known or target == source:
                continue
            view[source].add(target)
            view[target].add(source)

    return view


def _single_source_shortest_paths(
    view: Mapping[str, Set[str]],
    source: str,
) -> Dict[str, int]:
    """BFS hop distances from ``source``, omitting unreachable nodes."""
    distances = {source: 0}
    queue = deque([source])

    while queue:
        node = queue.popleft()
        for neighbour in view.get(node, ()):  # type: ignore[arg-type]
            if neighbour not in distances:
                distances[neighbour] = distances[node] + 1
                queue.append(neighbour)

    return distances


def degree_centrality(adjacency: Adjacency, nodes: Sequence[str]) -> Dict[str, float]:
    """Fraction of other nodes each node is directly connected to."""
    node_list = list(nodes)
    total = len(node_list)
    if total <= 1:
        return {node: 0.0 for node in node_list}

    view = _undirected_view(adjacency, node_list)
    return {node: len(view[node]) / (total - 1) for node in node_list}


def betweenness_centrality(
    adjacency: Adjacency,
    nodes: Sequence[str],
    sample_size: Optional[int] = None,
) -> Dict[str, float]:
    """Brandes' betweenness centrality, normalised to [0, 1].

    Betweenness is the measure that surfaces bridging accounts — the ones money
    has to pass through — which is precisely what a degree-based approximation
    cannot see.

    Args:
        adjacency: Node id to neighbour ids.
        nodes: The node set to score.
        sample_size: When given, run the accumulation from this many pivot
            sources instead of all of them and scale the result accordingly.
            Trades exactness for runtime on large graphs.

    Returns:
        Node id to betweenness score in [0, 1].
    """
    node_list = list(nodes)
    total = len(node_list)
    scores = {node: 0.0 for node in node_list}
    if total <= 2:
        return scores

    view = _undirected_view(adjacency, node_list)

    if sample_size is not None and sample_size < total:
        # Deterministic stride sampling keeps results reproducible run to run,
        # which matters because these scores drive investigation priority.
        if sample_size <= 0:
            return scores
        stride = max(1, total // sample_size)
        pivots: List[str] = node_list[::stride][:sample_size]
    else:
        pivots = node_list

    for source in pivots:
        stack: List[str] = []
        predecessors: Dict[str, List[str]] = {node: [] for node in node_list}
        path_counts = {node: 0.0 for node in node_list}
        path_counts[source] = 1.0
        distances: Dict[str, int] = {source: 0}

        queue = deque([source])
        while queue:
            node = queue.popleft()
            stack.append(node)
            for neighbour in view[node]:
                if neighbour not in distances:
                    distances[neighbour] = distances[node] + 1
                    queue.append(neighbour)
                if distances[neighbour] == distances[node] + 1:
                    path_counts[neighbour] += path_counts[node]
                    predecessors[neighbour].append(node)

        dependency = {node: 0.0 for node in node_list}
        while stack:
            node = stack.pop()
            for predecessor in predecessors[node]:
                if path_counts[node] == 0:
                    continue
                dependency[predecessor] += (
                    path_counts[predecessor] / path_counts[node]
                ) * (1.0 + dependency[node])
            if node != source:
                scores[node] += dependency[node]

    # Each unordered pair is counted from both endpoints on an undirected graph.
    for node in scores:
        scores[node] /= 2.0

    if pivots and len(pivots) < total:
        scale = total / len(pivots)
        for node in scores:
            scores[node] *= scale

    # Normalise by the number of pairs not involving the node itself.
    max_pairs = (total - 1) * (total - 2) / 2
    if max_pairs > 0:
        for node in scores:
            scores[node] = min(1.0, scores[node] / max_pairs)

    return scores


def closeness_centrality(adjacency: Adjacency, nodes: Sequence[str]) -> Dict[str, float]:
    """Closeness centrality with Wasserman-Faust normalisation.

    The normalisation scales each node's score by the fraction of the graph it
    can actually reach, so a node that is central within a small isolated
    component does not outrank a node central in the main component.
    """
    node_list = list(nodes)
    total = len(node_list)
    scores = {node: 0.0 for node in node_list}
    if total <= 1:
        return scores

    view = _undirected_view(adjacency, node_list)

    for node in node_list:
        distances = _single_source_shortest_paths(view, node)
        reachable = [d for target, d in distances.items() if target != node]
        if not reachable:
            continue

        total_distance = sum(reachable)
        if total_distance == 0:
            continue

        # (reachable / (n - 1)) scales for component size; the second term is
        # the classic inverse mean distance within that component.
        component_fraction = len(reachable) / (total - 1)
        scores[node] = component_fraction * (len(reachable) / total_distance)

    return scores


def pagerank(
    adjacency: Adjacency,
    nodes: Sequence[str],
    damping: float = DEFAULT_DAMPING,
    tolerance: float = DEFAULT_TOLERANCE,
    max_iterations: int = DEFAULT_MAX_ITERATIONS,
) -> Dict[str, float]:
    """PageRank via damped power iteration over the directed graph.

    Dangling nodes — accounts that receive but never send — would otherwise leak
    rank out of the system, so their mass is redistributed uniformly each round.

    Returns:
        Node id to rank, summing to 1.0 across the graph.
    """
    node_list = list(nodes)
    total = len(node_list)
    if total == 0:
        return {}
    if total == 1:
        return {node_list[0]: 1.0}

    known = set(node_list)
    outgoing: Dict[str, List[str]] = {node: [] for node in node_list}
    for source, targets in adjacency.items():
        if source not in known:
            continue
        outgoing[source] = [t for t in targets if t in known and t != source]

    incoming: Dict[str, List[str]] = {node: [] for node in node_list}
    for source, targets in outgoing.items():
        for target in targets:
            incoming[target].append(source)

    dangling = [node for node in node_list if not outgoing[node]]
    ranks = {node: 1.0 / total for node in node_list}
    teleport = (1.0 - damping) / total

    for _ in range(max_iterations):
        dangling_mass = damping * sum(ranks[node] for node in dangling) / total
        updated = {}
        for node in node_list:
            inbound = sum(
                ranks[source] / len(outgoing[source]) for source in incoming[node]
            )
            updated[node] = teleport + dangling_mass + damping * inbound

        delta = sum(abs(updated[node] - ranks[node]) for node in node_list)
        ranks = updated
        if delta < tolerance:
            break

    # Guard against drift accumulated over the iterations.
    total_rank = sum(ranks.values())
    if total_rank > 0:
        ranks = {node: rank / total_rank for node, rank in ranks.items()}

    return ranks


def eigenvector_centrality(
    adjacency: Adjacency,
    nodes: Sequence[str],
    tolerance: float = DEFAULT_TOLERANCE,
    max_iterations: int = DEFAULT_MAX_ITERATIONS,
) -> Dict[str, float]:
    """Eigenvector centrality via power iteration, scaled so the maximum is 1.0.

    Power iteration does not converge on every graph — a bipartite component can
    oscillate indefinitely — so the iteration count is capped and the best
    available vector is returned rather than looping forever.
    """
    node_list = list(nodes)
    total = len(node_list)
    scores = {node: 0.0 for node in node_list}
    if total == 0:
        return scores
    if total == 1:
        return {node_list[0]: 0.0}

    view = _undirected_view(adjacency, node_list)
    vector = {node: 1.0 / total for node in node_list}

    for _ in range(max_iterations):
        updated = {node: 0.0 for node in node_list}
        for node in node_list:
            for neighbour in view[node]:
                updated[node] += vector[neighbour]

        norm = sum(value * value for value in updated.values()) ** 0.5
        if norm == 0:
            # No edges at all: every node is equally (un)central.
            return scores

        updated = {node: value / norm for node, value in updated.items()}
        delta = sum(abs(updated[node] - vector[node]) for node in node_list)
        vector = updated
        if delta < tolerance:
            break

    peak = max(vector.values())
    if peak <= 0:
        return scores
    return {node: value / peak for node, value in vector.items()}


def graph_diameter(adjacency: Adjacency, nodes: Sequence[str]) -> int:
    """Longest shortest-path length within the largest connected component."""
    node_list = list(nodes)
    if len(node_list) <= 1:
        return 0

    view = _undirected_view(adjacency, node_list)
    diameter = 0
    for node in node_list:
        distances = _single_source_shortest_paths(view, node)
        if distances:
            diameter = max(diameter, max(distances.values()))

    return diameter


def average_clustering_coefficient(adjacency: Adjacency, nodes: Sequence[str]) -> float:
    """Mean local clustering coefficient across every node.

    Measures how often a node's neighbours are themselves connected — dense
    mutual connection is a strong signal of a coordinated ring rather than
    incidental co-occurrence.
    """
    node_list = list(nodes)
    if len(node_list) < 3:
        return 0.0

    view = _undirected_view(adjacency, node_list)
    coefficients = []

    for node in node_list:
        neighbours = view[node]
        degree = len(neighbours)
        if degree < 2:
            coefficients.append(0.0)
            continue

        links = 0
        neighbour_list = list(neighbours)
        for i, first in enumerate(neighbour_list):
            for second in neighbour_list[i + 1:]:
                if second in view[first]:
                    links += 1

        possible = degree * (degree - 1) / 2
        coefficients.append(links / possible if possible else 0.0)

    return sum(coefficients) / len(coefficients) if coefficients else 0.0


def all_centralities(
    adjacency: Adjacency,
    nodes: Iterable[str],
    betweenness_sample_size: Optional[int] = None,
) -> Dict[str, Dict[str, float]]:
    """Compute every measure once for the whole graph.

    Ranking callers want scores for many nodes, and each of these measures is a
    whole-graph computation — calling a per-node entry point in a loop would
    repeat the same global work once per node.

    Returns:
        Node id to a dict of measure name to score.
    """
    node_list = list(nodes)
    degree = degree_centrality(adjacency, node_list)
    betweenness = betweenness_centrality(adjacency, node_list, betweenness_sample_size)
    closeness = closeness_centrality(adjacency, node_list)
    ranks = pagerank(adjacency, node_list)
    eigen = eigenvector_centrality(adjacency, node_list)

    return {
        node: {
            "degree_centrality": degree.get(node, 0.0),
            "betweenness_centrality": betweenness.get(node, 0.0),
            "closeness_centrality": closeness.get(node, 0.0),
            "page_rank": ranks.get(node, 0.0),
            "eigen_centrality": eigen.get(node, 0.0),
        }
        for node in node_list
    }
