"""Graph traversal algorithms for adjacency-dict graphs.

A graph is represented as ``{node: [neighbor, ...]}``. Edges are directed
unless noted otherwise. Nodes that only appear as neighbors of a key are
still considered part of the graph.
"""

from collections import deque


def bfs(graph, start):
    """Return nodes reachable from start in breadth-first order."""
    if start not in graph:
        return [start]
    visited = []
    seen = {start}
    queue = deque([start])
    while queue:
        node = queue.popleft()
        visited.append(node)
        for neighbor in graph.get(node, ()):
            if neighbor not in seen:
                seen.add(neighbor)
                queue.append(neighbor)
    return visited


def dfs(graph, start):
    """Return nodes reachable from start in depth-first pre-order."""
    if start not in graph:
        return [start]
    visited = []
    seen = {start}
    stack = [start]
    while stack:
        node = stack.pop()
        visited.append(node)
        for neighbor in reversed(graph.get(node, ())):
            if neighbor not in seen:
                seen.add(neighbor)
                stack.append(neighbor)
    return visited


def _bfs_parents(graph, start):
    parents = {start: None}
    queue = deque([start])
    while queue:
        node = queue.popleft()
        for neighbor in graph.get(node, ()):
            if neighbor not in parents:
                parents[neighbor] = node
                queue.append(neighbor)
    return parents


def shortest_path(graph, start, end):
    """Return the shortest directed path as a list, [] when start == end, or None."""
    if start == end:
        return []
    if start not in graph:
        return None
    parents = _bfs_parents(graph, start)
    if end not in parents:
        return None
    path = [end]
    while path[-1] != start:
        path.append(parents[path[-1]])
    path.reverse()
    return path


def neighbors_in_degree(graph):
    """Return {node: number of incoming edges} for every node in the graph."""
    degrees = {node: 0 for node in graph}
    for neighbors in graph.values():
        for neighbor in neighbors:
            degrees.setdefault(neighbor, 0)
            degrees[neighbor] += 1
    return degrees


def connected_components(graph):
    """Return undirected connected components as lists of nodes."""
    adjacency = {}
    for node, neighbors in graph.items():
        adjacency.setdefault(node, set()).update(neighbors)
        for neighbor in neighbors:
            adjacency.setdefault(neighbor, set()).add(node)
    components = []
    unvisited = set(adjacency)
    while unvisited:
        start = unvisited.pop()
        component = [start]
        stack = [start]
        while stack:
            node = stack.pop()
            for neighbor in adjacency.get(node, ()):
                if neighbor in unvisited:
                    unvisited.remove(neighbor)
                    component.append(neighbor)
                    stack.append(neighbor)
        components.append(component)
    return components


def _reverse_adjacency(graph):
    reverse = {}
    for node, neighbors in graph.items():
        for neighbor in neighbors:
            reverse.setdefault(neighbor, []).append(node)
    return reverse


def bidirectional_search(graph, start, end):
    """Return the shortest path using bidirectional BFS, or None if unreachable."""
    if start == end:
        return []
    if start not in graph:
        return None

    def expand(frontier, parents, other_parents, adjacency):
        next_frontier = []
        for node in frontier:
            for neighbor in adjacency.get(node, ()):
                if neighbor in parents:
                    continue
                parents[neighbor] = node
                if neighbor in other_parents:
                    return next_frontier, neighbor
                next_frontier.append(neighbor)
        return next_frontier, None

    reverse = _reverse_adjacency(graph)
    start_frontier = [start]
    end_frontier = [end]
    start_parents = {start: None}
    end_parents = {end: None}
    while start_frontier and end_frontier:
        if len(start_frontier) <= len(end_frontier):
            start_frontier, meeting = expand(start_frontier, start_parents, end_parents, graph)
        else:
            end_frontier, meeting = expand(end_frontier, end_parents, start_parents, reverse)
        if meeting is not None:
            return _reconstruct_path(start, meeting, start_parents, end_parents)
    return None


def _reconstruct_path(start, meeting, start_parents, end_parents):
    forward = [meeting]
    while forward[-1] != start:
        forward.append(start_parents[forward[-1]])
    forward.reverse()
    backward = []
    node = end_parents[meeting]
    while node is not None:
        backward.append(node)
        node = end_parents[node]
    return forward + backward
