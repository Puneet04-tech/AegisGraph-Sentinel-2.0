"""Tests for the graph traversal module.

Covers BFS, DFS, shortest path, in-degree counting, connected components,
and bidirectional search on adjacency-dict graphs.
"""

from src.graph_analytics.traversal import (
    bfs,
    dfs,
    shortest_path,
    neighbors_in_degree,
    connected_components,
    bidirectional_search,
)

CHAIN = {"a": ["b"], "b": ["c"], "c": ["d"]}

BRANCHING = {"a": ["b", "c"], "b": ["d"], "c": ["d"]}

DIRECTED_CYCLE = {"a": ["b"], "b": ["c"], "c": ["a"]}

UNDIRECTED_CYCLE = {"a": ["b"], "b": ["a"]}

TWO_COMPONENTS = {"a": ["b"], "b": ["a"], "c": ["d"], "d": ["c"]}

EMPTY = {}


def test_bfs_order_on_chain():
    assert bfs(CHAIN, "a") == ["a", "b", "c", "d"]


def test_bfs_visits_all_reachable():
    assert bfs(BRANCHING, "a") == ["a", "b", "c", "d"]


def test_bfs_reaches_all_nodes_of_a_component():
    visited = bfs(UNDIRECTED_CYCLE, "a")
    assert set(visited) == {"a", "b"}


def test_bfs_start_is_neighbor_only_returns_self():
    graph = {"a": ["b"], "b": ["c"]}
    assert bfs(graph, "c") == ["c"]


def test_bfs_unknown_start_returns_self():
    assert bfs(EMPTY, "missing") == ["missing"]


def test_bfs_does_not_follow_neighbors_of_unknown_start():
    graph = {"a": ["b"]}
    assert bfs(graph, "x") == ["x"]


def test_dfs_order_on_small_graph():
    assert dfs(BRANCHING, "a") == ["a", "b", "d", "c"]


def test_dfs_order_on_chain():
    assert dfs(CHAIN, "a") == ["a", "b", "c", "d"]


def test_dfs_unknown_start_returns_self():
    assert dfs(EMPTY, "missing") == ["missing"]


def test_dfs_terminates_on_cycle():
    assert dfs(DIRECTED_CYCLE, "a") == ["a", "b", "c"]


def test_shortest_path_on_chain():
    assert shortest_path(CHAIN, "a", "d") == ["a", "b", "c", "d"]


def test_shortest_path_on_branching_graph():
    assert shortest_path(BRANCHING, "a", "d") == ["a", "b", "d"]


def test_shortest_path_backward_edge_ignored():
    graph = {"a": ["b", "c"], "c": ["d"]}
    assert shortest_path(graph, "a", "d") == ["a", "c", "d"]


def test_shortest_path_unreachable_returns_none():
    graph = {"a": ["b"]}
    assert shortest_path(graph, "a", "c") is None


def test_shortest_path_start_equals_end_returns_empty():
    assert shortest_path(CHAIN, "b", "b") == []


def test_shortest_path_unknown_start_returns_none():
    assert shortest_path(EMPTY, "a", "b") is None


def test_shortest_path_end_not_in_graph_returns_none():
    graph = {"a": ["b"]}
    assert shortest_path(graph, "b", "a") is None


def test_neighbors_in_degree_counts():
    assert neighbors_in_degree(CHAIN) == {"a": 0, "b": 1, "c": 1, "d": 1}


def test_neighbors_in_degree_counts_converging_edges():
    assert neighbors_in_degree(BRANCHING) == {"a": 0, "b": 1, "c": 1, "d": 2}


def test_neighbors_in_degree_includes_neighbor_only_nodes():
    graph = {"a": ["b"], "c": []}
    degrees = neighbors_in_degree(graph)
    assert set(degrees) == {"a", "b", "c"}
    assert degrees["b"] == 1
    assert degrees["c"] == 0


def test_connected_components_two_components():
    components = connected_components(TWO_COMPONENTS)
    assert sorted(sorted(c) for c in components) == [["a", "b"], ["c", "d"]]


def test_connected_components_single_node():
    assert connected_components({"a": []}) == [["a"]]


def test_connected_components_undirected_traversal():
    components = connected_components(CHAIN)
    assert len(components) == 1
    assert set(components[0]) == {"a", "b", "c", "d"}


def test_connected_components_includes_neighbor_only_node():
    components = connected_components({"a": ["b"], "c": []})
    assert sorted(sorted(c) for c in components) == [["a", "b"], ["c"]]


def test_connected_components_empty_graph():
    assert connected_components(EMPTY) == []


def test_bidirectional_search_matches_shortest_path():
    for graph in (CHAIN, BRANCHING, DIRECTED_CYCLE, UNDIRECTED_CYCLE, TWO_COMPONENTS):
        for start in graph:
            for end in graph:
                expected = shortest_path(graph, start, end)
                assert bidirectional_search(graph, start, end) == expected


def test_bidirectional_search_on_directed_path():
    graph = {"a": ["b", "d"], "d": ["e"], "b": ["c"], "c": ["e"]}
    assert bidirectional_search(graph, "a", "e") == ["a", "d", "e"]


def test_bidirectional_search_reverse_edges_not_used():
    graph = {"a": ["b"], "c": ["b"]}
    assert bidirectional_search(graph, "a", "c") is None


def test_bidirectional_search_unreachable_returns_none():
    graph = {"a": ["b"]}
    assert bidirectional_search(graph, "a", "c") is None


def test_bidirectional_search_start_equals_end():
    assert bidirectional_search(CHAIN, "b", "b") == []


def test_bidirectional_search_unknown_start_returns_none():
    assert bidirectional_search(EMPTY, "a", "b") is None


def test_bfs_terminates_on_directed_cycle():
    visited = bfs(DIRECTED_CYCLE, "a")
    assert visited == ["a", "b", "c"]


def test_bfs_terminates_on_self_loop():
    graph = {"a": ["a", "b"]}
    assert bfs(graph, "a") == ["a", "b"]


def test_dfs_terminates_on_self_loop():
    graph = {"a": ["a", "b"]}
    assert dfs(graph, "a") == ["a", "b"]


def test_bfs_on_empty_graph_returns_start():
    assert bfs(EMPTY, "a") == ["a"]


def test_dfs_on_empty_graph_returns_start():
    assert dfs(EMPTY, "a") == ["a"]


def test_shortest_path_on_empty_graph():
    assert shortest_path(EMPTY, "a", "a") == []
    assert shortest_path(EMPTY, "a", "b") is None
