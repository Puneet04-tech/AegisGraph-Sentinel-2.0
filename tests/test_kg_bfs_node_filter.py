"""
Regression tests for knowledge graph BFS traversal node_filter semantics.

The BFS traversal marked a node as visited before the node filter was applied,
so filter-rejected nodes were counted in nodes_visited and could not be reached
again via any other path. This made BFS inconsistent with DFS (which discards
filtered nodes from visited) and inflated the nodes_visited metric.
"""

import pytest

from src.global_intelligence.store import GlobalIntelligenceStore
from src.global_intelligence.knowledge_graph import KnowledgeGraphEngine, TraversalType
from src.global_intelligence.models import EntityType, ThreatLevel


class TestBFSTraversalNodeFilter:
    """BFS node_filter must only count accepted nodes as visited."""

    def setup_method(self):
        self.store = GlobalIntelligenceStore()
        self.kg = KnowledgeGraphEngine(store=self.store)
        for nid in ["A", "B", "C", "D"]:
            self.kg.add_entity(nid, EntityType.ACCOUNT, {"name": nid})

    def build_chain(self):
        self.kg.add_relationship("A", "B", "linked_to")
        self.kg.add_relationship("B", "C", "linked_to")

    def test_filtered_node_not_counted_visited(self):
        self.build_chain()
        self.kg.add_relationship("A", "D", "linked_to")

        def exclude_b(node):
            return node.node_id != "B"

        res = self.kg.traverse("A", TraversalType.BFS, max_depth=3, node_filter=exclude_b)

        assert sorted(n.node_id for n in res.nodes) == ["A", "D"]
        assert res.nodes_visited == len(res.nodes)

    def test_no_filter_visits_all(self):
        self.build_chain()

        res = self.kg.traverse("A", TraversalType.BFS, max_depth=3)

        assert res.nodes_visited == 3
        assert len(res.nodes) == 3

    def test_nodes_visited_matches_nodes_without_filter(self):
        self.build_chain()
        self.kg.add_relationship("A", "D", "linked_to")

        res = self.kg.traverse("A", TraversalType.BFS, max_depth=3)

        assert res.nodes_visited == len(res.nodes)

    def test_filtered_node_blocked_but_not_counted(self):
        self.build_chain()

        def exclude_b(node):
            return node.node_id != "B"

        res = self.kg.traverse("A", TraversalType.BFS, max_depth=3, node_filter=exclude_b)

        assert [n.node_id for n in res.nodes] == ["A"]
        assert res.nodes_visited == 1

    def test_bfs_matches_dfs_visited_semantics(self):
        self.build_chain()
        self.kg.add_relationship("A", "D", "linked_to")

        def exclude_b(node):
            return node.node_id != "B"

        bfs = self.kg.traverse("A", TraversalType.BFS, max_depth=3, node_filter=exclude_b)
        dfs = self.kg.traverse("A", TraversalType.DFS, max_depth=3, node_filter=exclude_b)

        bfs_nodes = {n.node_id for n in bfs.nodes}
        dfs_nodes = {n.node_id for n in dfs.nodes}
        assert bfs_nodes == dfs_nodes
        assert bfs.nodes_visited == dfs.nodes_visited

    def test_depth_one_paths_exclude_filtered(self):
        self.kg.add_relationship("A", "B", "linked_to")
        self.kg.add_relationship("A", "D", "linked_to")

        def exclude_b(node):
            return node.node_id != "B"

        res = self.kg.traverse("A", TraversalType.BFS, max_depth=1, node_filter=exclude_b)

        assert res.paths == [["A", "D"]]

    def test_filtered_node_reachable_only_after_accept_elsewhere(self):
        self.kg.add_relationship("A", "B", "linked_to")
        self.kg.add_relationship("A", "D", "linked_to")
        self.kg.add_relationship("D", "B", "linked_to")

        def exclude_d(node):
            return node.node_id != "D"

        res = self.kg.traverse("A", TraversalType.BFS, max_depth=3, node_filter=exclude_d)

        assert "D" not in [n.node_id for n in res.nodes]
        assert res.nodes_visited == len(res.nodes)


class TestBFSTraversalBasics:
    """Unfiltered BFS traversal still behaves correctly."""

    def setup_method(self):
        self.store = GlobalIntelligenceStore()
        self.kg = KnowledgeGraphEngine(store=self.store)

    def test_bfs_level_order(self):
        for nid in ["A", "B", "C", "D"]:
            self.kg.add_entity(nid, EntityType.ACCOUNT, {"name": nid})
        self.kg.add_relationship("A", "B", "linked_to")
        self.kg.add_relationship("A", "C", "linked_to")
        self.kg.add_relationship("B", "D", "linked_to")

        res = self.kg.traverse("A", TraversalType.BFS, max_depth=3)

        assert sorted(n.node_id for n in res.nodes) == ["A", "B", "C", "D"]
        assert res.nodes_visited == 4

    def test_start_node_not_found_returns_empty(self):
        res = self.kg.traverse("missing", TraversalType.BFS, max_depth=3)

        assert res.nodes == []
        assert res.nodes_visited == 0
        assert res.depth_reached == 0

    def test_relationship_type_filter(self):
        for nid in ["A", "B", "C"]:
            self.kg.add_entity(nid, EntityType.ACCOUNT, {"name": nid})
        self.kg.add_relationship("A", "B", "linked_to")
        self.kg.add_relationship("A", "C", "shares_ip")

        res = self.kg.traverse(
            "A", TraversalType.BFS, max_depth=2, relationship_types=["shares_ip"]
        )

        assert [n.node_id for n in res.nodes] == ["A", "C"]

    def test_dfs_relationship_type_filter(self):
        for nid in ["A", "B", "C"]:
            self.kg.add_entity(nid, EntityType.ACCOUNT, {"name": nid})
        self.kg.add_relationship("A", "B", "linked_to")
        self.kg.add_relationship("A", "C", "shares_ip")

        res = self.kg.traverse(
            "A", TraversalType.DFS, max_depth=2, relationship_types=["shares_ip"]
        )

        assert [n.node_id for n in res.nodes] == ["A", "C"]

    def test_dfs_includes_start_node_like_bfs(self):
        for nid in ["A", "B"]:
            self.kg.add_entity(nid, EntityType.ACCOUNT, {"name": nid})
        self.kg.add_relationship("A", "B", "linked_to")

        bfs = self.kg.traverse("A", TraversalType.BFS, max_depth=2)
        dfs = self.kg.traverse("A", TraversalType.DFS, max_depth=2)

        assert sorted(n.node_id for n in bfs.nodes) == ["A", "B"]
        assert sorted(n.node_id for n in dfs.nodes) == ["A", "B"]
        assert bfs.nodes_visited == dfs.nodes_visited

    def test_undirected_edge_traversal(self):
        for nid in ["A", "B"]:
            self.kg.add_entity(nid, EntityType.ACCOUNT, {"name": nid})
        self.kg.add_relationship("A", "B", "linked_to")

        from_b = self.kg.traverse("B", TraversalType.BFS, max_depth=2)

        assert sorted(n.node_id for n in from_b.nodes) == ["A", "B"]

    def test_self_edge_not_duplicated(self):
        self.kg.add_entity("A", EntityType.ACCOUNT, {"name": "A"})
        self.kg.add_relationship("A", "A", "linked_to")

        res = self.kg.traverse("A", TraversalType.BFS, max_depth=2)

        assert [n.node_id for n in res.nodes] == ["A"]
        assert res.nodes_visited == 1
