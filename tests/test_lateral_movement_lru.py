"""Regression coverage for in-memory lateral movement graph pruning."""

from collections import OrderedDict
import threading

import networkx as nx

from src.features.lateral_movement import LateralMovementDetector


def test_update_graph_prunes_least_recently_used_nodes():
    detector = LateralMovementDetector.__new__(LateralMovementDetector)
    detector.graph_service = None
    detector.use_redis = False
    detector.use_neo4j = False
    detector._lock = threading.Lock()
    detector._node_access_order = OrderedDict()
    detector.active_graph = nx.DiGraph()

    original_prune = detector._prune_lru_nodes

    def tiny_prune(max_nodes=10000):
        return original_prune(max_nodes=3)

    detector._prune_lru_nodes = tiny_prune

    detector.update_graph("ACC_A", "ACC_B")
    detector.update_graph("ACC_C", "ACC_D")
    detector.update_graph("ACC_E", "ACC_F")

    assert "ACC_A" not in detector.active_graph
    assert "ACC_B" not in detector.active_graph
    assert "ACC_D" in detector.active_graph
    assert "ACC_E" in detector.active_graph
    assert "ACC_F" in detector.active_graph
