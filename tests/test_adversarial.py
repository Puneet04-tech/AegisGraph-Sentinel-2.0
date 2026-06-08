"""
Unit tests for the adversarial evaluation suite.

Each attack class is tested for:
    - It actually perturbs the graph (not a silent no-op)
    - It doesn't mutate the input graph
    - It's reproducible given a fixed seed
    - Edge cases (zero budget, max budget) behave correctly
"""
from __future__ import annotations
import os
import pytest

if os.getenv("RUN_TORCH_TESTS", "").lower() != "true":
    pytest.skip("PyTorch tests require RUN_TORCH_TESTS=true", allow_module_level=True)

# Handle optional torch dependency
try:
    import torch
    from src.adversarial.base import AttackConfig
    from src.adversarial.attacks import EdgeAddition, EdgeDeletion, FeaturePerturbation, NodeInjection, DecoyNodeInjection
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False

pytestmark = pytest.mark.skipif(not TORCH_AVAILABLE, reason="PyTorch not installed")


if TORCH_AVAILABLE:

    def _build_graph(num_nodes=30, num_edges=60, feature_dim=32, seed=0):
        gen = torch.Generator().manual_seed(seed)
        return {
            "x": torch.randn(num_nodes, feature_dim, generator=gen),
            "edge_index": torch.randint(0, num_nodes, (2, num_edges), generator=gen),
            "node_type": torch.randint(0, 5, (num_nodes,), generator=gen),
            "edge_type": torch.randint(0, 4, (num_edges,), generator=gen),
            "edge_timestamp": torch.rand(num_edges, generator=gen) * 86400,
        }

    def _graphs_equal(g1, g2):
        if g1.keys() != g2.keys():
            return False
        for k in g1:
            if g1[k].shape != g2[k].shape:
                return False
            if not torch.equal(g1[k], g2[k]):
                return False
        return True

    class TestEdgeAddition:
        def test_adds_edges(self):
            graph = _build_graph()
            attack = EdgeAddition(AttackConfig(budget=0.10, seed=42))
            perturbed = attack.perturb(graph)
            assert perturbed["edge_index"].shape[1] > graph["edge_index"].shape[1]

        def test_preserves_node_count(self):
            graph = _build_graph()
            attack = EdgeAddition(AttackConfig(budget=0.10, seed=42))
            perturbed = attack.perturb(graph)
            assert perturbed["x"].shape == graph["x"].shape

        def test_does_not_mutate_input(self):
            graph = _build_graph()
            original_count = graph["edge_index"].shape[1]
            attack = EdgeAddition(AttackConfig(budget=0.10, seed=42))
            _ = attack.perturb(graph)
            assert graph["edge_index"].shape[1] == original_count

        def test_reproducible_with_same_seed(self):
            graph = _build_graph()
            p1 = EdgeAddition(AttackConfig(budget=0.10, seed=42)).perturb(graph)
            p2 = EdgeAddition(AttackConfig(budget=0.10, seed=42)).perturb(graph)
            assert _graphs_equal(p1, p2)

        def test_different_seeds_diverge(self):
            graph = _build_graph()
            p1 = EdgeAddition(AttackConfig(budget=0.10, seed=1)).perturb(graph)
            p2 = EdgeAddition(AttackConfig(budget=0.10, seed=2)).perturb(graph)
            assert not _graphs_equal(p1, p2)

    class TestEdgeDeletion:
        def test_removes_edges(self):
            graph = _build_graph()
            attack = EdgeDeletion(AttackConfig(budget=0.10, seed=42))
            perturbed = attack.perturb(graph)
            assert perturbed["edge_index"].shape[1] < graph["edge_index"].shape[1]

        def test_keeps_at_least_one_edge_at_max_budget(self):
            graph = _build_graph(num_edges=10)
            attack = EdgeDeletion(AttackConfig(budget=1.0, seed=42))
            perturbed = attack.perturb(graph)
            assert perturbed["edge_index"].shape[1] >= 1

        def test_does_not_mutate_input(self):
            graph = _build_graph()
            original_count = graph["edge_index"].shape[1]
            attack = EdgeDeletion(AttackConfig(budget=0.10, seed=42))
            _ = attack.perturb(graph)
            assert graph["edge_index"].shape[1] == original_count

        def test_preserves_node_features(self):
            graph = _build_graph()
            attack = EdgeDeletion(AttackConfig(budget=0.10, seed=42))
            perturbed = attack.perturb(graph)
            assert torch.equal(graph["x"], perturbed["x"])

    class TestFeaturePerturbation:
        def test_modifies_features(self):
            graph = _build_graph()
            attack = FeaturePerturbation(AttackConfig(budget=0.1, seed=42))
            perturbed = attack.perturb(graph)
            assert not torch.equal(graph["x"], perturbed["x"])

        def test_preserves_structure(self):
            graph = _build_graph()
            attack = FeaturePerturbation(AttackConfig(budget=0.1, seed=42))
            perturbed = attack.perturb(graph)
            assert torch.equal(graph["edge_index"], perturbed["edge_index"])
            assert torch.equal(graph["edge_type"], perturbed["edge_type"])

        def test_zero_budget_is_no_op(self):
            graph = _build_graph()
            attack = FeaturePerturbation(AttackConfig(budget=0.0, seed=42))
            perturbed = attack.perturb(graph)
            assert torch.equal(graph["x"], perturbed["x"])

        def test_does_not_mutate_input(self):
            graph = _build_graph()
            original_x = graph["x"].clone()
            attack = FeaturePerturbation(AttackConfig(budget=0.1, seed=42))
            _ = attack.perturb(graph)
            assert torch.equal(graph["x"], original_x)
            
    class TestNodeInjection:
        def test_adds_nodes(self):
            graph = _build_graph(num_nodes=30)
            attack = NodeInjection(AttackConfig(budget=0.10, seed=42))
            perturbed = attack.perturb(graph)
            assert perturbed["x"].shape[0] > graph["x"].shape[0]
            assert perturbed["node_type"].shape[0] == perturbed["x"].shape[0]

        def test_adds_edges(self):
            graph = _build_graph()
            attack = NodeInjection(AttackConfig(budget=0.10, seed=42))
            perturbed = attack.perturb(graph)
            assert perturbed["edge_index"].shape[1] > graph["edge_index"].shape[1]

        def test_preserves_existing_nodes(self):
            graph = _build_graph()
            original_n = graph["x"].shape[0]
            attack = NodeInjection(AttackConfig(budget=0.10, seed=42))
            perturbed = attack.perturb(graph)
            assert torch.equal(perturbed["x"][:original_n], graph["x"])

        def test_does_not_mutate_input(self):
            graph = _build_graph()
            original_n = graph["x"].shape[0]
            attack = NodeInjection(AttackConfig(budget=0.10, seed=42))
            _ = attack.perturb(graph)
            assert graph["x"].shape[0] == original_n

        def test_reproducible_with_same_seed(self):
            graph = _build_graph()
            p1 = NodeInjection(AttackConfig(budget=0.10, seed=42)).perturb(graph)
            p2 = NodeInjection(AttackConfig(budget=0.10, seed=42)).perturb(graph)
            assert _graphs_equal(p1, p2)

    class TestDecoyNodeInjection:
        def test_adds_nodes(self):
            graph = _build_graph(num_nodes=30)
            attack = DecoyNodeInjection(AttackConfig(budget=0.10, seed=42))
            perturbed = attack.perturb(graph)
            assert perturbed["x"].shape[0] > graph["x"].shape[0]
            assert perturbed["node_type"].shape[0] == perturbed["x"].shape[0]

        def test_adds_edges(self):
            graph = _build_graph()
            attack = DecoyNodeInjection(AttackConfig(budget=0.10, seed=42))
            perturbed = attack.perturb(graph)
            assert perturbed["edge_index"].shape[1] > graph["edge_index"].shape[1]

        def test_preserves_existing_nodes(self):
            graph = _build_graph()
            original_n = graph["x"].shape[0]
            attack = DecoyNodeInjection(AttackConfig(budget=0.10, seed=42))
            perturbed = attack.perturb(graph)
            assert torch.equal(perturbed["x"][:original_n], graph["x"])

        def test_does_not_mutate_input(self):
            graph = _build_graph()
            original_n = graph["x"].shape[0]
            attack = DecoyNodeInjection(AttackConfig(budget=0.10, seed=42))
            _ = attack.perturb(graph)
            assert graph["x"].shape[0] == original_n

        def test_reproducible_with_same_seed(self):
            graph = _build_graph()
            p1 = DecoyNodeInjection(AttackConfig(budget=0.10, seed=42)).perturb(graph)
            p2 = DecoyNodeInjection(AttackConfig(budget=0.10, seed=42)).perturb(graph)
            assert _graphs_equal(p1, p2)
