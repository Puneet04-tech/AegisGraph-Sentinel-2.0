"""Unit tests for explanation faithfulness metrics in the Aegis explainer.

Covers perturbation-based validation of the GNNExplainer critical subgraph:
    - fidelity+ (necessity): removing explanation edges drops the prediction
    - fidelity- (sufficiency): keeping only explanation edges preserves it
    - sparsity and the FAITHFUL / PARTIALLY_FAITHFUL / UNFAITHFUL /
      NO_EXPLANATION verdicts
    - narrative rendering of the faithfulness section by AegisOracle
"""
from __future__ import annotations
import os
from types import SimpleNamespace

import pytest

if os.getenv("RUN_TORCH_TESTS", "").lower() != "true":
    pytest.skip("PyTorch tests require RUN_TORCH_TESTS=true", allow_module_level=True)

# Handle optional torch dependency
try:
    import torch
    from src.inference.explainer import AegisModelExplainer, AegisOracle
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False

pytestmark = pytest.mark.skipif(not TORCH_AVAILABLE, reason="PyTorch not installed")


if TORCH_AVAILABLE:

    class EdgeSumModel(torch.nn.Module):
        """Toy node scorer whose output depends only on incoming edges.

        Probability of node i = clamped sum of x[src, 0] over edges src -> i,
        so removing an edge into the target provably changes the prediction.
        """

        def forward(self, x, edge_index):
            probs = torch.zeros(x.size(0))
            if edge_index.numel():
                src, dst = edge_index[0], edge_index[1]
                probs.index_add_(0, dst, x[src, 0])
            return probs.clamp(0.0, 1.0)

    class FakeExplainer:
        """Stands in for the torch_geometric Explainer with a fixed mask."""

        def __init__(self, edge_mask):
            self.edge_mask = torch.tensor(edge_mask)

        def __call__(self, x, edge_index, index=None):
            return SimpleNamespace(edge_mask=self.edge_mask)


TARGET_NODE = 4

# Node 0 and 1 drive the target's fraud score; node 2 barely contributes;
# edges 3 and 4 do not touch the target at all.
NODE_FRAUD_SCORES = [0.45, 0.45, 0.05, 0.0, 0.0]

EDGES = [
    [0, 1, 2, 3, 2],  # sources
    [4, 4, 4, 2, 3],  # destinations
]


def _make_explainer(edge_mask):
    explainer = AegisModelExplainer(EdgeSumModel())
    explainer._explainer = FakeExplainer(edge_mask)
    return explainer


@pytest.fixture
def node_features():
    x = torch.zeros(5, 3)
    x[:, 0] = torch.tensor(NODE_FRAUD_SCORES)
    return x


@pytest.fixture
def edge_index():
    return torch.tensor(EDGES, dtype=torch.long)


class TestCriticalTopologyBackwardCompat:
    def test_only_edges_above_threshold_reported(self, node_features, edge_index):
        explainer = _make_explainer([0.9, 0.8, 0.1, 0.1, 0.1])
        path = explainer.extract_critical_topology(
            node_features, edge_index, TARGET_NODE
        )

        assert path == [
            {"source_node": 0, "target_node": 4, "fraud_contribution": pytest.approx(0.9)},
            {"source_node": 1, "target_node": 4, "fraud_contribution": pytest.approx(0.8)},
        ]

    def test_capped_at_max_explanation_edges(self, node_features):
        num_edges = 15
        edge_index = torch.stack([
            torch.zeros(num_edges, dtype=torch.long),
            torch.full((num_edges,), TARGET_NODE, dtype=torch.long),
        ])
        explainer = _make_explainer([0.9] * num_edges)
        path = explainer.extract_critical_topology(
            node_features, edge_index, TARGET_NODE
        )

        assert len(path) == AegisModelExplainer.MAX_EXPLANATION_EDGES


class TestFaithfulnessMetrics:
    def test_faithful_explanation(self, node_features, edge_index):
        # Mask highlights the two edges that actually drive the target score
        explainer = _make_explainer([0.9, 0.8, 0.1, 0.1, 0.1])
        result = explainer.explain_with_faithfulness(
            node_features, edge_index, TARGET_NODE
        )
        metrics = result['explanation_faithfulness']

        # p_orig = 0.95; without {0->4, 1->4} it drops to 0.05
        assert metrics['fidelity_plus'] == pytest.approx(0.90, abs=1e-3)
        # keeping only the explanation edges preserves 0.90 of the 0.95
        assert metrics['fidelity_minus'] == pytest.approx(0.05, abs=1e-3)
        assert metrics['sparsity'] == pytest.approx(0.6)
        assert metrics['explanation_edge_count'] == 2
        assert metrics['total_edge_count'] == 5
        assert metrics['verdict'] == 'FAITHFUL'

    def test_unfaithful_when_mask_highlights_irrelevant_edges(
        self, node_features, edge_index
    ):
        # Mask highlights the two edges that never touch the target node
        explainer = _make_explainer([0.1, 0.1, 0.1, 0.9, 0.8])
        result = explainer.explain_with_faithfulness(
            node_features, edge_index, TARGET_NODE
        )
        metrics = result['explanation_faithfulness']

        # Removing irrelevant edges changes nothing -> not necessary
        assert metrics['fidelity_plus'] == pytest.approx(0.0, abs=1e-3)
        # Keeping only them loses the whole prediction -> not sufficient
        assert metrics['fidelity_minus'] == pytest.approx(0.95, abs=1e-3)
        assert metrics['verdict'] == 'UNFAITHFUL'

    def test_partially_faithful_explanation(self, node_features, edge_index):
        # Mask highlights only one of the two true drivers
        explainer = _make_explainer([0.9, 0.1, 0.1, 0.1, 0.1])
        result = explainer.explain_with_faithfulness(
            node_features, edge_index, TARGET_NODE
        )
        metrics = result['explanation_faithfulness']

        # Necessary (drop 0.45) but not sufficient (0.50 unexplained)
        assert metrics['fidelity_plus'] == pytest.approx(0.45, abs=1e-3)
        assert metrics['fidelity_minus'] == pytest.approx(0.50, abs=1e-3)
        assert metrics['verdict'] == 'PARTIALLY_FAITHFUL'

    def test_no_explanation_when_all_weights_below_threshold(
        self, node_features, edge_index
    ):
        explainer = _make_explainer([0.1, 0.2, 0.1, 0.3, 0.1])
        result = explainer.explain_with_faithfulness(
            node_features, edge_index, TARGET_NODE
        )
        metrics = result['explanation_faithfulness']

        assert metrics['verdict'] == 'NO_EXPLANATION'
        assert metrics['explanation_edge_count'] == 0
        assert result['critical_topology'] == []

    def test_critical_topology_matches_faithfulness_selection(
        self, node_features, edge_index
    ):
        # The reported edges and the evaluated edges must be the same set
        explainer = _make_explainer([0.9, 0.8, 0.1, 0.1, 0.1])
        result = explainer.explain_with_faithfulness(
            node_features, edge_index, TARGET_NODE
        )

        assert len(result['critical_topology']) == (
            result['explanation_faithfulness']['explanation_edge_count']
        )

    def test_two_dimensional_model_output_is_squeezed(
        self, node_features, edge_index
    ):
        class ColumnOutputModel(EdgeSumModel):
            def forward(self, x, edge_index):
                return super().forward(x, edge_index).unsqueeze(-1)  # [N, 1]

        explainer = AegisModelExplainer(ColumnOutputModel())
        explainer._explainer = FakeExplainer([0.9, 0.8, 0.1, 0.1, 0.1])
        result = explainer.explain_with_faithfulness(
            node_features, edge_index, TARGET_NODE
        )

        assert result['explanation_faithfulness']['verdict'] == 'FAITHFUL'


class TestNarrativeRendering:
    FAITHFULNESS = {
        'fidelity_plus': 0.90,
        'fidelity_minus': 0.05,
        'sparsity': 0.6,
        'explanation_edge_count': 2,
        'total_edge_count': 5,
        'verdict': 'FAITHFUL',
    }

    def test_faithfulness_section_rendered(self):
        oracle = AegisOracle()
        lines = oracle._explain_graph_patterns(
            {'explanation_faithfulness': self.FAITHFULNESS}
        )
        text = "\n".join(lines)

        assert 'Explanation Faithfulness Validation' in text
        assert 'Fidelity+ (necessity): 0.9000' in text
        assert 'Fidelity- (sufficiency): 0.0500' in text
        assert 'Sparsity: 60.00% (2 of 5 edges used)' in text
        assert 'Verdict: FAITHFUL' in text

    def test_no_faithfulness_section_without_metrics(self):
        oracle = AegisOracle()
        lines = oracle._explain_graph_patterns({'chain_detected': True})

        assert 'Explanation Faithfulness Validation' not in "\n".join(lines)

    def test_faithfulness_appears_in_full_explanation(self):
        oracle = AegisOracle()
        report = oracle.explain_decision(
            transaction={
                'transaction_id': 'TXN-1', 'source_account': 'A',
                'target_account': 'B', 'amount': 100000,
            },
            risk_result={
                'risk_score': 0.94, 'decision': 'BLOCK',
                'breakdown': {'graph': 0.91}, 'confidence': 0.96,
            },
            graph_patterns={
                'critical_topology': [
                    {'source_node': 1, 'target_node': 2, 'fraud_contribution': 0.9},
                ],
                'explanation_faithfulness': self.FAITHFULNESS,
            },
        )

        assert 'Explanation Faithfulness Validation' in report['explanation']
        assert 'Verdict: FAITHFUL' in report['explanation']
