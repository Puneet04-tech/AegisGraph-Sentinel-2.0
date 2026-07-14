"""Tests for attention-grounded causal factors in the Aegis-Oracle explainer.

Covers the fix for the Oracle silently dropping HTGAT attention weights:
- attention-derived evidence replaces the static template when weights are provided
- all three accepted payload shapes (edges list, ProductionRiskScorer
  top_relationships, flat 'SRC->TGT' mapping)
- graceful fallback to template evidence on missing or malformed payloads
- factor ranking reflects attention weight
"""

import math

import pytest

from src.features.aegis_oracle_explainer import AegisOracleExplainer


@pytest.fixture
def explainer():
    return AegisOracleExplainer()


@pytest.fixture
def transaction():
    return {
        'transaction_id': 'TXN123',
        'source_account': 'ACC_001',
        'target_account': 'ACC_MULE',
        'amount': 75000,
    }


@pytest.fixture
def risk_assessment():
    return {'decision': 'BLOCK', 'risk_score': 0.92, 'confidence': 0.95}


GRAPH_ONLY_BREAKDOWN = {'graph': 0.8, 'velocity': 0.0, 'behavior': 0.0, 'entropy': 0.0}

ATTENTION_EDGES = {
    'edges': [
        {'source': 'ACC_001', 'target': 'ACC_MULE', 'weight': 0.91},
        {'source': 'ACC_MULE', 'target': 'ACC_EXIT', 'weight': 0.74},
    ]
}

TEMPLATE_EVIDENCE_MARKER = 'high-velocity transfer chain'


def _graph_factor(explanation):
    return next(
        factor for factor in explanation['causal_factors']
        if factor['type'] == 'GRAPH'
    )


class TestAttentionEvidence:
    def test_attention_edges_replace_template_evidence(
        self, explainer, transaction, risk_assessment
    ):
        explanation = explainer.generate_explanation(
            transaction,
            risk_assessment,
            attention_weights=ATTENTION_EDGES,
            break_down=GRAPH_ONLY_BREAKDOWN,
        )
        factor = _graph_factor(explanation)

        assert 'High-attention transfer paths' in factor['evidence']
        assert 'ACC_001 -> ACC_MULE (attention 0.91)' in factor['evidence']
        assert TEMPLATE_EVIDENCE_MARKER not in factor['evidence']

    def test_structured_edges_attached_to_factor(
        self, explainer, transaction, risk_assessment
    ):
        explanation = explainer.generate_explanation(
            transaction,
            risk_assessment,
            attention_weights=ATTENTION_EDGES,
            break_down=GRAPH_ONLY_BREAKDOWN,
        )
        factor = _graph_factor(explanation)

        assert factor['attention_edges'] == [
            {'source': 'ACC_001', 'target': 'ACC_MULE', 'weight': 0.91},
            {'source': 'ACC_MULE', 'target': 'ACC_EXIT', 'weight': 0.74},
        ]

    def test_attention_evidence_appears_in_narrative(
        self, explainer, transaction, risk_assessment
    ):
        explanation = explainer.generate_explanation(
            transaction,
            risk_assessment,
            attention_weights=ATTENTION_EDGES,
            break_down=GRAPH_ONLY_BREAKDOWN,
        )

        assert 'High-attention transfer paths' in explanation['main_narrative']

    def test_edges_sorted_descending_and_capped_at_five(self, explainer, transaction):
        edges = {
            'edges': [
                {'source': f'ACC_{i}', 'target': f'ACC_{i + 1}', 'weight': weight}
                for i, weight in enumerate([0.2, 0.9, 0.5, 0.7, 0.1, 0.8, 0.3])
            ]
        }
        factors = explainer._extract_causal_factors(
            transaction, GRAPH_ONLY_BREAKDOWN, [], edges
        )
        factor = next(f for f in factors if f['type'] == 'GRAPH')

        weights = [edge['weight'] for edge in factor['attention_edges']]
        assert len(weights) == 5
        assert weights == sorted(weights, reverse=True)
        assert weights[0] == 0.9


class TestAcceptedPayloadShapes:
    def test_production_scorer_top_relationships_shape(self, explainer, transaction):
        attention = {
            'top_relationships': [
                {
                    'source_node': 'ACC_001',
                    'target_node': 'ACC_MULE',
                    'attention_score': 0.83,
                },
            ]
        }
        factors = explainer._extract_causal_factors(
            transaction, GRAPH_ONLY_BREAKDOWN, [], attention
        )
        factor = next(f for f in factors if f['type'] == 'GRAPH')

        assert factor['attention_edges'] == [
            {'source': 'ACC_001', 'target': 'ACC_MULE', 'weight': 0.83},
        ]

    def test_flat_edge_key_mapping_shape(self, explainer, transaction):
        attention = {'ACC_001->ACC_MULE': 0.83, 'ACC_MULE->ACC_EXIT': 0.61}
        factors = explainer._extract_causal_factors(
            transaction, GRAPH_ONLY_BREAKDOWN, [], attention
        )
        factor = next(f for f in factors if f['type'] == 'GRAPH')

        assert factor['attention_edges'][0] == {
            'source': 'ACC_001', 'target': 'ACC_MULE', 'weight': 0.83,
        }

    def test_multi_head_weights_are_averaged(self, explainer):
        edges = explainer._parse_attention_edges(
            {'edges': [{'source': 'A', 'target': 'B', 'weight': [0.8, 0.6]}]}
        )

        assert edges == [{'source': 'A', 'target': 'B', 'weight': pytest.approx(0.7)}]


class TestFallbackBehavior:
    @pytest.mark.parametrize('attention_weights', [None, {}])
    def test_template_evidence_without_attention(
        self, explainer, transaction, risk_assessment, attention_weights
    ):
        explanation = explainer.generate_explanation(
            transaction,
            risk_assessment,
            attention_weights=attention_weights,
            break_down=GRAPH_ONLY_BREAKDOWN,
        )
        factor = _graph_factor(explanation)

        assert TEMPLATE_EVIDENCE_MARKER in factor['evidence']
        assert 'attention_edges' not in factor

    @pytest.mark.parametrize('attention_weights', [
        {'edges': 'not-a-list'},
        {'edges': ['not-a-dict', {'source': 'A'}, {'weight': 0.5}]},
        {'unrelated_key': 'value'},
        {'edges': [{'source': 'A', 'target': 'B', 'weight': 'high'}]},
    ])
    def test_template_fallback_on_malformed_payload(
        self, explainer, transaction, risk_assessment, attention_weights
    ):
        explanation = explainer.generate_explanation(
            transaction,
            risk_assessment,
            attention_weights=attention_weights,
            break_down=GRAPH_ONLY_BREAKDOWN,
        )
        factor = _graph_factor(explanation)

        assert TEMPLATE_EVIDENCE_MARKER in factor['evidence']
        assert 'attention_edges' not in factor

    def test_non_finite_weights_are_skipped(self, explainer):
        edges = explainer._parse_attention_edges({
            'edges': [
                {'source': 'A', 'target': 'B', 'weight': float('nan')},
                {'source': 'C', 'target': 'D', 'weight': float('inf')},
                {'source': 'E', 'target': 'F', 'weight': 0.4},
            ]
        })

        assert edges == [{'source': 'E', 'target': 'F', 'weight': 0.4}]

    def test_no_graph_factor_when_breakdown_below_threshold(
        self, explainer, transaction
    ):
        # Attention enriches an existing GRAPH factor; it must not create one
        breakdown = {'graph': 0.3, 'velocity': 0.0, 'behavior': 0.0, 'entropy': 0.0}
        factors = explainer._extract_causal_factors(
            transaction, breakdown, [], ATTENTION_EDGES
        )

        assert all(factor['type'] != 'GRAPH' for factor in factors)


class TestFactorRanking:
    def test_attention_boosts_graph_weight(self, explainer, transaction):
        breakdown = {'graph': 0.55, 'velocity': 0.0, 'behavior': 0.0, 'entropy': 0.0}
        factors = explainer._extract_causal_factors(
            transaction, breakdown, [], ATTENTION_EDGES
        )
        factor = next(f for f in factors if f['type'] == 'GRAPH')

        assert factor['weight'] == pytest.approx(0.91)

    def test_graph_weight_boost_capped_at_one(self, explainer, transaction):
        attention = {'edges': [{'source': 'A', 'target': 'B', 'weight': 3.5}]}
        factors = explainer._extract_causal_factors(
            transaction, GRAPH_ONLY_BREAKDOWN, [], attention
        )
        factor = next(f for f in factors if f['type'] == 'GRAPH')

        assert factor['weight'] == 1.0

    def test_high_attention_graph_outranks_velocity(self, explainer, transaction):
        breakdown = {'graph': 0.55, 'velocity': 0.6, 'behavior': 0.0, 'entropy': 0.0}
        factors = explainer._extract_causal_factors(
            transaction, breakdown, [], ATTENTION_EDGES
        )

        # Both factors have HIGH impact; attention lifts GRAPH above VELOCITY
        assert factors[0]['type'] == 'GRAPH'
        assert factors[1]['type'] == 'VELOCITY'

    def test_breakdown_weight_kept_when_higher_than_attention(
        self, explainer, transaction
    ):
        attention = {'edges': [{'source': 'A', 'target': 'B', 'weight': 0.2}]}
        factors = explainer._extract_causal_factors(
            transaction, GRAPH_ONLY_BREAKDOWN, [], attention
        )
        factor = next(f for f in factors if f['type'] == 'GRAPH')

        assert factor['weight'] == pytest.approx(0.8)
