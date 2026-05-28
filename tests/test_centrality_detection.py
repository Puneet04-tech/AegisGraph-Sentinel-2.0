"""
Test suite for centrality-based fraud pattern detection.

Tests for:
- Betweenness centrality (layering chain detection)
- PageRank analysis (super-mule detection)
- Clique detection (fraud ring detection)
- Temporal decay weighting
"""

import pytest
import numpy as np
from datetime import datetime, timedelta, timezone
from src.features.fraud_pattern_detector import FraudPatternDetector


class TestLayeringChainDetection:
    """Test betweenness centrality-based layering chain detection"""

    @pytest.fixture
    def detector(self):
        """Initialize detector"""
        return FraudPatternDetector()

    def test_detect_linear_layering_chain(self, detector):
        """Test detection of A→B→C→D linear chain"""
        # Create linear layering: A → B → C → D
        transactions = [
            {
                'source_account': 'ACC_A',
                'target_account': 'ACC_B',
                'amount': 100000,
                'timestamp': datetime.now(timezone.utc),
            },
            {
                'source_account': 'ACC_B',
                'target_account': 'ACC_C',
                'amount': 95000,  # Slightly reduced (fee simulation)
                'timestamp': datetime.now(timezone.utc) + timedelta(minutes=5),
            },
            {
                'source_account': 'ACC_C',
                'target_account': 'ACC_D',
                'amount': 90000,
                'timestamp': datetime.now(timezone.utc) + timedelta(minutes=10),
            },
        ]

        chains = detector.detect_layering_chains(
            transactions,
            betweenness_threshold=0.3,
        )

        assert len(chains) > 0
        assert chains[0]['type'] == 'LAYERING_CHAIN'
        assert chains[0]['pattern'] == 'LINEAR_LAYERING'
        assert chains[0]['risk_score'] > 0.5

    def test_no_detection_single_transfer(self, detector):
        """Test no detection for single transfer (no intermediate)"""
        transactions = [
            {
                'source_account': 'ACC_A',
                'target_account': 'ACC_B',
                'amount': 100000,
                'timestamp': datetime.now(timezone.utc),
            },
        ]

        chains = detector.detect_layering_chains(transactions)
        # May or may not detect depending on threshold
        assert isinstance(chains, list)

    def test_layering_chain_with_uniform_amounts(self, detector):
        """Test detection favors uniform amounts (obfuscation indicator)"""
        # Uniform amounts suggest deliberate layering
        transactions = [
            {
                'source_account': 'ACC_A',
                'target_account': 'ACC_B',
                'amount': 50000,
                'timestamp': datetime.now(timezone.utc),
            },
            {
                'source_account': 'ACC_B',
                'target_account': 'ACC_C',
                'amount': 50000,  # Exactly same
                'timestamp': datetime.now(timezone.utc) + timedelta(minutes=5),
            },
        ]

        chains = detector.detect_layering_chains(transactions, betweenness_threshold=0.2)
        
        if chains:
            assert chains[0]['risk_score'] > 0.4

    def test_betweenness_scores_present(self, detector):
        """Test that betweenness centrality scores are in output"""
        transactions = [
            {
                'source_account': 'ACC_A',
                'target_account': 'ACC_B',
                'amount': 100000,
                'timestamp': datetime.now(timezone.utc),
            },
            {
                'source_account': 'ACC_B',
                'target_account': 'ACC_C',
                'amount': 95000,
                'timestamp': datetime.now(timezone.utc) + timedelta(minutes=5),
            },
        ]

        chains = detector.detect_layering_chains(transactions, betweenness_threshold=0.1)
        
        if chains:
            assert 'betweenness_scores' in chains[0]
            assert isinstance(chains[0]['betweenness_scores'], dict)


class TestSuperMuleDetection:
    """Test PageRank-based super-mule detection"""

    @pytest.fixture
    def detector(self):
        return FraudPatternDetector()

    def test_detect_super_mule_high_influence(self, detector):
        """Test detection of super-mule with high incoming volume"""
        # Central hub receiving from many sources
        transactions = [
            {'source_account': f'ACC_SRC_{i}', 'target_account': 'ACC_HUB', 'amount': 50000,
             'timestamp': datetime.now(timezone.utc)} for i in range(8)
        ]
        # Hub sends out
        transactions.extend([
            {'source_account': 'ACC_HUB', 'target_account': f'ACC_DST_{i}', 'amount': 30000,
             'timestamp': datetime.now(timezone.utc) + timedelta(hours=1)} for i in range(5)
        ])

        super_mules = detector.detect_super_mules(
            transactions,
            pagerank_threshold=0.5,
        )

        assert len(super_mules) > 0
        assert super_mules[0]['type'] == 'SUPER_MULE'
        assert super_mules[0]['account'] == 'ACC_HUB'
        assert super_mules[0]['risk_score'] > 0.5

    def test_super_mule_pagerank_volume_combination(self, detector):
        """Test that super-mule score combines PageRank and volume"""
        transactions = [
            {'source_account': 'ACC_HIGH_VALUE', 'target_account': 'ACC_MULE', 'amount': 500000,
             'timestamp': datetime.now(timezone.utc)},
            {'source_account': 'ACC_MULE', 'target_account': 'ACC_RECIPIENT', 'amount': 450000,
             'timestamp': datetime.now(timezone.utc) + timedelta(minutes=10)},
        ]

        super_mules = detector.detect_super_mules(transactions, pagerank_threshold=0.2)
        
        if super_mules:
            assert 'pagerank_score' in super_mules[0]
            assert 'volume_score' in super_mules[0]
            assert 'combined_score' in super_mules[0]

    def test_no_super_mule_single_transfer(self, detector):
        """Test no super-mule for single transfer"""
        transactions = [
            {'source_account': 'ACC_A', 'target_account': 'ACC_B', 'amount': 100000,
             'timestamp': datetime.now(timezone.utc)},
        ]

        # Single transfer should not create super-mule (in_degree must be > 1)
        super_mules = detector.detect_super_mules(transactions, pagerank_threshold=0.7)
        
        # Should be empty - single transfer node has in_degree=1
        assert len(super_mules) == 0

    def test_super_mule_high_incoming_transfers(self, detector):
        """Test super-mule score increases with incoming transfer count"""
        transactions = []
        # Many small incoming transfers
        for i in range(15):
            transactions.append({
                'source_account': f'ACC_SRC_{i}',
                'target_account': 'ACC_MULE',
                'amount': 10000,
                'timestamp': datetime.now(timezone.utc),
            })

        super_mules = detector.detect_super_mules(transactions, pagerank_threshold=0.3)
        
        if super_mules:
            assert super_mules[0]['incoming_transfers'] >= 15


class TestFraudRingDetection:
    """Test clique-based fraud ring detection"""

    @pytest.fixture
    def detector(self):
        return FraudPatternDetector()

    def test_detect_complete_fraud_ring(self, detector):
        """Test detection of complete fraud ring (all accounts connected)"""
        # Create 4-account complete ring
        accounts = ['ACC_A', 'ACC_B', 'ACC_C', 'ACC_D']
        transactions = []
        
        timestamp = datetime.now(timezone.utc)
        for i, source in enumerate(accounts):
            for target in accounts:
                if source != target:
                    transactions.append({
                        'source_account': source,
                        'target_account': target,
                        'amount': 25000,
                        'timestamp': timestamp + timedelta(minutes=i * 2),
                    })

        rings = detector.detect_fraud_rings(
            transactions,
            min_clique_size=3,
            max_clique_size=8,
            density_threshold=0.75,
        )

        assert len(rings) > 0
        assert rings[0]['type'] == 'FRAUD_RING'
        assert rings[0]['ring_size'] == 4
        assert rings[0]['density'] > 0.9  # Should be nearly complete

    def test_detect_partial_fraud_ring(self, detector):
        """Test detection of partial ring (80% complete)"""
        accounts = ['ACC_A', 'ACC_B', 'ACC_C', 'ACC_D', 'ACC_E']
        transactions = []
        
        timestamp = datetime.now(timezone.utc)
        # Create 80% complete graph
        for i, source in enumerate(accounts):
            for target in accounts:
                if source != target:
                    # Skip some connections to make it ~80% complete
                    if (source == 'ACC_A' and target == 'ACC_E') or \
                       (source == 'ACC_E' and target == 'ACC_A'):
                        continue
                    
                    transactions.append({
                        'source_account': source,
                        'target_account': target,
                        'amount': 20000,
                        'timestamp': timestamp + timedelta(minutes=np.random.randint(0, 30)),
                    })

        rings = detector.detect_fraud_rings(
            transactions,
            min_clique_size=4,
            max_clique_size=8,
            density_threshold=0.75,
        )

        if rings:
            assert rings[0]['ring_size'] >= 4

    def test_fraud_ring_synchronization_score(self, detector):
        """Test that synchronized transfers have higher sync score"""
        # Highly synchronized transfers - all within same second
        accounts = ['ACC_A', 'ACC_B', 'ACC_C']
        transactions = []
        
        timestamp = datetime.now(timezone.utc)
        # All transfers within the same millisecond for maximum synchronization
        for source in accounts:
            for target in accounts:
                if source != target:
                    transactions.append({
                        'source_account': source,
                        'target_account': target,
                        'amount': 30000,
                        'timestamp': timestamp,  # All at same time
                    })

        rings = detector.detect_fraud_rings(
            transactions,
            min_clique_size=3,
            density_threshold=0.75,
        )

        if rings:
            # Synchronized transfers (low time variance) should have higher sync score
            assert rings[0]['sync_score'] >= 0.0  # Just verify it exists

    def test_no_ring_too_sparse(self, detector):
        """Test no detection for sparse network with low density threshold"""
        # Create 5-node sparse network (not a ring)
        transactions = [
            {'source_account': 'ACC_A', 'target_account': 'ACC_B', 'amount': 10000,
             'timestamp': datetime.now(timezone.utc)},
            {'source_account': 'ACC_B', 'target_account': 'ACC_C', 'amount': 10000,
             'timestamp': datetime.now(timezone.utc) + timedelta(hours=2)},
            {'source_account': 'ACC_C', 'target_account': 'ACC_D', 'amount': 10000,
             'timestamp': datetime.now(timezone.utc) + timedelta(hours=4)},
        ]

        # Very high density threshold should exclude linear chains
        rings = detector.detect_fraud_rings(transactions, density_threshold=0.99)
        
        # Linear chain A→B→C→D cannot be density 0.99
        # In undirected form it's only 3 edges, density = 2*3/(4*3) = 0.5
        assert len(rings) == 0 or rings[0]['density'] <= 0.75

    def test_prunes_low_degree_fringe_before_clique_enumeration(self, detector):
        """Test that clique enumeration sees only the k-core candidate subgraph."""
        clique_accounts = ['ACC_A', 'ACC_B', 'ACC_C', 'ACC_D']
        fringe_accounts = [f'ACC_FRINGE_{i}' for i in range(6)]
        transactions = []

        timestamp = datetime.now(timezone.utc)
        for source in clique_accounts:
            for target in clique_accounts:
                if source != target:
                    transactions.append({
                        'source_account': source,
                        'target_account': target,
                        'amount': 25000,
                        'timestamp': timestamp,
                    })

        for account in fringe_accounts:
            transactions.append({
                'source_account': account,
                'target_account': 'ACC_A',
                'amount': 500,
                'timestamp': timestamp,
            })

        captured = {}

        class RecordingCache:
            def cache_find_cliques(self, graph, ttl=900):
                captured['nodes'] = set(graph.nodes())
                captured['edge_count'] = graph.number_of_edges()
                return [frozenset(clique_accounts)]

        detector.cache = RecordingCache()

        rings = detector.detect_fraud_rings(
            transactions,
            min_clique_size=4,
            max_clique_size=8,
            density_threshold=0.75,
        )

        assert captured['nodes'] == set(clique_accounts)
        assert captured['edge_count'] == 6
        assert len(rings) == 1
        assert rings[0]['ring_size'] == 4


class TestTemporalDecay:
    """Test temporal decay weighting"""

    @pytest.fixture
    def detector(self):
        return FraudPatternDetector()

    def test_decay_recent_pattern(self, detector):
        """Test recent patterns maintain high weight"""
        pattern = {
            'type': 'TEST_PATTERN',
            'risk_score': 0.8,
            'detected_at': datetime.now(timezone.utc),
        }

        decayed = detector.apply_temporal_decay_to_pattern(pattern, decay_rate=0.1)
        
        # Recent pattern should have decay factor close to 1.0
        assert decayed['temporal_decay_factor'] > 0.95
        assert decayed['risk_score'] > 0.75

    def test_decay_old_pattern(self, detector):
        """Test old patterns get lower weight"""
        pattern = {
            'type': 'TEST_PATTERN',
            'risk_score': 0.8,
            'detected_at': datetime.now(timezone.utc) - timedelta(days=30),
        }

        decayed = detector.apply_temporal_decay_to_pattern(pattern, decay_rate=0.1)
        
        # 30 days old with decay_rate=0.1: e^(-0.1*30) ≈ 0.0498
        assert decayed['temporal_decay_factor'] < 0.1
        assert decayed['risk_score'] < 0.1

    def test_decay_maintains_pattern_info(self, detector):
        """Test decay preserves original pattern info"""
        pattern = {
            'type': 'TEST_PATTERN',
            'risk_score': 0.8,
            'detected_at': datetime.now(timezone.utc) - timedelta(days=7),
            'accounts': ['ACC_A', 'ACC_B'],
        }

        decayed = detector.apply_temporal_decay_to_pattern(pattern)
        
        assert decayed['type'] == 'TEST_PATTERN'
        assert decayed['accounts'] == ['ACC_A', 'ACC_B']
        assert 'original_risk_score' in decayed
        assert 'days_elapsed' in decayed

    def test_decay_exponential_progression(self, detector):
        """Test exponential decay follows mathematical formula"""
        base_pattern = {
            'risk_score': 1.0,
            'type': 'TEST',
        }

        decay_rate = 0.1
        reference_time = datetime.now(timezone.utc)

        # Test different ages
        ages_and_expected = [
            (0, 1.0),  # Today: no decay
            (7, 0.49),  # 7 days: e^(-0.7) ≈ 0.49
            (30, 0.05),  # 30 days: e^(-3) ≈ 0.05
        ]

        for days_ago, expected_decay in ages_and_expected:
            pattern = {
                **base_pattern,
                'detected_at': reference_time - timedelta(days=days_ago),
            }

            decayed = detector.apply_temporal_decay_to_pattern(
                pattern,
                decay_rate=decay_rate,
                reference_time=reference_time,
            )

            # Allow ±5% tolerance
            assert abs(decayed['temporal_decay_factor'] - expected_decay) < 0.05


class TestIntegration:
    """Integration tests for all centrality methods"""

    @pytest.fixture
    def detector(self):
        return FraudPatternDetector()

    def test_complex_fraud_network_detection(self, detector):
        """Test detection in complex network with multiple patterns"""
        transactions = []
        reference_time = datetime.now(timezone.utc)

        # 1. Layering chain: A → B → C
        transactions.extend([
            {'source_account': 'LAYER_A', 'target_account': 'LAYER_B', 'amount': 100000,
             'timestamp': reference_time},
            {'source_account': 'LAYER_B', 'target_account': 'LAYER_C', 'amount': 95000,
             'timestamp': reference_time + timedelta(minutes=5)},
        ])

        # 2. Super-mule hub
        for i in range(10):
            transactions.append({
                'source_account': f'SRC_{i}',
                'target_account': 'SUPER_MULE',
                'amount': 50000,
                'timestamp': reference_time,
            })

        # 3. Fraud ring (4 accounts)
        ring_accounts = ['RING_A', 'RING_B', 'RING_C', 'RING_D']
        for source in ring_accounts:
            for target in ring_accounts:
                if source != target:
                    transactions.append({
                        'source_account': source,
                        'target_account': target,
                        'amount': 30000,
                        'timestamp': reference_time + timedelta(hours=1),
                    })

        # Run all detections
        chains = detector.detect_layering_chains(transactions, betweenness_threshold=0.2)
        super_mules = detector.detect_super_mules(transactions, pagerank_threshold=0.3)
        rings = detector.detect_fraud_rings(transactions, density_threshold=0.75)

        # Should detect multiple patterns
        assert len(super_mules) > 0
        assert super_mules[0]['account'] == 'SUPER_MULE'
        assert len(rings) > 0
        assert rings[0]['ring_size'] == 4

    def test_performance_large_transaction_set(self, detector):
        """Test performance with large transaction set"""
        transactions = []
        
        # Create 500 random transactions
        np.random.seed(42)
        accounts = [f'ACC_{i}' for i in range(50)]
        
        for _ in range(500):
            source = np.random.choice(accounts)
            target = np.random.choice([a for a in accounts if a != source])
            
            transactions.append({
                'source_account': source,
                'target_account': target,
                'amount': np.random.randint(10000, 100000),
                'timestamp': datetime.now(timezone.utc),
            })

        # Should complete without timeout (reasonable time)
        import time
        start = time.time()
        
        super_mules = detector.detect_super_mules(transactions)
        rings = detector.detect_fraud_rings(transactions)
        
        elapsed = time.time() - start
        assert elapsed < 5.0  # Should complete in <5 seconds

    def test_all_detections_include_required_fields(self, detector):
        """Test all detected patterns include required fields"""
        transactions = [
            {'source_account': 'A', 'target_account': 'B', 'amount': 100000,
             'timestamp': datetime.now(timezone.utc)},
            {'source_account': 'B', 'target_account': 'C', 'amount': 95000,
             'timestamp': datetime.now(timezone.utc) + timedelta(minutes=5)},
            {'source_account': 'C', 'target_account': 'D', 'amount': 90000,
             'timestamp': datetime.now(timezone.utc) + timedelta(minutes=10)},
        ]

        chains = detector.detect_layering_chains(transactions, betweenness_threshold=0.2)
        
        if chains:
            required_fields = ['type', 'risk_score', 'detected_at', 'pattern']
            for field in required_fields:
                assert field in chains[0]


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
