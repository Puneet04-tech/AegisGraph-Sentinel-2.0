"""
Unit tests for feature extraction modules
"""
# Working on feature extraction testing

import pytest
import numpy as np
import pandas as pd

from src.features.behavioral_biometrics import KeystrokeDynamicsAnalyzer
from src.features.velocity_calculator import Transaction, VelocityCalculator
from src.features.entropy_calculator import GraphEntropyCalculator


class TestKeystrokeDynamics:
    """Test behavioral biometrics analyzer"""
    
    def test_normal_typing(self):
        """Test with normal typing pattern"""
        analyzer = KeystrokeDynamicsAnalyzer()
        
        # Simulate normal typing (consistent timing)
        events = [
            {'key': 'a', 'timestamp': 0.0, 'event_type': 'keydown'},
            {'key': 'a', 'timestamp': 0.1, 'event_type': 'keyup'},
            {'key': 'b', 'timestamp': 0.15, 'event_type': 'keydown'},
            {'key': 'b', 'timestamp': 0.25, 'event_type': 'keyup'},
            {'key': 'c', 'timestamp': 0.3, 'event_type': 'keydown'},
            {'key': 'c', 'timestamp': 0.4, 'event_type': 'keyup'},
        ]
        
        features = analyzer.analyze(events)
        
        assert 'stress_score' in features
        assert 0 <= features['stress_score'] <= 1
        assert features['wpm'] > 0
    
    def test_stressed_typing(self):
        """Test with stressed typing pattern (high variability)"""
        analyzer = KeystrokeDynamicsAnalyzer()
        
        # Simulate stressed typing (erratic timing)
        events = [
            {'key': 'a', 'timestamp': 0.0, 'event_type': 'keydown'},
            {'key': 'a', 'timestamp': 0.05, 'event_type': 'keyup'},
            {'key': 'b', 'timestamp': 0.5, 'event_type': 'keydown'},
            {'key': 'b', 'timestamp': 0.55, 'event_type': 'keyup'},
            {'key': 'c', 'timestamp': 0.6, 'event_type': 'keydown'},
            {'key': 'c', 'timestamp': 1.2, 'event_type': 'keyup'},
        ]
        
        features = analyzer.analyze(events)
        
        # Stressed typing should have higher stress score
        assert features['stress_score'] > 0.3


class TestVelocityCalculator:
    """Test transaction velocity calculator"""
    
    def test_kinetic_energy(self):
        """Test kinetic energy calculation"""
        calculator = VelocityCalculator()
        
        transactions = pd.DataFrame({
            'account_id': ['A', 'A', 'A'],
            'amount': [100, 200, 150],
            'timestamp': [0, 60, 120],
        })
        
        energy = calculator.calculate_kinetic_energy(transactions)
        
        assert energy >= 0
        assert isinstance(energy, float)
    
    def test_burst_detection(self):
        """Test burst detection"""
        calculator = VelocityCalculator()
        
        # Create burst pattern (many transactions in short time)
        recent = pd.DataFrame({
            'account_id': ['A'] * 10,
            'amount': [100] * 10,
            'timestamp': range(0, 100, 10),  # 10 txns in 100 seconds
        })
        
        historical = pd.DataFrame({
            'account_id': ['A'] * 10,
            'amount': [100] * 10,
            'timestamp': range(0, 10000, 1000),  # 10 txns in 10000 seconds
        })
        
        burst_score = calculator.detect_burst(recent, historical)
        
        # Should detect burst
        assert burst_score > 1.0
    
    def test_chain_velocity(self):
        """Test chain velocity through network"""
        calculator = VelocityCalculator()
        
        # Create transaction chain A -> B -> C
        transactions = [
            {'from': 'A', 'to': 'B', 'amount': 100, 'timestamp': 0},
            {'from': 'B', 'to': 'C', 'amount': 90, 'timestamp': 60},
        ]
        
        velocity = calculator.calculate_chain_velocity(transactions)
        
        assert velocity > 0

    def test_chain_velocity_reuses_single_source_shortest_paths(self, monkeypatch):
        """Test that repeated sources reuse cached shortest-path traversals."""
        import networkx as nx

        calculator = VelocityCalculator()
        graph = nx.Graph()
        graph.add_edges_from([
            ('A', 'B'),
            ('B', 'C'),
            ('C', 'D'),
        ])

        transactions = [
            Transaction(source='A', target='B', amount=100, timestamp=0, txn_id='txn-1'),
            Transaction(source='A', target='C', amount=100, timestamp=10, txn_id='txn-2'),
            Transaction(source='A', target='D', amount=100, timestamp=20, txn_id='txn-3'),
        ]

        call_count = {"count": 0}
        original = nx.single_source_shortest_path_length

        def counting_single_source_shortest_path_length(*args, **kwargs):
            call_count["count"] += 1
            return original(*args, **kwargs)

        monkeypatch.setattr(
            "src.features.velocity_calculator.nx.single_source_shortest_path_length",
            counting_single_source_shortest_path_length,
        )

        features = calculator.compute_chain_velocity(transactions, graph)

        assert call_count["count"] == 1
        assert features["total_distance"] == 5
        assert features["chain_velocity"] == 0.25


class TestGraphEntropyCalculator:
    """Test graph entropy calculator"""
    
    def test_neighbor_entropy(self):
        """Test neighbor entropy calculation"""
        calculator = GraphEntropyCalculator()
        
        # Create simple graph
        import networkx as nx
        G = nx.Graph()
        G.add_edges_from([
            ('A', 'B'), ('A', 'C'), ('B', 'C'),
            ('C', 'D'), ('D', 'E')
        ])
        
        # Node C should have moderate entropy (connects different parts)
        entropy = calculator.calculate_neighbor_entropy(G, 'C')
        
        assert entropy >= 0
    
    def test_mule_detection(self):
        """Test detection of mule accounts (high entropy star pattern)"""
        calculator = GraphEntropyCalculator()
        
        import networkx as nx
        G = nx.DiGraph()
        
        # Create star pattern (mule account M receives from many, sends to few)
        for i in range(10):
            G.add_edge(f'source_{i}', 'M', amount=100, timestamp=i*60)
        
        G.add_edge('M', 'destination', amount=900, timestamp=600)
        
        # Calculate entropy for mule node
        entropy = calculator.calculate_neighbor_entropy(G, 'M')
        
        # Mule should have high entropy due to many diverse neighbors
        assert entropy > 0


class TestFeatureIntegration:
    """Test integration of multiple features"""
    
    def test_all_features_together(self):
        """Test combining all feature extractors"""
        biometrics_analyzer = KeystrokeDynamicsAnalyzer()
        velocity_calculator = VelocityCalculator()
        entropy_calculator = GraphEntropyCalculator()
        
        # Simulate a complete transaction with all features
        keystroke_events = [
            {'key': 'a', 'timestamp': 0.0, 'event_type': 'keydown'},
            {'key': 'a', 'timestamp': 0.1, 'event_type': 'keyup'},
        ]
        
        transactions = pd.DataFrame({
            'account_id': ['A', 'A'],
            'amount': [100, 200],
            'timestamp': [0, 60],
        })
        
        import networkx as nx
        graph = nx.Graph()
        graph.add_edge('A', 'B', amount=100)
        
        # Calculate all features
        biometrics = biometrics_analyzer.analyze(keystroke_events)
        kinetic_energy = velocity_calculator.calculate_kinetic_energy(transactions)
        entropy = entropy_calculator.calculate_neighbor_entropy(graph, 'A')
        
        # Verify all features are computed
        assert isinstance(biometrics, dict)
        assert isinstance(kinetic_energy, float)
        assert isinstance(entropy, float)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
