"""
Unit tests for AegisGraph Sentinel models
"""

import pytest
import torch
import numpy as np

from src.models.htgat import HTGATConv, HTGAT
from src.models.temporal_encoding import TemporalEncoding
from src.models.risk_model import FraudDetectionModel


class TestHTGATConv:
    """Test HTGAT convolution layer"""
    
    def test_forward_pass(self):
        """Test basic forward pass"""
        in_channels = 32
        out_channels = 64
        num_node_types = 5
        num_edge_types = 4
        heads = 4
        
        model = HTGATConv(
            in_channels=in_channels,
            out_channels=out_channels,
            num_node_types=num_node_types,
            num_edge_types=num_edge_types,
            heads=heads,
        )
        
        # Create sample data
        num_nodes = 10
        num_edges = 20
        
        x = torch.randn(num_nodes, in_channels)
        edge_index = torch.randint(0, num_nodes, (2, num_edges))
        node_type = torch.randint(0, num_node_types, (num_nodes,))
        edge_type = torch.randint(0, num_edge_types, (num_edges,))
        
        # Forward pass
        out = model(x, edge_index, node_type, edge_type)
        
        # Check output shape
        assert out.shape == (num_nodes, heads * out_channels)
    
    def test_attention_weights(self):
        """Test attention weight computation"""
        model = HTGATConv(32, 64, 5, 4, heads=4)
        
        x = torch.randn(5, 32)
        edge_index = torch.tensor([[0, 1, 2], [1, 2, 3]])
        node_type = torch.randint(0, 5, (5,))
        edge_type = torch.randint(0, 4, (3,))
        
        out, (edge_idx, attention) = model(
            x, edge_index, node_type, edge_type,
            return_attention_weights=True
        )
        
        # Check attention weights are between 0 and 1
        assert torch.all(attention >= 0) and torch.all(attention <= 1)


class TestHTGAT:
    """Test full HTGAT model"""
    
    def test_multi_layer(self):
        """Test multi-layer HTGAT"""
        model = HTGAT(
            in_channels=32,
            hidden_channels=64,
            out_channels=32,
            num_node_types=5,
            num_edge_types=4,
            num_layers=2,
            heads=4,
        )
        
        num_nodes = 10
        num_edges = 20
        
        x = torch.randn(num_nodes, 32)
        edge_index = torch.randint(0, num_nodes, (2, num_edges))
        node_type = torch.randint(0, 5, (num_nodes,))
        edge_type = torch.randint(0, 4, (num_edges,))
        
        out = model(x, edge_index, node_type, edge_type)
        
        assert out.shape == (num_nodes, 32)


class TestTemporalEncoding:
    """Test temporal encoding"""
    
    def test_encoding_shape(self):
        """Test output shape"""
        encoder = TemporalEncoding(encoding_dim=16)
        
        timestamps = torch.tensor([0.0, 100.0, 1000.0, 10000.0])
        encoding = encoder(timestamps)
        
        assert encoding.shape == (4, 16)
    
    def test_encoding_values(self):
        """Test encoding values are bounded"""
        encoder = TemporalEncoding(encoding_dim=16)
        
        timestamps = torch.rand(100) * 86400  # Random times in 24 hours
        encoding = encoder(timestamps)
        
        # Values should be between -1 and 1 (sin/cos)
        assert torch.all(encoding >= -1) and torch.all(encoding <= 1)


class TestFraudDetectionModel:
    """Test complete fraud detection model"""
    
    def test_model_forward(self):
        """Test model forward pass"""
        model = FraudDetectionModel(
            node_feature_dim=32,
            hidden_dim=64,
            output_dim=32,
            num_node_types=5,
            num_edge_types=4,
        )
        
        num_nodes = 15
        num_edges = 30
        
        x = torch.randn(num_nodes, 32)
        edge_index = torch.randint(0, num_nodes, (2, num_edges))
        node_type = torch.randint(0, 5, (num_nodes,))
        edge_type = torch.randint(0, 4, (num_edges,))
        edge_timestamp = torch.rand(num_edges) * 86400
        
        output = model(x, edge_index, node_type, edge_type, edge_timestamp)
        
        # Check output contains risk score
        assert 'risk' in output
        assert output['risk'].shape == torch.Size([])
        
        # Risk should be between 0 and 1
        assert 0 <= output['risk'].item() <= 1
    
    def test_model_with_embedding(self):
        """Test model returns embeddings when requested"""
        model = FraudDetectionModel(
            node_feature_dim=32,
            hidden_dim=64,
            output_dim=32,
            num_node_types=5,
            num_edge_types=4,
        )
        
        num_nodes = 10
        num_edges = 20
        
        x = torch.randn(num_nodes, 32)
        edge_index = torch.randint(0, num_nodes, (2, num_edges))
        node_type = torch.randint(0, 5, (num_nodes,))
        edge_type = torch.randint(0, 4, (num_edges,))
        edge_timestamp = torch.rand(num_edges) * 86400
        
        output = model(
            x, edge_index, node_type, edge_type, edge_timestamp,
            return_embedding=True
        )
        
        assert 'node_embedding' in output
        assert output['node_embedding'].shape == (num_nodes, 32)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
