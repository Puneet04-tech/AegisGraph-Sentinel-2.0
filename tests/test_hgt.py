import os
import pytest
import torch
from src.models.hgt import HGTConv, HGT
from src.models.htgat import HTGAT
from src.models.risk_model import FraudDetectionModel

if os.getenv("RUN_TORCH_TESTS", "").lower() != "true":
    pytest.skip("PyTorch tests require RUN_TORCH_TESTS=true", allow_module_level=True)

def test_hgt_conv_forward():
    in_channels = 32
    out_channels = 64
    num_node_types = 5
    num_edge_types = 4
    heads = 4
    
    model = HGTConv(
        in_channels=in_channels,
        out_channels=out_channels,
        num_node_types=num_node_types,
        num_edge_types=num_edge_types,
        heads=heads,
    )
    
    num_nodes = 10
    num_edges = 20
    
    x = torch.randn(num_nodes, in_channels)
    edge_index = torch.randint(0, num_nodes, (2, num_edges))
    node_type = torch.randint(0, num_node_types, (num_nodes,))
    edge_type = torch.randint(0, num_edge_types, (num_edges,))
    
    out = model(x, edge_index, node_type, edge_type)
    assert out.shape == (num_nodes, heads * out_channels)
    
    # Check attention weights return
    model.eval()
    out, (edge_idx, attention) = model(
        x, edge_index, node_type, edge_type,
        return_attention_weights=True
    )
    assert torch.all(attention >= 0) and torch.all(attention <= 1)
    assert attention.shape == (num_edges, heads)

def test_hgt_multi_layer():
    model = HGT(
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

def test_risk_model_with_hgt():
    model = FraudDetectionModel(
        node_feature_dim=32,
        hidden_dim=64,
        output_dim=32,
        num_node_types=5,
        num_edge_types=4,
        model_type='hgt',
    )
    
    num_nodes = 15
    num_edges = 30
    
    x = torch.randn(num_nodes, 32)
    edge_index = torch.randint(0, num_nodes, (2, num_edges))
    node_type = torch.randint(0, 5, (num_nodes,))
    edge_type = torch.randint(0, 4, (num_edges,))
    edge_timestamp = torch.rand(num_edges) * 86400
    
    output = model(x, edge_index, node_type, edge_type, edge_timestamp)
    
    assert 'risk' in output
    assert 0 <= output['risk'].item() <= 1
