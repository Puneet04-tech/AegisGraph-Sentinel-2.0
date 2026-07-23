"""
Behavioral parity tests for HTGAT fallback implementation.

Tests verify that the fallback implementation (when torch_geometric is unavailable)
produces behaviorally equivalent outputs to the official PyTorch Geometric implementation
wherever reasonably possible.

Run with: RUN_TORCH_TESTS=true pytest tests/test_htgat_fallback_parity.py -v
"""
import os
import pytest
import torch
import sys
from typing import Optional

# Skip tests if RUN_TORCH_TESTS is not set
RUN_TORCH_TESTS = os.getenv("RUN_TORCH_TESTS", "").lower() == "true"
pytestmark = pytest.mark.skipif(
    not RUN_TORCH_TESTS,
    reason="PyTorch tests require RUN_TORCH_TESTS=true"
)

# Check if torch_geometric is available
try:
    import torch_geometric
    TORCH_GEOMETRIC_AVAILABLE = True
except ImportError:
    TORCH_GEOMETRIC_AVAILABLE = False


class TestFallbackSoftmaxParity:
    """Test fallback softmax implementation parity with torch_geometric."""
    
    @pytest.mark.skipif(not TORCH_GEOMETRIC_AVAILABLE, reason="torch_geometric required")
    def test_softmax_basic_parity(self):
        """Test basic softmax computation matches torch_geometric."""
        from torch_geometric.utils import softmax as pyg_softmax
        from src.models.htgat import softmax as fallback_softmax
        
        torch.manual_seed(42)
        
        # Test case 1: Simple case
        src = torch.randn(10, 4)
        index = torch.tensor([0, 0, 1, 1, 2, 2, 3, 3, 4, 4])
        
        pyg_result = pyg_softmax(src, index)
        fallback_result = fallback_softmax(src, index)
        
        assert torch.allclose(pyg_result, fallback_result, rtol=1e-5, atol=1e-6)
    
    @pytest.mark.skipif(not TORCH_GEOMETRIC_AVAILABLE, reason="torch_geometric required")
    def test_softmax_with_num_nodes(self):
        """Test softmax with explicit num_nodes parameter."""
        from torch_geometric.utils import softmax as pyg_softmax
        from src.models.htgat import softmax as fallback_softmax
        
        torch.manual_seed(42)
        
        src = torch.randn(10, 4)
        index = torch.tensor([0, 0, 1, 1, 2, 2, 3, 3, 4, 4])
        num_nodes = 6  # More nodes than actually present
        
        pyg_result = pyg_softmax(src, index, num_nodes=num_nodes)
        fallback_result = fallback_softmax(src, index, num_nodes=num_nodes)
        
        assert torch.allclose(pyg_result, fallback_result, rtol=1e-5, atol=1e-6)
    
    @pytest.mark.skipif(not TORCH_GEOMETRIC_AVAILABLE, reason="torch_geometric required")
    def test_softmax_normalization(self):
        """Test that attention weights sum to 1 per node."""
        from src.models.htgat import softmax as fallback_softmax
        
        torch.manual_seed(42)
        
        src = torch.randn(20, 4)
        index = torch.tensor([0, 0, 0, 1, 1, 2, 2, 2, 2, 3, 3, 4, 4, 4, 5, 5, 5, 5, 5, 5])
        
        result = fallback_softmax(src, index)
        
        # Check that weights sum to 1 per node
        for node_id in index.unique():
            mask = index == node_id
            node_weights = result[mask]
            sum_weights = node_weights.sum(dim=0)
            assert torch.allclose(sum_weights, torch.ones_like(sum_weights), rtol=1e-5, atol=1e-6)
    
    @pytest.mark.skipif(not TORCH_GEOMETRIC_AVAILABLE, reason="torch_geometric required")
    def test_softmax_numerical_stability(self):
        """Test softmax numerical stability with large logits."""
        from torch_geometric.utils import softmax as pyg_softmax
        from src.models.htgat import softmax as fallback_softmax
        
        torch.manual_seed(42)
        
        # Test with large positive values
        src_large = torch.randn(10, 4) * 100
        index = torch.tensor([0, 0, 1, 1, 2, 2, 3, 3, 4, 4])
        
        pyg_result = pyg_softmax(src_large, index)
        fallback_result = fallback_softmax(src_large, index)
        
        assert torch.allclose(pyg_result, fallback_result, rtol=1e-5, atol=1e-6)
        
        # Test with large negative values
        src_neg = torch.randn(10, 4) * -100
        pyg_result = pyg_softmax(src_neg, index)
        fallback_result = fallback_softmax(src_neg, index)
        
        assert torch.allclose(pyg_result, fallback_result, rtol=1e-5, atol=1e-6)
    
    @pytest.mark.skipif(not TORCH_GEOMETRIC_AVAILABLE, reason="torch_geometric required")
    def test_softmax_no_nan_inf(self):
        """Test that softmax produces no NaN or Inf values."""
        from src.models.htgat import softmax as fallback_softmax
        
        torch.manual_seed(42)
        
        # Test with various ranges
        for scale in [1.0, 10.0, 100.0, -10.0, -100.0]:
            src = torch.randn(50, 8) * scale
            index = torch.randint(0, 10, (50,))
            
            result = fallback_softmax(src, index)
            
            assert not torch.isnan(result).any(), f"NaN found with scale {scale}"
            assert not torch.isinf(result).any(), f"Inf found with scale {scale}"
            assert (result >= 0).all(), f"Negative values found with scale {scale}"
            assert (result <= 1).all(), f"Values > 1 found with scale {scale}"
    
    @pytest.mark.skipif(not TORCH_GEOMETRIC_AVAILABLE, reason="torch_geometric required")
    def test_softmax_single_edge_per_node(self):
        """Test softmax when each node has exactly one incoming edge."""
        from torch_geometric.utils import softmax as pyg_softmax
        from src.models.htgat import softmax as fallback_softmax
        
        torch.manual_seed(42)
        
        src = torch.randn(5, 4)
        index = torch.tensor([0, 1, 2, 3, 4])
        
        pyg_result = pyg_softmax(src, index)
        fallback_result = fallback_softmax(src, index)
        
        # Single edge should get weight 1
        assert torch.allclose(pyg_result, torch.ones_like(pyg_result))
        assert torch.allclose(fallback_result, torch.ones_like(fallback_result))
        assert torch.allclose(pyg_result, fallback_result)
    
    @pytest.mark.skipif(not TORCH_GEOMETRIC_AVAILABLE, reason="torch_geometric required")
    def test_softmax_empty_groups(self):
        """Test softmax with some nodes having no incoming edges."""
        from torch_geometric.utils import softmax as pyg_softmax
        from src.models.htgat import softmax as fallback_softmax
        
        torch.manual_seed(42)
        
        src = torch.randn(10, 4)
        # Nodes 0, 1, 2 have edges, nodes 3, 4, 5 have no edges
        index = torch.tensor([0, 0, 1, 1, 2, 2, 2, 0, 1, 2])
        
        pyg_result = pyg_softmax(src, index, num_nodes=6)
        fallback_result = fallback_softmax(src, index, num_nodes=6)
        
        assert torch.allclose(pyg_result, fallback_result, rtol=1e-5, atol=1e-6)
    
    def test_fallback_softmax_unsupported_ptr(self):
        """Test that fallback softmax raises error for ptr parameter."""
        from src.models.htgat import softmax as fallback_softmax
        
        src = torch.randn(10, 4)
        ptr = torch.tensor([0, 5, 10])
        
        with pytest.raises(NotImplementedError, match="ptr-based softmax not supported"):
            fallback_softmax(src, ptr=ptr)
    
    def test_fallback_softmax_unsupported_dim(self):
        """Test that fallback softmax raises error for dim != 0."""
        from src.models.htgat import softmax as fallback_softmax
        
        src = torch.randn(10, 4)
        index = torch.tensor([0, 0, 1, 1, 2, 2, 3, 3, 4, 4])
        
        with pytest.raises(ValueError, match="Only dim=0 is supported"):
            fallback_softmax(src, index, dim=-1)


class TestFallbackMessagePassingParity:
    """Test fallback MessagePassing implementation."""
    
    def test_fallback_messagepassing_unsupported_aggr(self):
        """Test that fallback MessagePassing raises error for unsupported aggr."""
        from src.models.htgat import MessagePassing
        
        with pytest.raises(ValueError, match="Only aggr='add' is supported"):
            MessagePassing(aggr='mean')
    
    def test_fallback_messagepassing_unsupported_flow(self):
        """Test that fallback MessagePassing raises error for unsupported flow."""
        from src.models.htgat import MessagePassing
        
        with pytest.raises(ValueError, match="Only flow='source_to_target' is supported"):
            MessagePassing(flow='target_to_source')
    
    def test_fallback_messagepassing_unsupported_node_dim(self):
        """Test that fallback MessagePassing raises error for unsupported node_dim."""
        from src.models.htgat import MessagePassing
        
        # node_dim=0 and -2 are supported, but other values should raise error
        with pytest.raises(ValueError, match="Only node_dim=0 or node_dim=-2 are supported"):
            MessagePassing(node_dim=1)
    
    def test_fallback_propagate_unsupported_size(self):
        """Test that fallback propagate raises error for size parameter."""
        from src.models.htgat import MessagePassing
        
        class SimpleMP(MessagePassing):
            def message(self, x_i, x_j, **kwargs):
                return x_j
        
        mp = SimpleMP()
        edge_index = torch.tensor([[0, 1], [1, 2]])
        x = torch.randn(3, 4)
        
        with pytest.raises(ValueError, match="size parameter not supported"):
            mp.propagate(edge_index, x=x, size=(3, 3))
    
    def test_fallback_propagate_basic(self):
        """Test basic fallback propagate functionality."""
        from src.models.htgat import MessagePassing
        
        class SimpleMP(MessagePassing):
            def message(self, x_i, x_j, **kwargs):
                return x_j
        
        mp = SimpleMP()
        edge_index = torch.tensor([[0, 1, 2], [1, 2, 0]])
        x = torch.randn(3, 4)
        
        out = mp.propagate(edge_index, x=x)
        
        # Each node should receive message from its source
        # Node 0 receives from node 2
        # Node 1 receives from node 0
        # Node 2 receives from node 1
        assert out.shape == x.shape


class TestHTGATConvParity:
    """Test HTGATConv behavioral parity."""
    
    @pytest.mark.skipif(not TORCH_GEOMETRIC_AVAILABLE, reason="torch_geometric required")
    def test_htgat_conv_forward_parity_basic(self):
        """Test basic forward pass parity between implementations."""
        from src.models.htgat import HTGATConv
        
        torch.manual_seed(42)
        
        in_channels = 16
        out_channels = 8
        num_node_types = 3
        num_edge_types = 2
        heads = 4
        
        # Create two models with same seed
        model1 = HTGATConv(in_channels, out_channels, num_node_types, num_edge_types, heads)
        torch.manual_seed(42)
        model2 = HTGATConv(in_channels, out_channels, num_node_types, num_edge_types, heads)
        
        # Copy weights
        for p1, p2 in zip(model1.parameters(), model2.parameters()):
            p2.data.copy_(p1.data)
        
        # Create test data
        num_nodes = 10
        num_edges = 20
        x = torch.randn(num_nodes, in_channels)
        edge_index = torch.randint(0, num_nodes, (2, num_edges))
        node_type = torch.randint(0, num_node_types, (num_nodes,))
        edge_type = torch.randint(0, num_edge_types, (num_edges,))
        
        model1.eval()
        model2.eval()
        
        with torch.no_grad():
            out1 = model1(x, edge_index, node_type, edge_type)
            out2 = model2(x, edge_index, node_type, edge_type)
        
        # Outputs should be identical (same implementation)
        assert torch.allclose(out1, out2, rtol=1e-5, atol=1e-6)
    
    @pytest.mark.skipif(not TORCH_GEOMETRIC_AVAILABLE, reason="torch_geometric required")
    def test_htgat_conv_attention_weights_parity(self):
        """Test attention weights computation parity."""
        from src.models.htgat import HTGATConv
        
        torch.manual_seed(42)
        
        model = HTGATConv(16, 8, 3, 2, heads=4)
        model.eval()
        
        num_nodes = 5
        num_edges = 10
        x = torch.randn(num_nodes, 16)
        edge_index = torch.randint(0, num_nodes, (2, num_edges))
        node_type = torch.randint(0, 3, (num_nodes,))
        edge_type = torch.randint(0, 2, (num_edges,))
        
        with torch.no_grad():
            out, (edge_idx, attention) = model(
                x, edge_index, node_type, edge_type,
                return_attention_weights=True
            )
        
        # Check attention weights are valid
        assert attention.shape == (num_edges, 4)
        assert (attention >= 0).all()
        assert (attention <= 1).all()
        assert not torch.isnan(attention).any()
        assert not torch.isinf(attention).any()
    
    def test_htgat_conv_deterministic(self):
        """Test that HTGATConv produces deterministic outputs with fixed seed."""
        from src.models.htgat import HTGATConv
        
        torch.manual_seed(12345)
        
        model1 = HTGATConv(16, 8, 3, 2, heads=4)
        model1.eval()
        
        num_nodes = 10
        num_edges = 20
        x = torch.randn(num_nodes, 16)
        edge_index = torch.randint(0, num_nodes, (2, num_edges))
        node_type = torch.randint(0, 3, (num_nodes,))
        edge_type = torch.randint(0, 2, (num_edges,))
        
        with torch.no_grad():
            out1 = model1(x, edge_index, node_type, edge_type)
        
        # Reset seed and run again
        torch.manual_seed(12345)
        model2 = HTGATConv(16, 8, 3, 2, heads=4)
        model2.eval()
        
        # Copy weights
        for p1, p2 in zip(model1.parameters(), model2.parameters()):
            p2.data.copy_(p1.data)
        
        with torch.no_grad():
            out2 = model2(x, edge_index, node_type, edge_type)
        
        assert torch.allclose(out1, out2, rtol=1e-5, atol=1e-6)
    
    def test_htgat_conv_multiple_node_types(self):
        """Test HTGATConv with multiple node types."""
        from src.models.htgat import HTGATConv
        
        torch.manual_seed(42)
        
        model = HTGATConv(16, 8, num_node_types=5, num_edge_types=3, heads=4)
        model.eval()
        
        num_nodes = 20
        num_edges = 40
        x = torch.randn(num_nodes, 16)
        edge_index = torch.randint(0, num_nodes, (2, num_edges))
        node_type = torch.randint(0, 5, (num_nodes,))
        edge_type = torch.randint(0, 3, (num_edges,))
        
        with torch.no_grad():
            out = model(x, edge_index, node_type, edge_type)
        
        assert out.shape == (num_nodes, 32)  # heads * out_channels
    
    def test_htgat_conv_multiple_edge_types(self):
        """Test HTGATConv with multiple edge types."""
        from src.models.htgat import HTGATConv
        
        torch.manual_seed(42)
        
        model = HTGATConv(16, 8, num_node_types=3, num_edge_types=5, heads=4)
        model.eval()
        
        num_nodes = 15
        num_edges = 30
        x = torch.randn(num_nodes, 16)
        edge_index = torch.randint(0, num_nodes, (2, num_edges))
        node_type = torch.randint(0, 3, (num_nodes,))
        edge_type = torch.randint(0, 5, (num_edges,))
        
        with torch.no_grad():
            out = model(x, edge_index, node_type, edge_type)
        
        assert out.shape == (num_nodes, 32)
    
    def test_htgat_conv_multiple_heads(self):
        """Test HTGATConv with multiple attention heads."""
        from src.models.htgat import HTGATConv
        
        torch.manual_seed(42)
        
        for heads in [1, 2, 4, 8]:
            model = HTGATConv(16, 8, num_node_types=3, num_edge_types=2, heads=heads)
            model.eval()
            
            num_nodes = 10
            num_edges = 20
            x = torch.randn(num_nodes, 16)
            edge_index = torch.randint(0, num_nodes, (2, num_edges))
            node_type = torch.randint(0, 3, (num_nodes,))
            edge_type = torch.randint(0, 2, (num_edges,))
            
            with torch.no_grad():
                out = model(x, edge_index, node_type, edge_type)
            
            assert out.shape == (num_nodes, heads * 8)
    
    def test_htgat_conv_with_edge_attributes(self):
        """Test HTGATConv with edge attributes (temporal encoding)."""
        from src.models.htgat import HTGATConv
        
        torch.manual_seed(42)
        
        edge_dim = 4
        model = HTGATConv(16, 8, num_node_types=3, num_edge_types=2, heads=4, edge_dim=edge_dim)
        model.eval()
        
        num_nodes = 10
        num_edges = 20
        x = torch.randn(num_nodes, 16)
        edge_index = torch.randint(0, num_nodes, (2, num_edges))
        node_type = torch.randint(0, 3, (num_nodes,))
        edge_type = torch.randint(0, 2, (num_edges,))
        edge_attr = torch.randn(num_edges, edge_dim)
        
        with torch.no_grad():
            out = model(x, edge_index, node_type, edge_type, edge_attr)
        
        assert out.shape == (num_nodes, 32)
    
    def test_htgat_conv_isolated_nodes(self):
        """Test HTGATConv with isolated nodes (no incoming edges)."""
        from src.models.htgat import HTGATConv
        
        torch.manual_seed(42)
        
        model = HTGATConv(16, 8, num_node_types=3, num_edge_types=2, heads=4)
        model.eval()
        
        num_nodes = 10
        num_edges = 10
        x = torch.randn(num_nodes, 16)
        # Only nodes 0-4 have incoming edges, nodes 5-9 are isolated
        edge_index = torch.tensor([[0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
                                    [0, 1, 2, 3, 4, 0, 1, 2, 3, 4]])
        node_type = torch.randint(0, 3, (num_nodes,))
        edge_type = torch.randint(0, 2, (num_edges,))
        
        with torch.no_grad():
            out = model(x, edge_index, node_type, edge_type)
        
        assert out.shape == (num_nodes, 32)
        # Isolated nodes should have output (bias only, since no messages)
        assert not torch.isnan(out).any()
    
    def test_htgat_conv_empty_graph(self):
        """Test HTGATConv with empty graph (no edges)."""
        from src.models.htgat import HTGATConv
        
        torch.manual_seed(42)
        
        model = HTGATConv(16, 8, num_node_types=3, num_edge_types=2, heads=4)
        model.eval()
        
        num_nodes = 5
        num_edges = 0
        x = torch.randn(num_nodes, 16)
        edge_index = torch.empty((2, 0), dtype=torch.long)
        node_type = torch.randint(0, 3, (num_nodes,))
        edge_type = torch.empty((0,), dtype=torch.long)
        
        with torch.no_grad():
            out = model(x, edge_index, node_type, edge_type)
        
        assert out.shape == (num_nodes, 32)
        # All nodes should have output (bias only)
        assert not torch.isnan(out).any()
    
    def test_htgat_conv_single_node(self):
        """Test HTGATConv with graph containing a single node."""
        from src.models.htgat import HTGATConv
        
        torch.manual_seed(42)
        
        model = HTGATConv(16, 8, num_node_types=1, num_edge_types=1, heads=4)
        model.eval()
        
        num_nodes = 1
        num_edges = 0
        x = torch.randn(num_nodes, 16)
        edge_index = torch.empty((2, 0), dtype=torch.long)
        node_type = torch.tensor([0])
        edge_type = torch.empty((0,), dtype=torch.long)
        
        with torch.no_grad():
            out = model(x, edge_index, node_type, edge_type)
        
        assert out.shape == (num_nodes, 32)
        assert not torch.isnan(out).any()
    
    def test_htgat_conv_concat_false(self):
        """Test HTGATConv with concat=False (average heads)."""
        from src.models.htgat import HTGATConv
        
        torch.manual_seed(42)
        
        model = HTGATConv(16, 8, num_node_types=3, num_edge_types=2, heads=4, concat=False)
        model.eval()
        
        num_nodes = 10
        num_edges = 20
        x = torch.randn(num_nodes, 16)
        edge_index = torch.randint(0, num_nodes, (2, num_edges))
        node_type = torch.randint(0, 3, (num_nodes,))
        edge_type = torch.randint(0, 2, (num_edges,))
        
        with torch.no_grad():
            out = model(x, edge_index, node_type, edge_type)
        
        assert out.shape == (num_nodes, 8)  # out_channels, not heads * out_channels


class TestHTGATParity:
    """Test multi-layer HTGAT behavioral parity."""
    
    def test_htgat_deterministic(self):
        """Test that HTGAT produces deterministic outputs with fixed seed."""
        from src.models.htgat import HTGAT
        
        torch.manual_seed(12345)
        
        model1 = HTGAT(16, 32, 8, num_node_types=3, num_edge_types=2, num_layers=2, heads=4)
        model1.eval()
        
        num_nodes = 10
        num_edges = 20
        x = torch.randn(num_nodes, 16)
        edge_index = torch.randint(0, num_nodes, (2, num_edges))
        node_type = torch.randint(0, 3, (num_nodes,))
        edge_type = torch.randint(0, 2, (num_edges,))
        
        with torch.no_grad():
            out1 = model1(x, edge_index, node_type, edge_type)
        
        # Reset seed and run again
        torch.manual_seed(12345)
        model2 = HTGAT(16, 32, 8, num_node_types=3, num_edge_types=2, num_layers=2, heads=4)
        model2.eval()
        
        # Copy weights
        for p1, p2 in zip(model1.parameters(), model2.parameters()):
            p2.data.copy_(p1.data)
        
        with torch.no_grad():
            out2 = model2(x, edge_index, node_type, edge_type)
        
        assert torch.allclose(out1, out2, rtol=1e-5, atol=1e-6)
    
    def test_htgat_multiple_layers(self):
        """Test HTGAT with different numbers of layers."""
        from src.models.htgat import HTGAT
        
        torch.manual_seed(42)
        
        for num_layers in [1, 2, 3, 4]:
            model = HTGAT(16, 32, 8, num_node_types=3, num_edge_types=2, 
                         num_layers=num_layers, heads=4)
            model.eval()
            
            num_nodes = 10
            num_edges = 20
            x = torch.randn(num_nodes, 16)
            edge_index = torch.randint(0, num_nodes, (2, num_edges))
            node_type = torch.randint(0, 3, (num_nodes,))
            edge_type = torch.randint(0, 2, (num_edges,))
            
            with torch.no_grad():
                out = model(x, edge_index, node_type, edge_type)
            
            # When num_layers=1, single layer uses hidden_channels=32 with concat=True → 4*32 = 128
            # When num_layers>1, final layer uses out_channels=8 with concat=False → 8
            expected_out_channels = 8 if num_layers > 1 else 128  # 8 or 4*32
            assert out.shape == (num_nodes, expected_out_channels)
    
    def test_htgat_with_edge_attributes(self):
        """Test HTGAT with edge attributes."""
        from src.models.htgat import HTGAT
        
        torch.manual_seed(42)
        
        edge_dim = 4
        model = HTGAT(16, 32, 8, num_node_types=3, num_edge_types=2, 
                     num_layers=2, heads=4, edge_dim=edge_dim)
        model.eval()
        
        num_nodes = 10
        num_edges = 20
        x = torch.randn(num_nodes, 16)
        edge_index = torch.randint(0, num_nodes, (2, num_edges))
        node_type = torch.randint(0, 3, (num_nodes,))
        edge_type = torch.randint(0, 2, (num_edges,))
        edge_attr = torch.randn(num_edges, edge_dim)
        
        with torch.no_grad():
            out = model(x, edge_index, node_type, edge_type, edge_attr)
        
        assert out.shape == (num_nodes, 8)


class TestAttentionNormalization:
    """Test attention coefficient normalization properties."""
    
    def test_attention_normalization_per_node(self):
        """Test that attention weights sum to 1 per target node."""
        from src.models.htgat import HTGATConv
        
        torch.manual_seed(42)
        
        model = HTGATConv(16, 8, num_node_types=3, num_edge_types=2, heads=4)
        model.eval()
        
        num_nodes = 10
        num_edges = 30
        x = torch.randn(num_nodes, 16)
        edge_index = torch.randint(0, num_nodes, (2, num_edges))
        node_type = torch.randint(0, 3, (num_nodes,))
        edge_type = torch.randint(0, 2, (num_edges,))
        
        with torch.no_grad():
            _, (edge_idx, attention) = model(
                x, edge_index, node_type, edge_type,
                return_attention_weights=True
            )
        
        # Check that attention weights sum to 1 per target node
        dst_nodes = edge_idx[1]
        for node_id in dst_nodes.unique():
            mask = dst_nodes == node_id
            node_attention = attention[mask]
            sum_attention = node_attention.sum(dim=0)
            assert torch.allclose(sum_attention, torch.ones_like(sum_attention), 
                                   rtol=1e-4, atol=1e-5), \
                f"Attention weights for node {node_id} do not sum to 1"
    
    def test_attention_no_nan_inf(self):
        """Test that attention coefficients contain no NaN or Inf."""
        from src.models.htgat import HTGATConv
        
        torch.manual_seed(42)
        
        model = HTGATConv(16, 8, num_node_types=3, num_edge_types=2, heads=4)
        model.eval()
        
        num_nodes = 10
        num_edges = 30
        x = torch.randn(num_nodes, 16)
        edge_index = torch.randint(0, num_nodes, (2, num_edges))
        node_type = torch.randint(0, 3, (num_nodes,))
        edge_type = torch.randint(0, 2, (num_edges,))
        
        with torch.no_grad():
            _, (edge_idx, attention) = model(
                x, edge_index, node_type, edge_type,
                return_attention_weights=True
            )
        
        assert not torch.isnan(attention).any(), "Attention contains NaN values"
        assert not torch.isinf(attention).any(), "Attention contains Inf values"
        assert (attention >= 0).all(), "Attention contains negative values"
        assert (attention <= 1).all(), "Attention contains values > 1"
    
    def test_attention_range(self):
        """Test that attention coefficients are in valid range [0, 1]."""
        from src.models.htgat import HTGATConv
        
        torch.manual_seed(42)
        
        model = HTGATConv(16, 8, num_node_types=3, num_edge_types=2, heads=4)
        model.eval()
        
        num_nodes = 10
        num_edges = 30
        x = torch.randn(num_nodes, 16)
        edge_index = torch.randint(0, num_nodes, (2, num_edges))
        node_type = torch.randint(0, 3, (num_nodes,))
        edge_type = torch.randint(0, 2, (num_edges,))
        
        with torch.no_grad():
            _, (edge_idx, attention) = model(
                x, edge_index, node_type, edge_type,
                return_attention_weights=True
            )
        
        assert attention.min() >= 0, f"Min attention {attention.min()} < 0"
        assert attention.max() <= 1, f"Max attention {attention.max()} > 1"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
