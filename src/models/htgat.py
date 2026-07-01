"""
Heterogeneous Temporal Graph Attention Network (HTGAT) Implementation

Implements the core HTGAT layer as described in the paper, with support for:
- Heterogeneous node and edge types
- Multi-head attention mechanism
- Temporal edge encoding
"""
# Working on HTGAT model architecture improvements

import torch
import torch.nn as nn
import torch.nn.functional as F
from typing import Dict, Optional, List
import math
import logging

logger = logging.getLogger(__name__)

# Optional torch_geometric imports
try:
    from torch_geometric.nn import MessagePassing
    from torch_geometric.utils import softmax
    TORCH_GEOMETRIC_AVAILABLE = True
except ImportError:
    logger.warning("⚠️  torch_geometric not available - HTGAT will use fallback implementation")
    class MessagePassing(nn.Module):
        def __init__(self, **kwargs):
            super().__init__()

        def propagate(self, edge_index, x, edge_type, edge_attr=None):
            src, dst = edge_index
            x_src, x_dst = x
            messages = self.message(
                x_i=x_dst[dst],
                x_j=x_src[src],
                edge_type=edge_type,
                edge_attr=edge_attr,
                index=dst,
                ptr=None,
                size_i=x_dst.size(0),
            )
            out = torch.zeros_like(x_dst)
            out.index_add_(0, dst, messages)
            return out
    TORCH_GEOMETRIC_AVAILABLE = False
    
    def softmax(src, index, num_nodes=None):
        """Scatter softmax matching torch_geometric.utils.softmax.

        Normalises each target node's incoming edge weights so that, for every
        target node i, the attention coefficients over all edges pointing into i
        sum to 1.  The original one-liner (torch.softmax(src, dim=-1)) ignored
        `index` entirely and normalised each edge's logit vector against itself
        across the head dimension — producing non-normalised attention weights
        with no error raised (fix #135).

        Args:
            src:       [num_edges, num_heads]  raw attention logits
            index:     [num_edges]             target-node index for each edge
            num_nodes: int, optional           total number of nodes
        Returns:
            [num_edges, num_heads] attention weights; per-node sums == 1
        """
        if num_nodes is None:
            num_nodes = int(index.max().item()) + 1

        # -- Step 1: per-node max for numerical stability -----------------
        src_max = torch.full(
            (num_nodes, src.size(-1)), float('-inf'),
            dtype=src.dtype, device=src.device,
        )
        idx = index.unsqueeze(-1).expand_as(src)
        src_max.scatter_reduce_(0, idx, src, reduce='amax', include_self=True)
        # Nodes with no incoming edges get -inf; clamp so exp doesn't NaN.
        src_max = src_max.clamp(min=0)

        # -- Step 2: shifted exp ------------------------------------------
        out = (src - src_max[index]).exp()

        # -- Step 3: per-node sum -----------------------------------------
        out_sum = torch.zeros_like(src_max)
        out_sum.scatter_add_(0, idx, out)

        # -- Step 4: normalise --------------------------------------------
        return out / (out_sum[index] + 1e-16)


class HTGATConv(MessagePassing):
    """
    Heterogeneous Temporal Graph Attention Network Convolution Layer
    
    Implements attention mechanism that handles:
    - Multiple node types with type-specific transformations
    - Multiple edge types with type-specific attention
    - Temporal edge features
    
    Args:
        in_channels: Input feature dimension
        out_channels: Output feature dimension per head
        num_node_types: Number of distinct node types
        num_edge_types: Number of distinct edge types
        heads: Number of attention heads
        dropout: Dropout probability
        concat: Whether to concatenate multi-head outputs (True) or average (False)
        negative_slope: LeakyReLU negative slope
        add_self_loops: Whether to add self-loops
        edge_dim: Dimension of edge features (for temporal encoding)
    """
    
    def __init__(
        self,
        in_channels: int,
        out_channels: int,
        num_node_types: int,
        num_edge_types: int,
        heads: int = 4,
        dropout: float = 0.3,
        concat: bool = True,
        negative_slope: float = 0.2,
        add_self_loops: bool = False,
        edge_dim: Optional[int] = None,
    ):
        super().__init__(aggr='add', node_dim=0)
        
        self.in_channels = in_channels
        self.out_channels = out_channels
        self.num_node_types = num_node_types
        self.num_edge_types = num_edge_types
        self.heads = heads
        self.dropout = dropout
        self.concat = concat
        self.negative_slope = negative_slope
        self.add_self_loops = add_self_loops
        self.edge_dim = edge_dim
        
        # Type-specific linear transformations for source nodes
        self.W_src = nn.ModuleList([
            nn.Linear(in_channels, heads * out_channels, bias=False)
            for _ in range(num_node_types)
        ])
        
        # Type-specific linear transformations for target nodes
        self.W_dst = nn.ModuleList([
            nn.Linear(in_channels, heads * out_channels, bias=False)
            for _ in range(num_node_types)
        ])
        
        # Relation-specific attention parameters
        # For each edge type, we have an attention vector
        self.att_src = nn.ParameterList([
            nn.Parameter(torch.Tensor(1, heads, out_channels))
            for _ in range(num_edge_types)
        ])
        
        self.att_dst = nn.ParameterList([
            nn.Parameter(torch.Tensor(1, heads, out_channels))
            for _ in range(num_edge_types)
        ])
        
        # Edge feature transformation (for temporal encoding)
        if edge_dim is not None:
            self.W_edge = nn.ModuleList([
                nn.Linear(edge_dim, heads * out_channels, bias=False)
                for _ in range(num_edge_types)
            ])
            self.att_edge = nn.ParameterList([
                nn.Parameter(torch.Tensor(1, heads, out_channels))
                for _ in range(num_edge_types)
            ])
        else:
            self.register_parameter('W_edge', None)
            self.register_parameter('att_edge', None)
        
        # Bias
        if concat:
            self.bias = nn.Parameter(torch.Tensor(heads * out_channels))
        else:
            self.bias = nn.Parameter(torch.Tensor(out_channels))
        
        self.reset_parameters()
    
    def reset_parameters(self):
        """Initialize parameters using Glorot initialization"""
        gain = nn.init.calculate_gain('relu')
        
        for w in self.W_src:
            nn.init.xavier_uniform_(w.weight, gain=gain)
        for w in self.W_dst:
            nn.init.xavier_uniform_(w.weight, gain=gain)
        
        for att in self.att_src:
            nn.init.xavier_uniform_(att, gain=gain)
        for att in self.att_dst:
            nn.init.xavier_uniform_(att, gain=gain)
        
        if self.W_edge is not None:
            for w in self.W_edge:
                nn.init.xavier_uniform_(w.weight, gain=gain)
            for att in self.att_edge:
                nn.init.xavier_uniform_(att, gain=gain)
        
        nn.init.zeros_(self.bias)
    
    def forward(
        self,
        x: torch.Tensor,
        edge_index: torch.LongTensor,
        node_type: torch.LongTensor,
        edge_type: torch.LongTensor,
        edge_attr: Optional[torch.Tensor] = None,
        return_attention_weights: bool = False,
    ):
        """
        Forward pass of HTGAT layer
        
        Args:
            x: Node features [num_nodes, in_channels]
            edge_index: Edge indices [2, num_edges]
            node_type: Node type for each node [num_nodes]
            edge_type: Edge type for each edge [num_edges]
            edge_attr: Edge features [num_edges, edge_dim] (e.g., temporal encoding)
            return_attention_weights: Whether to return attention weights
        
        Returns:
            out: Updated node features [num_nodes, out_channels * heads] if concat
                 or [num_nodes, out_channels] if not concat
            attention_weights: (Optional) Attention weights if return_attention_weights=True
        """
        H, C = self.heads, self.out_channels
        
        # Apply type-specific transformations
        # We'll create separate embeddings for source and destination contexts
        x_src = self._apply_type_specific_transform(x, node_type, self.W_src)
        x_dst = self._apply_type_specific_transform(x, node_type, self.W_dst)
        
        # Reshape for multi-head attention: [num_nodes, heads, out_channels]
        x_src = x_src.view(-1, H, C)
        x_dst = x_dst.view(-1, H, C)
        
        # Propagate messages
        out = self.propagate(
            edge_index,
            x=(x_src, x_dst),
            edge_type=edge_type,
            edge_attr=edge_attr,
        )
        attention_weights = getattr(self, '_last_attention_weights', None)
        
        # Concatenate or average multi-head outputs
        if self.concat:
            out = out.view(-1, H * C)
        else:
            out = out.mean(dim=1)
        
        # Add bias
        out = out + self.bias
        
        if return_attention_weights:
            return out, (edge_index, attention_weights)
        return out
    
    def message(
        self,
        x_i: torch.Tensor,
        x_j: torch.Tensor,
        edge_type: torch.LongTensor,
        edge_attr: Optional[torch.Tensor],
        index: torch.LongTensor,
        ptr: Optional[torch.Tensor],
        size_i: Optional[int],
    ):
        """
        Construct messages from neighbors
        
        Args:
            x_i: Target node features [num_edges, heads, out_channels]
            x_j: Source node features [num_edges, heads, out_channels]
            edge_type: Edge type for each edge [num_edges]
            edge_attr: Edge features [num_edges, edge_dim]
            index: Target node indices
            ptr: CSR pointer (not used)
            size_i: Number of target nodes
        
        Returns:
            Weighted messages [num_edges, heads, out_channels]
        """
        # Compute attention coefficients for each edge type
        alpha = self._compute_attention(x_i, x_j, edge_type, edge_attr, index, size_i)
        
        # Apply dropout to attention coefficients
        alpha = F.dropout(alpha, p=self.dropout, training=self.training)
        
        # Weight messages by attention
        # alpha: [num_edges, heads, 1]
        # x_j: [num_edges, heads, out_channels]
        return x_j * alpha
    
    def _compute_attention(
        self,
        x_i: torch.Tensor,
        x_j: torch.Tensor,
        edge_type: torch.LongTensor,
        edge_attr: Optional[torch.Tensor],
        index: torch.LongTensor,
        size_i: Optional[int],
    ):
        """
        Compute attention coefficients for edges
        
        Returns attention weights of shape [num_edges, heads, 1]
        """
        num_edges = x_i.size(0)
        H = self.heads
        
        # Initialize attention logits
        alpha = torch.zeros(num_edges, H, device=x_i.device)
        
        # Compute attention for each edge type separately
        for rel_type in range(self.num_edge_types):
            mask = edge_type == rel_type
            if not mask.any():
                continue
            
            # Get attention parameters for this relation type
            att_src = self.att_src[rel_type]  # [1, heads, out_channels]
            att_dst = self.att_dst[rel_type]  # [1, heads, out_channels]
            
            # Compute attention components
            # (x * att).sum(dim=-1) gives us the attention score
            alpha_src = (x_j[mask] * att_src).sum(dim=-1)  # [num_edges_type, heads]
            alpha_dst = (x_i[mask] * att_dst).sum(dim=-1)  # [num_edges_type, heads]
            
            alpha_edge_type = alpha_src + alpha_dst
            
            # Add edge feature contribution if available
            if edge_attr is not None and self.W_edge is not None:
                edge_embedding = self.W_edge[rel_type](edge_attr[mask])
                edge_embedding = edge_embedding.view(-1, H, self.out_channels)
                att_edge = self.att_edge[rel_type]
                alpha_edge = (edge_embedding * att_edge).sum(dim=-1)
                alpha_edge_type = alpha_edge_type + alpha_edge
            
            alpha[mask] = alpha_edge_type
        
        # Apply LeakyReLU
        alpha = F.leaky_relu(alpha, self.negative_slope)
        
        # Normalize attention coefficients using softmax
        alpha = softmax(alpha, index, num_nodes=size_i)
        self._last_attention_weights = alpha.detach()

        return alpha.unsqueeze(-1)  # [num_edges, heads, 1]
    
    def _apply_type_specific_transform(
        self,
        x: torch.Tensor,
        node_type: torch.LongTensor,
        transforms: nn.ModuleList,
    ):
        """
        Apply type-specific linear transformations to nodes
        
        Args:
            x: Node features [num_nodes, in_channels]
            node_type: Node type indices [num_nodes]
            transforms: List of linear transformations
        
        Returns:
            Transformed features [num_nodes, heads * out_channels]
        """
        num_nodes = x.size(0)
        out = torch.zeros(num_nodes, self.heads * self.out_channels, device=x.device)
        
        for ntype in range(self.num_node_types):
            mask = node_type == ntype
            if not mask.any():
                continue
            out[mask] = transforms[ntype](x[mask])
        
        return out
    
    def __repr__(self):
        return (f'{self.__class__.__name__}({self.in_channels}, '
                f'{self.out_channels}, heads={self.heads}, '
                f'node_types={self.num_node_types}, '
                f'edge_types={self.num_edge_types})')


class HTGAT(nn.Module):
    """
    Multi-layer Heterogeneous Temporal Graph Attention Network
    
    Args:
        in_channels: Input feature dimension
        hidden_channels: Hidden layer dimension
        out_channels: Output dimension
        num_node_types: Number of node types
        num_edge_types: Number of edge types
        num_layers: Number of HTGAT layers
        heads: Number of attention heads
        dropout: Dropout probability
        edge_dim: Edge feature dimension (for temporal encoding)
    """
    
    def __init__(
        self,
        in_channels: int,
        hidden_channels: int,
        out_channels: int,
        num_node_types: int,
        num_edge_types: int,
        num_layers: int = 2,
        heads: int = 4,
        dropout: float = 0.3,
        edge_dim: Optional[int] = None,
    ):
        super().__init__()
        
        self.num_layers = num_layers
        self.dropout = dropout
        
        self.convs = nn.ModuleList()
        self.norms = nn.ModuleList()
        
        # First layer
        self.convs.append(
            HTGATConv(
                in_channels,
                hidden_channels,
                num_node_types,
                num_edge_types,
                heads=heads,
                dropout=dropout,
                concat=True,
                edge_dim=edge_dim,
            )
        )
        self.norms.append(nn.LayerNorm(heads * hidden_channels))
        
        # Hidden layers
        for _ in range(num_layers - 2):
            self.convs.append(
                HTGATConv(
                    heads * hidden_channels,
                    hidden_channels,
                    num_node_types,
                    num_edge_types,
                    heads=heads,
                    dropout=dropout,
                    concat=True,
                    edge_dim=edge_dim,
                )
            )
            self.norms.append(nn.LayerNorm(heads * hidden_channels))
        
        # Last layer (no concatenation)
        if num_layers > 1:
            self.convs.append(
                HTGATConv(
                    heads * hidden_channels,
                    out_channels,
                    num_node_types,
                    num_edge_types,
                    heads=heads,
                    dropout=dropout,
                    concat=False,
                    edge_dim=edge_dim,
                )
            )
        
    def forward(
        self,
        x: torch.Tensor,
        edge_index: torch.LongTensor,
        node_type: torch.LongTensor,
        edge_type: torch.LongTensor,
        edge_attr: Optional[torch.Tensor] = None,
        return_attention_weights: bool = False,
    ):
        """
        Forward pass through all HTGAT layers
        
        Args:
            x: Node features [num_nodes, in_channels]
            edge_index: Edge indices [2, num_edges]
            node_type: Node types [num_nodes]
            edge_type: Edge types [num_edges]
            edge_attr: Edge features [num_edges, edge_dim]
        
        Returns:
            Node embeddings [num_nodes, out_channels]
        """
        last_attention = None

        for i in range(self.num_layers):

            if return_attention_weights and i == self.num_layers - 1:

                x, (_, last_attention) = self.convs[i](
                    x,
                    edge_index,
                    node_type,
                    edge_type,
                    edge_attr,
                    return_attention_weights=True,
                )

            else:

                x = self.convs[i](
                    x,
                    edge_index,
                    node_type,
                    edge_type,
                    edge_attr,
                )

            if i < self.num_layers - 1:
                x = self.norms[i](x)
                x = F.relu(x)
                x = F.dropout(x, p=self.dropout, training=self.training)

        if return_attention_weights:
            return x, (edge_index, last_attention)

        return x