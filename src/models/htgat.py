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
    logger.warning(
        "⚠️  torch_geometric not available - HTGAT will use fallback implementation. "
        "Some advanced features may not be available."
    )
    TORCH_GEOMETRIC_AVAILABLE = False
    
    def softmax(
        src: torch.Tensor,
        index: Optional[torch.Tensor] = None,
        ptr: Optional[torch.Tensor] = None,
        num_nodes: Optional[int] = None,
        dim: int = 0,
    ) -> torch.Tensor:
        """Fallback softmax implementation matching torch_geometric.utils.softmax.

        Computes a sparsely evaluated softmax. Groups values along the first
        dimension based on indices and computes softmax per group.

        This implementation matches PyTorch Geometric's behavior for the
        index-based case. It does NOT support the ptr-based CSR representation.

        Args:
            src: Source tensor of shape [num_edges, num_heads] or similar
            index: Target node indices for each element [num_edges]
            ptr: NOT SUPPORTED in fallback - CSR pointer representation
            num_nodes: Total number of nodes (inferred from index if None)
            dim: Dimension along which to normalize (only dim=0 supported)

        Returns:
            Normalized tensor of same shape as src where values per index sum to 1

        Raises:
            NotImplementedError: If ptr is provided (not supported in fallback)
            ValueError: If dim != 0 (only dim=0 supported in fallback)

        Note:
            This is a fallback implementation when torch_geometric is unavailable.
            For production use, install torch_geometric for full functionality.
        """
        if ptr is not None:
            raise NotImplementedError(
                "ptr-based softmax not supported in fallback implementation. "
                "Install torch_geometric for full functionality."
            )
        
        if dim != 0:
            raise ValueError(
                f"Only dim=0 is supported in fallback softmax, got dim={dim}. "
                "Install torch_geometric for full functionality."
            )
        
        if index is None:
            raise ValueError("index must be provided for softmax computation")
        
        if num_nodes is None:
            num_nodes = int(index.max().item()) + 1 if index.numel() > 0 else 0

        # Step 1: Compute per-node max for numerical stability
        # This matches torch_geometric's scatter(src, index, reduce='max')
        src_max = torch.full(
            (num_nodes, src.size(-1)), float('-inf'),
            dtype=src.dtype, device=src.device,
        )
        idx = index.unsqueeze(-1).expand_as(src)
        src_max.scatter_reduce_(0, idx, src, reduce='amax', include_self=True)
        
        # Step 2: Shift by max and exponentiate
        # Nodes with no incoming edges have -inf max; their exp will be 0
        src_max_expanded = src_max[index]
        # Only shift where src_max is not -inf (nodes with incoming edges)
        valid_mask = src_max_expanded != float('-inf')
        out = torch.zeros_like(src)
        out[valid_mask] = (src[valid_mask] - src_max_expanded[valid_mask]).exp()

        # Step 3: Compute per-node sum
        out_sum = torch.zeros_like(src_max)
        out_sum.scatter_add_(0, idx, out)

        # Step 4: Normalize
        # Add epsilon to avoid division by zero for nodes with no incoming edges
        out_sum_expanded = out_sum[index]
        out_sum_expanded = out_sum_expanded.clamp(min=1e-16)
        
        return out / out_sum_expanded


class MessagePassing(nn.Module):
    """Fallback MessagePassing base class for graph neural networks.

    This is a minimal fallback implementation when torch_geometric is unavailable.
    It provides basic message passing functionality but lacks many advanced features
    of the full PyTorch Geometric implementation.

    Supported features:
    - Basic message passing with edge_index
    - Message computation via message() method
    - Add aggregation (default)
    - Tuple-based node features for bipartite graphs (x=(x_src, x_dst))

    Unsupported features:
    - ptr-based CSR representation
    - Custom aggregation schemes (only 'add' supported)
    - Flow direction control (only source_to_target)
    - SparseTensor edge_index
    - message_and_aggregate fusion
    - update() method customization
    - size parameter for non-square graphs

    For production use, install torch_geometric for full functionality.
    """

    def __init__(self, aggr: str = 'add', flow: str = 'source_to_target', node_dim: int = -2):
        """Initialize MessagePassing.

        Args:
            aggr: Aggregation scheme (only 'add' supported in fallback)
            flow: Flow direction (only 'source_to_target' supported in fallback)
            node_dim: Node dimension (0 or -2 supported in fallback)

        Raises:
            ValueError: If unsupported parameters are provided
        """
        super().__init__()
        
        if aggr != 'add':
            raise ValueError(
                f"Only aggr='add' is supported in fallback, got aggr='{aggr}'. "
                "Install torch_geometric for full functionality."
            )
        if flow != 'source_to_target':
            raise ValueError(
                f"Only flow='source_to_target' is supported in fallback, got flow='{flow}'. "
                "Install torch_geometric for full functionality."
            )
        if node_dim not in [0, -2]:
            raise ValueError(
                f"Only node_dim=0 or node_dim=-2 are supported in fallback, got node_dim={node_dim}. "
                "Install torch_geometric for full functionality."
            )
        
        self.aggr = aggr
        self.flow = flow
        self.node_dim = node_dim

    def propagate(
        self,
        edge_index: torch.Tensor,
        size: Optional[tuple] = None,
        **kwargs,
    ) -> torch.Tensor:
        """Propagate messages from source to target nodes.

        Args:
            edge_index: Edge indices [2, num_edges]
            size: NOT SUPPORTED in fallback - tuple (num_src_nodes, num_dst_nodes)
            **kwargs: Additional arguments passed to message()

        Returns:
            Aggregated node features

        Raises:
            ValueError: If size is provided (not supported in fallback)
        """
        if size is not None:
            raise ValueError(
                "size parameter not supported in fallback propagate(). "
                "Install torch_geometric for full functionality."
            )
        
        src, dst = edge_index
        
        # Handle tuple-based node features (bipartite graphs)
        x = kwargs.get('x')
        if isinstance(x, tuple):
            x_src, x_dst = x
        else:
            x_src = x_dst = x
        
        # Index node features for each edge
        x_j = x_src[src]  # Source node features for each edge
        x_i = x_dst[dst]  # Target node features for each edge
        
        # Compute messages
        messages = self.message(
            x_i=x_i,
            x_j=x_j,
            index=dst,
            ptr=None,
            size_i=x_dst.size(0),
            **{k: v for k, v in kwargs.items() if k != 'x'}
        )
        
        # Aggregate messages (only 'add' supported)
        out = torch.zeros_like(x_dst)
        out.index_add_(0, dst, messages)
        
        # Apply update if implemented
        out = self.update(out, **kwargs)
        
        return out

    def message(self, **kwargs) -> torch.Tensor:
        """Construct messages from source to target nodes.

        Must be implemented by subclass.

        Args:
            x_i: Target node features [num_edges, ...]
            x_j: Source node features [num_edges, ...]
            index: Target node indices [num_edges]
            ptr: CSR pointer (not supported, always None)
            size_i: Number of target nodes
            **kwargs: Additional arguments

        Returns:
            Message tensor [num_edges, ...]
        """
        raise NotImplementedError("message() must be implemented by subclass")

    def update(self, out: torch.Tensor, **kwargs) -> torch.Tensor:
        """Update node embeddings after aggregation.

        Default implementation returns output unchanged.
        Override in subclass for custom update logic.

        Args:
            out: Aggregated messages [num_nodes, ...]
            **kwargs: Additional arguments

        Returns:
            Updated node features
        """
        return out


class HTGATConv(MessagePassing):
    """
    Heterogeneous Temporal Graph Attention Network Convolution Layer.

    Implements attention mechanism that handles:
    - Multiple node types with type-specific transformations
    - Multiple edge types with type-specific attention
    - Temporal edge features
    - Multi-head attention

    This layer works with both torch_geometric (official) and fallback
    implementations. The fallback provides basic functionality but may
    have numerical differences compared to the official implementation.

    Args:
        in_channels: Input feature dimension for each node
        out_channels: Output feature dimension per attention head
        num_node_types: Number of distinct node types in the graph
        num_edge_types: Number of distinct edge types in the graph
        heads: Number of attention heads (default: 4)
        dropout: Dropout probability for attention coefficients (default: 0.3)
        concat: Whether to concatenate multi-head outputs (True) or average (False)
        negative_slope: Negative slope for LeakyReLU activation (default: 0.2)
        add_self_loops: Whether to add self-loops to the graph (default: False)
        edge_dim: Dimension of edge features for temporal encoding (optional)

    Note:
        When using the fallback implementation (torch_geometric unavailable),
        some advanced features may not be available. Install torch_geometric
        for production use.
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
    ) -> None:
        """Initialize HTGATConv layer.

        Args:
            in_channels: Input feature dimension
            out_channels: Output feature dimension per head
            num_node_types: Number of node types
            num_edge_types: Number of edge types
            heads: Number of attention heads
            dropout: Dropout probability
            concat: Whether to concatenate multi-head outputs
            negative_slope: LeakyReLU negative slope
            add_self_loops: Whether to add self-loops
            edge_dim: Edge feature dimension (optional)
        """
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
    
    def reset_parameters(self) -> None:
        """Initialize parameters using Glorot initialization.

        Uses Xavier uniform initialization with ReLU gain for linear
        transformations and attention parameters. Bias is initialized to zero.
        """
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
    ) -> torch.Tensor:
        """Forward pass of HTGAT layer.

        Args:
            x: Node features [num_nodes, in_channels]
            edge_index: Edge indices [2, num_edges] where edge_index[0] are source
                nodes and edge_index[1] are target nodes
            node_type: Node type for each node [num_nodes], values in [0, num_node_types)
            edge_type: Edge type for each edge [num_edges], values in [0, num_edge_types)
            edge_attr: Edge features [num_edges, edge_dim] for temporal encoding (optional)
            return_attention_weights: Whether to return attention weights

        Returns:
            out: Updated node features [num_nodes, out_channels * heads] if concat=True
                 or [num_nodes, out_channels] if concat=False
            attention_weights: (Optional) Tuple of (edge_index, attention_weights)
                if return_attention_weights=True, where attention_weights has shape
                [num_edges, heads]

        Note:
            Attention weights are computed per edge and normalized per target node
            so that incoming attention weights sum to 1 for each node.
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
    ) -> torch.Tensor:
        """Construct messages from neighbors.

        Computes attention coefficients for each edge and weights the source
        node features accordingly.

        Args:
            x_i: Target node features [num_edges, heads, out_channels]
            x_j: Source node features [num_edges, heads, out_channels]
            edge_type: Edge type for each edge [num_edges]
            edge_attr: Edge features [num_edges, edge_dim] (optional)
            index: Target node indices [num_edges] for attention normalization
            ptr: CSR pointer (not used in current implementation)
            size_i: Number of target nodes (for attention normalization)

        Returns:
            Weighted messages [num_edges, heads, out_channels]

        Note:
            Attention coefficients are normalized using softmax per target node,
            ensuring that incoming attention weights sum to 1 for each node.
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
    ) -> torch.Tensor:
        """Compute attention coefficients for edges.

        Computes type-specific attention coefficients using separate attention
        parameters for each edge type. Attention scores are computed as:
            alpha = LeakyReLU(att_src^T * x_j + att_dst^T * x_i + att_edge^T * edge_attr)

        Args:
            x_i: Target node features [num_edges, heads, out_channels]
            x_j: Source node features [num_edges, heads, out_channels]
            edge_type: Edge type for each edge [num_edges]
            edge_attr: Edge features [num_edges, edge_dim] (optional)
            index: Target node indices [num_edges] for normalization
            size_i: Number of target nodes

        Returns:
            Attention weights of shape [num_edges, heads, 1], normalized
            per target node using softmax

        Note:
            Attention weights are stored in _last_attention_weights for
            later retrieval when return_attention_weights=True.
        """
        num_edges = x_i.size(0)
        H = self.heads
        
        alpha_pieces = []
        indices = []
        
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
            
            alpha_pieces.append(alpha_edge_type)
            indices.append(torch.nonzero(mask, as_tuple=True)[0])
        
        if alpha_pieces:
            alpha = torch.cat(alpha_pieces, dim=0)
            indices = torch.cat(indices, dim=0)
            _, inverse_indices = indices.sort()
            alpha = alpha[inverse_indices]
        else:
            alpha = torch.zeros(num_edges, H, device=x_i.device)
        
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
    ) -> torch.Tensor:
        """Apply type-specific linear transformations to nodes.

        Applies different linear transformations to nodes based on their type.
        This allows the model to learn type-specific feature projections.

        Args:
            x: Node features [num_nodes, in_channels]
            node_type: Node type indices [num_nodes], values in [0, num_node_types)
            transforms: List of linear transformations, one per node type

        Returns:
            Transformed features [num_nodes, heads * out_channels]

        Note:
            Nodes without a corresponding transform (e.g., if node_type >= len(transforms))
            will receive zero features. This should not happen in normal usage.
        """
        num_nodes = x.size(0)
        out_pieces = []
        indices = []
        
        for ntype in range(self.num_node_types):
            mask = node_type == ntype
            if not mask.any():
                continue
            out_pieces.append(transforms[ntype](x[mask]))
            indices.append(torch.nonzero(mask, as_tuple=True)[0])
        
        if out_pieces:
            out = torch.cat(out_pieces, dim=0)
            indices = torch.cat(indices, dim=0)
            _, inverse_indices = indices.sort()
            out = out[inverse_indices]
        else:
            out = torch.zeros(num_nodes, self.heads * self.out_channels, device=x.device)
        
        return out
    
    def __repr__(self) -> str:
        """String representation of HTGATConv layer."""
        return (
            f'{self.__class__.__name__}('
            f'in_channels={self.in_channels}, '
            f'out_channels={self.out_channels}, '
            f'heads={self.heads}, '
            f'node_types={self.num_node_types}, '
            f'edge_types={self.num_edge_types}, '
            f'concat={self.concat})'
        )


class HTGAT(nn.Module):
    """
    Multi-layer Heterogeneous Temporal Graph Attention Network.

    Stacks multiple HTGATConv layers to build a deep graph neural network
    for heterogeneous temporal graphs. The first and hidden layers use
    concatenation of multi-head outputs, while the final layer averages them.

    Args:
        in_channels: Input feature dimension for each node
        hidden_channels: Hidden layer dimension per attention head
        out_channels: Output feature dimension
        num_node_types: Number of distinct node types in the graph
        num_edge_types: Number of distinct edge types in the graph
        num_layers: Number of HTGATConv layers (default: 2)
        heads: Number of attention heads per layer (default: 4)
        dropout: Dropout probability for attention and hidden layers (default: 0.3)
        edge_dim: Edge feature dimension for temporal encoding (optional)

    Note:
        - Layer normalization and ReLU activation are applied after each layer
          except the final layer
        - The model works with both torch_geometric (official) and fallback
          implementations
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
    ) -> None:
        """Initialize multi-layer HTGAT network.

        Args:
            in_channels: Input feature dimension
            hidden_channels: Hidden layer dimension per head
            out_channels: Output feature dimension
            num_node_types: Number of node types
            num_edge_types: Number of edge types
            num_layers: Number of HTGATConv layers
            heads: Number of attention heads
            dropout: Dropout probability
            edge_dim: Edge feature dimension (optional)
        """
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
    ) -> torch.Tensor:
        """Forward pass through all HTGAT layers.

        Args:
            x: Node features [num_nodes, in_channels]
            edge_index: Edge indices [2, num_edges]
            node_type: Node type for each node [num_nodes]
            edge_type: Edge type for each edge [num_edges]
            edge_attr: Edge features [num_edges, edge_dim] for temporal encoding (optional)
            return_attention_weights: Whether to return attention weights from final layer

        Returns:
            Node embeddings [num_nodes, out_channels]
            attention_weights: (Optional) Tuple of (edge_index, attention_weights)
                from final layer if return_attention_weights=True

        Note:
            Layer normalization and ReLU activation are applied after each layer
            except the final layer. Dropout is applied during training.
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