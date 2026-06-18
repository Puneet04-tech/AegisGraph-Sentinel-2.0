import torch
import torch.nn as nn
import torch.nn.functional as F
from typing import Dict, Optional, List
import math

class HGTConv(nn.Module):
    """
    Heterogeneous Graph Transformer (HGT) Convolution Layer in Pure PyTorch.
    Uses mutual attention mechanism to dynamically weight relations.
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
        super().__init__()
        
        self.in_channels = in_channels
        self.out_channels = out_channels
        self.num_node_types = num_node_types
        self.num_edge_types = num_edge_types
        self.heads = heads
        self.dropout = dropout
        self.concat = concat
        self.negative_slope = negative_slope
        
        # Head dimension
        self.d_k = out_channels
        
        # Type-specific linear transformations (always project to heads * out_channels)
        self.k_linears = nn.ModuleList([
            nn.Linear(in_channels, heads * out_channels, bias=False)
            for _ in range(num_node_types)
        ])
        self.q_linears = nn.ModuleList([
            nn.Linear(in_channels, heads * out_channels, bias=False)
            for _ in range(num_node_types)
        ])
        self.v_linears = nn.ModuleList([
            nn.Linear(in_channels, heads * out_channels, bias=False)
            for _ in range(num_node_types)
        ])
        
        # Relation-specific parameter matrices
        self.relation_pri = nn.Parameter(torch.ones(num_edge_types, heads))
        self.relation_att = nn.ParameterList([
            nn.Parameter(torch.Tensor(self.d_k, self.d_k))
            for _ in range(num_edge_types)
        ])
        self.relation_msg = nn.ParameterList([
            nn.Parameter(torch.Tensor(self.d_k, self.d_k))
            for _ in range(num_edge_types)
        ])
        
        # Target node output projection (input is heads * out_channels if concat else out_channels)
        self.out_dim = heads * out_channels if concat else out_channels
        self.a_linears = nn.ModuleList([
            nn.Linear(self.out_dim, self.out_dim)
            for _ in range(num_node_types)
        ])
        
        # Edge features (temporal) projection
        if edge_dim is not None:
            self.edge_linear = nn.Linear(edge_dim, heads * out_channels, bias=False)
        else:
            self.edge_linear = None
            
        self.reset_parameters()
        
    def reset_parameters(self):
        gain = nn.init.calculate_gain('relu')
        for linear in self.k_linears:
            nn.init.xavier_uniform_(linear.weight, gain=gain)
        for linear in self.q_linears:
            nn.init.xavier_uniform_(linear.weight, gain=gain)
        for linear in self.v_linears:
            nn.init.xavier_uniform_(linear.weight, gain=gain)
        for linear in self.a_linears:
            nn.init.xavier_uniform_(linear.weight, gain=gain)
            
        if self.edge_linear is not None:
            nn.init.xavier_uniform_(self.edge_linear.weight, gain=gain)
            
        for att in self.relation_att:
            nn.init.xavier_uniform_(att, gain=gain)
        for msg in self.relation_msg:
            nn.init.xavier_uniform_(msg, gain=gain)
            
    def forward(
        self,
        x: torch.Tensor,
        edge_index: torch.LongTensor,
        node_type: torch.LongTensor,
        edge_type: torch.LongTensor,
        edge_attr: Optional[torch.Tensor] = None,
        return_attention_weights: bool = False,
    ):
        num_nodes = x.size(0)
        H, C = self.heads, self.d_k
        
        # 1. Project node features per type
        k = torch.zeros(num_nodes, H, C, device=x.device)
        q = torch.zeros(num_nodes, H, C, device=x.device)
        v = torch.zeros(num_nodes, H, C, device=x.device)
        
        for ntype in range(self.num_node_types):
            mask = node_type == ntype
            if mask.any():
                k[mask] = self.k_linears[ntype](x[mask]).view(-1, H, C)
                q[mask] = self.q_linears[ntype](x[mask]).view(-1, H, C)
                v[mask] = self.v_linears[ntype](x[mask]).view(-1, H, C)
                
        # Optional edge attribute projection
        if edge_attr is not None and self.edge_linear is not None:
            edge_proj = self.edge_linear(edge_attr).view(-1, H, C)
        else:
            edge_proj = None
            
        # 2. Compute attention & messages over edges
        src, dst = edge_index
        q_dst = q[dst]
        k_src = k[src]
        v_src = v[src]
        
        attn_logits = torch.zeros(src.size(0), H, device=x.device)
        messages = torch.zeros(src.size(0), H, C, device=x.device)
        
        for rtype in range(self.num_edge_types):
            mask = edge_type == rtype
            if not mask.any():
                continue
                
            w_att = self.relation_att[rtype]
            w_msg = self.relation_msg[rtype]
            
            q_dst_mask = q_dst[mask]
            k_src_transformed = torch.matmul(k_src[mask], w_att)
            
            att_val = (q_dst_mask * k_src_transformed).sum(dim=-1) * (self.relation_pri[rtype] / math.sqrt(C))
            attn_logits[mask] = att_val
            
            msg_val = torch.matmul(v_src[mask], w_msg)
            if edge_proj is not None:
                msg_val = msg_val + edge_proj[mask]
            messages[mask] = msg_val
            
        # 3. Softmax normalize attention weights per target node
        attn_weights = torch.zeros_like(attn_logits)
        
        max_logits = torch.full((num_nodes, H), float('-inf'), device=x.device)
        dst_expanded = dst.unsqueeze(-1).expand_as(attn_logits)
        max_logits.scatter_reduce_(0, dst_expanded, attn_logits, reduce='amax', include_self=True)
        max_logits = max_logits.clamp(min=0)
        
        shifted_logits = attn_logits - max_logits[dst]
        exp_logits = shifted_logits.exp()
        
        sum_exp = torch.zeros((num_nodes, H), device=x.device)
        sum_exp.scatter_add_(0, dst_expanded, exp_logits)
        
        attn_weights = exp_logits / (sum_exp[dst] + 1e-16)
        attn_weights = F.dropout(attn_weights, p=self.dropout, training=self.training)
        
        # 4. Aggregate messages weighted by attention
        weighted_msgs = messages * attn_weights.unsqueeze(-1)
        
        aggregated = torch.zeros(num_nodes, H, C, device=x.device)
        dst_expanded_msg = dst.view(-1, 1, 1).expand(-1, H, C)
        aggregated.scatter_add_(0, dst_expanded_msg, weighted_msgs)
        
        # 5. Output projection per target node type
        if self.concat:
            aggregated = aggregated.view(num_nodes, -1)
        else:
            aggregated = aggregated.mean(dim=1)
            
        out = torch.zeros(num_nodes, self.out_dim, device=x.device)
        
        for ntype in range(self.num_node_types):
            mask = node_type == ntype
            if mask.any():
                out[mask] = self.a_linears[ntype](aggregated[mask])
                
        # Residual connection
        if x.size(-1) == out.size(-1):
            out = out + x
            
        if return_attention_weights:
            return out, (edge_index, attn_weights)
        return out


class HGT(nn.Module):
    """
    Multi-layer Heterogeneous Graph Transformer
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
            HGTConv(
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
                HGTConv(
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
            
        # Last layer
        if num_layers > 1:
            self.convs.append(
                HGTConv(
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
