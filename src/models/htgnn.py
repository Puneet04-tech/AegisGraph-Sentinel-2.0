"""
AegisHTGNN: Heterogeneous Temporal Graph Neural Network for mule-account detection.

Pure-PyTorch implementation (no torch_geometric dependency) that consumes the
HeteroData batches produced by ``src.training.data_loader.AegisGraphLoader``:

  - node types: ``account`` (16 features), ``device`` (8 features)
  - edge types: ``('account', 'transacts', 'account')``,
                ``('device', 'logs_into', 'account')``

Account node features are encoded per node type, message-passed through
multi-layer HGT convolutions (see ``hgt.py``) and projected to a single
fraud logit per account node, so gradients flow into real model parameters.
"""

import torch
import torch.nn as nn
from typing import Any, Dict, Optional, Tuple

from .hgt import HGT

DEFAULT_NODE_CHANNELS: Dict[str, int] = {"account": 16, "device": 8}
DEFAULT_EDGE_TYPES: list = [
    ("account", "transacts", "account"),
    ("device", "logs_into", "account"),
]


class AegisHTGNN(nn.Module):
    """Heterogeneous Temporal Graph Neural Network for account risk scoring.

    Args:
        hidden_channels: Hidden dimensionality used by the message-passing layers.
        out_channels: Output dimensionality (one fraud logit per account).
        num_layers: Number of HGT convolution layers.
        heads: Number of attention heads per convolution layer.
        dropout: Dropout probability applied inside the convolutions.
        node_channels: Feature dimensionality per node type.
        edge_types: Supported heterogeneous edge types (triples of names).
    """

    def __init__(
        self,
        hidden_channels: int = 64,
        out_channels: int = 1,
        num_layers: int = 2,
        heads: int = 4,
        dropout: float = 0.3,
        node_channels: Optional[Dict[str, int]] = None,
        edge_types: Optional[list] = None,
    ):
        super().__init__()
        self.node_channels = dict(node_channels or DEFAULT_NODE_CHANNELS)
        self.node_types: list = list(self.node_channels.keys())
        self.edge_types: list = list(edge_types) if edge_types is not None else DEFAULT_EDGE_TYPES
        self.hidden_channels = hidden_channels
        self.out_channels = out_channels

        # Per-node-type input encoders so heterogeneous features are projected
        # into a shared hidden space before message passing.
        self.node_encoders = nn.ModuleDict({
            node_type: nn.Linear(in_channels, hidden_channels)
            for node_type, in_channels in self.node_channels.items()
        })

        # Multi-layer heterogeneous graph transformer over the projected features.
        self.hgt = HGT(
            in_channels=hidden_channels,
            hidden_channels=hidden_channels,
            out_channels=hidden_channels,
            num_node_types=len(self.node_types),
            num_edge_types=len(self.edge_types),
            num_layers=num_layers,
            heads=heads,
            dropout=dropout,
        )

        # Final classification head producing one logit per account node.
        self.head = nn.Linear(hidden_channels, out_channels)

    def forward(self, x_dict: Dict[str, Any], edge_index_dict: Dict[Any, Any]) -> torch.Tensor:
        """Run the model over a heterogeneous graph batch.

        Args:
            x_dict: Mapping of node type name to its node feature tensor.
            edge_index_dict: Mapping of (source, relation, target) edge-type
                triple to its ``[2, num_edges]`` edge index tensor.

        Returns:
            Logits of shape ``[num_accounts, out_channels]``.
        """
        device = next(self.parameters()).device

        present = [nt for nt in self.node_types if nt in x_dict]
        if "account" not in present:
            raise ValueError(
                "Batch does not contain the required 'account' node type; "
                "got node types: %s" % (list(x_dict.keys()),)
            )

        # Project each node type's heterogeneous features into the shared
        # hidden space, then concatenate the encoded rows.
        encoded = {
            nt: self.node_encoders[nt](x_dict[nt].float().to(device))
            for nt in present
        }
        h = torch.cat([encoded[nt] for nt in present], dim=0)

        node_type = torch.zeros(h.size(0), dtype=torch.long, device=device)
        node_offset: Dict[str, Tuple[int, int]] = {}
        row = 0
        for nt in present:
            end = row + encoded[nt].size(0)
            node_offset[nt] = (row, end)
            node_type[row:end] = self.node_types.index(nt)
            row = end

        # Concatenate the heterogeneous edges into a single homogeneous batch.
        edge_index_lookup = {tuple(key): idx for idx, key in enumerate(self.edge_types)}
        edge_src: list = []
        edge_dst: list = []
        edge_type_ids: list = []
        for key, edge_index in edge_index_dict.items():
            triple = tuple(key)
            if triple not in edge_index_lookup:
                continue
            if edge_index.dim() != 2 or edge_index.size(0) != 2:
                continue
            src_type, _, dst_type = triple
            src_offset = node_offset.get(src_type)
            dst_offset = node_offset.get(dst_type)
            if src_offset is None or dst_offset is None:
                continue
            src, dst = edge_index.to(device)
            if src.numel() == 0:
                continue
            edge_src.append(src + src_offset[0])
            edge_dst.append(dst + dst_offset[0])
            edge_type_ids.append(
                torch.full_like(src, edge_index_lookup[triple], dtype=torch.long)
            )

        if edge_src:
            edge_index = torch.stack(
                [torch.cat(edge_src), torch.cat(edge_dst)], dim=0
            )
            edge_type = torch.cat(edge_type_ids)
        else:
            edge_index = torch.zeros((2, 0), dtype=torch.long, device=device)
            edge_type = torch.zeros(0, dtype=torch.long, device=device)

        h = self.hgt(h, edge_index, node_type, edge_type)

        account_start, account_end = node_offset["account"]
        return self.head(h[account_start:account_end])
