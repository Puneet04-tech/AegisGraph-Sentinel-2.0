"""
1D Temporal Transformer Network for Keystroke Hesitation & Stress Profiling

Implements a 1D-CNN + Transformer Encoder architecture for continuous keystroke stress scoring
and coaching detection with attention masking.
"""

from __future__ import annotations

import math
import torch
import torch.nn as nn
import torch.nn.functional as F
from typing import Dict, Optional, Tuple


class PositionalEncoding(nn.Module):
    """Sinusoidal positional encoding for keystroke timing sequences."""

    def __init__(self, d_model: int, max_len: int = 500):
        super().__init__()
        pe = torch.zeros(max_len, d_model)
        position = torch.arange(0, max_len, dtype=torch.float).unsqueeze(1)
        div_term = torch.exp(torch.arange(0, d_model, 2).float() * (-math.log(10000.0) / d_model))

        pe[:, 0::2] = torch.sin(position * div_term)
        pe[:, 1::2] = torch.cos(position * div_term)
        self.register_buffer("pe", pe.unsqueeze(0))

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """Args: x: [batch_size, seq_len, d_model]"""
        return x + self.pe[:, : x.size(1)]


class KeystrokeTransformer(nn.Module):
    """1D-CNN + Transformer Encoder model for continuous keystroke stress detection."""

    def __init__(
        self,
        input_dim: int = 2,  # [hold_time, flight_time]
        d_model: int = 64,
        nhead: int = 4,
        num_layers: int = 2,
        dim_feedforward: int = 128,
        dropout: float = 0.1,
    ):
        super().__init__()
        self.d_model = d_model

        # 1D-CNN Projection Layer
        self.conv_input = nn.Conv1d(
            in_channels=input_dim,
            out_channels=d_model,
            kernel_size=3,
            padding=1,
        )

        self.pos_encoder = PositionalEncoding(d_model=d_model)

        encoder_layer = nn.TransformerEncoderLayer(
            d_model=d_model,
            nhead=nhead,
            dim_feedforward=dim_feedforward,
            dropout=dropout,
            batch_first=True,
        )
        self.transformer_encoder = nn.TransformerEncoder(encoder_layer, num_layers=num_layers)

        # Classification Head
        self.fc_out = nn.Sequential(
            nn.Linear(d_model, 32),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(32, 1),
            nn.Sigmoid(),
        )

    def forward(
        self,
        x: torch.Tensor,
        src_key_padding_mask: Optional[torch.Tensor] = None,
    ) -> torch.Tensor:
        """Forward pass through 1D-CNN + Transformer Encoder.

        Args:
            x: Keystroke sequence tensor [batch_size, seq_len, input_dim]
            src_key_padding_mask: Mask for padding tokens [batch_size, seq_len]

        Returns:
            Continuous stress risk score tensor [batch_size, 1]
        """
        # x shape: [batch_size, seq_len, input_dim] -> permute for 1D CNN [batch_size, input_dim, seq_len]
        x_conv = self.conv_input(x.transpose(1, 2)).transpose(1, 2)
        x_encoded = self.pos_encoder(x_conv)

        out = self.transformer_encoder(x_encoded, src_key_padding_mask=src_key_padding_mask)
        # Pooling: Mean pooling over sequence length
        if src_key_padding_mask is not None:
            mask_expanded = (~src_key_padding_mask).unsqueeze(-1).float()
            pooled = (out * mask_expanded).sum(dim=1) / (mask_expanded.sum(dim=1) + 1e-8)
        else:
            pooled = out.mean(dim=1)

        return self.fc_out(pooled)
