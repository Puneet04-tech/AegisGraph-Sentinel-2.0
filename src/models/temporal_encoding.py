"""
Temporal Encoding Module

Implements temporal encoding for graph edges using:
- Sinusoidal positional encoding (Transformer-style)
- Time decay factors
- Relative time encoding
"""

import torch
import torch.nn as nn
import math
from typing import Optional


class TemporalEncoding(nn.Module):
    """
    Temporal encoding using sinusoidal functions
    
    Encodes timestamps or time differences using sine and cosine functions
    of different frequencies, similar to Transformer positional encoding.
    
    Formula:
        ϕ(t)_i = sin(t / 10000^(2i/d))  if i is even
        ϕ(t)_i = cos(t / 10000^(2i/d))  if i is odd
    
    Args:
        encoding_dim: Dimension of temporal encoding
        max_time: Maximum time value for normalization
    """
    
    def __init__(self, encoding_dim: int = 16, max_time: float = 86400.0):
        super().__init__()
        self.encoding_dim = encoding_dim
        self.max_time = max_time
        
        # Pre-compute frequency factors
        dim_range = torch.arange(0, encoding_dim, 2, dtype=torch.float32)
        self.register_buffer(
            'freq',
            1.0 / (10000.0 ** (dim_range / encoding_dim))
        )
    
    def forward(self, timestamps: torch.Tensor) -> torch.Tensor:
        """
        Encode timestamps using sinusoidal functions
        
        Args:
            timestamps: Timestamp tensor of any shape
        
        Returns:
            Encoded timestamps [..., encoding_dim]
        """
        # Normalize timestamps
        t = timestamps.unsqueeze(-1) / self.max_time
        
        # Compute angles
        angles = t * self.freq
        
        # Interleave sin and cos
        encoding = torch.zeros(*timestamps.shape, self.encoding_dim, device=timestamps.device)
        encoding[..., 0::2] = torch.sin(angles)
        encoding[..., 1::2] = torch.cos(angles)
        
        return encoding


class TemporalDecay(nn.Module):
    """
    Temporal decay factor for weighting past events
    
    Computes exp(-λ * Δt) decay factor where Δt is time difference
    
    Args:
        decay_lambda: Decay rate (higher = faster decay)
        learnable: Whether lambda is learnable
    """
    
    def __init__(self, decay_lambda: float = 0.01, learnable: bool = False):
        super().__init__()
        if learnable:
            self.decay_lambda = nn.Parameter(torch.tensor(decay_lambda))
        else:
            self.register_buffer('decay_lambda', torch.tensor(decay_lambda))
    
    def forward(self, time_diff: torch.Tensor) -> torch.Tensor:
        """
        Compute decay factor
        
        Args:
            time_diff: Time difference (current_time - event_time)
        
        Returns:
            Decay factor in range (0, 1]
        """
        return torch.exp(-self.decay_lambda * time_diff)


class RelativeTemporalEncoding(nn.Module):
    """
    Relative temporal encoding for edge temporal features
    
    Encodes both absolute timestamp and multiple relative time features:
    - Time since account creation
    - Time since last transaction
    - Transaction frequency in time window
    
    Args:
        encoding_dim: Dimension of temporal encoding
        max_time: Maximum time for normalization
    """
    
    def __init__(self, encoding_dim: int = 16, max_time: float = 86400.0):
        super().__init__()
        self.encoding_dim = encoding_dim
        
        # Absolute time encoding
        self.abs_encoder = TemporalEncoding(encoding_dim // 2, max_time)
        
        # Relative time encoding
        self.rel_encoder = TemporalEncoding(encoding_dim // 2, max_time)
    
    def forward(
        self,
        timestamps: torch.Tensor,
        reference_time: Optional[torch.Tensor] = None,
    ) -> torch.Tensor:
        """
        Encode temporal information
        
        Args:
            timestamps: Event timestamps
            reference_time: Reference time for relative encoding (e.g., current time)
        
        Returns:
            Combined temporal encoding
        """
        # Absolute encoding
        abs_encoding = self.abs_encoder(timestamps)
        
        # Relative encoding
        if reference_time is not None:
            time_diff = reference_time - timestamps
            rel_encoding = self.rel_encoder(time_diff)
        else:
            rel_encoding = torch.zeros_like(abs_encoding)
        
        # Concatenate
        return torch.cat([abs_encoding, rel_encoding], dim=-1)


class TemporalAttention(nn.Module):
    """
    Temporal attention mechanism for aggregating node features over time
    
    Computes attention weights based on temporal distance, giving more
    importance to recent events.
    
    Args:
        feature_dim: Dimension of node features
        decay_lambda: Temporal decay rate
    """
    
    def __init__(self, feature_dim: int, decay_lambda: float = 0.01):
        super().__init__()
        self.feature_dim = feature_dim
        self.decay = TemporalDecay(decay_lambda, learnable=True)
        
        # Attention parameters
        self.W_query = nn.Linear(feature_dim, feature_dim)
        self.W_key = nn.Linear(feature_dim, feature_dim)
        self.W_value = nn.Linear(feature_dim, feature_dim)
    
    def forward(
        self,
        features: torch.Tensor,
        timestamps: torch.Tensor,
        current_time: torch.Tensor,
        mask: Optional[torch.Tensor] = None,
    ) -> torch.Tensor:
        """
        Apply temporal attention
        
        Args:
            features: Node features [num_nodes, feature_dim]
            timestamps: Event timestamps [num_nodes]
            current_time: Current time (scalar or [num_nodes])
            mask: Optional mask for valid events [num_nodes]
        
        Returns:
            Aggregated features [feature_dim]
        """
        # Compute decay factors
        time_diff = current_time - timestamps
        decay_weight = self.decay(time_diff)
        
        # Compute attention
        Q = self.W_query(features)
        K = self.W_key(features)
        V = self.W_value(features)
        
        # Attention scores with temporal decay
        attention_scores = torch.matmul(Q, K.transpose(-2, -1)) / math.sqrt(self.feature_dim)
        attention_scores = attention_scores * decay_weight.unsqueeze(-1)
        
        # Apply mask if provided
        if mask is not None:
            attention_scores = attention_scores.masked_fill(~mask.unsqueeze(-1), float('-inf'))
        
        # Softmax and aggregate
        attention_weights = torch.softmax(attention_scores, dim=-2)
        output = torch.matmul(attention_weights, V)
        
        return output.squeeze()


def time_to_seconds(time_str: str) -> float:
    """
    Convert time string (e.g., '2h', '30m', '5d') to seconds
    
    Args:
        time_str: Time string with suffix (s/m/h/d)
    
    Returns:
        Time in seconds
    """
    suffixes = {'s': 1, 'm': 60, 'h': 3600, 'd': 86400}
    return float(time_str[:-1]) * suffixes[time_str[-1]]


def compute_time_features(
    timestamp: torch.Tensor,
    window_size: float = 3600.0,
) -> dict:
    """
    Compute various time-based features
    
    Args:
        timestamp: Unix timestamp
        window_size: Time window in seconds
    
    Returns:
        Dictionary of time features
    """
    import datetime
    
    # Convert to datetime
    if isinstance(timestamp, torch.Tensor):
        timestamp = timestamp.item()
    
    dt = datetime.datetime.fromtimestamp(timestamp)
    
    return {
        'hour_of_day': dt.hour,
        'day_of_week': dt.weekday(),
        'day_of_month': dt.day,
        'is_weekend': int(dt.weekday() >= 5),
        'is_business_hours': int(9 <= dt.hour < 17),
        'is_night': int(dt.hour < 6 or dt.hour >= 22),
    }
