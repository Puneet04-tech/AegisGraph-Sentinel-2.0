"""
Risk Model - End-to-end fraud detection model

Combines HTGAT with temporal encoding and risk prediction head
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
from typing import Optional, Dict, Tuple
from .htgat import HTGAT
from .temporal_encoding import TemporalEncoding, TemporalDecay


class FraudDetectionModel(nn.Module):
    """
    Complete fraud detection model using HTGAT
    
    Architecture:
        1. Temporal encoding of edges
        2. HTGAT layers for graph representation learning
        3. Graph-level pooling (for transaction subgraph)
        4. Risk prediction head
    
    Args:
        node_feature_dim: Dimension of node features
        hidden_dim: Hidden dimension
        output_dim: HTGAT output dimension
        num_node_types: Number of node types
        num_edge_types: Number of edge types
        num_layers: Number of HTGAT layers
        heads: Number of attention heads
        dropout: Dropout probability
        temporal_dim: Temporal encoding dimension
        pooling: Graph pooling method ('mean', 'max', 'sum', 'attention')
    """
    
    def __init__(
        self,
        node_feature_dim: int,
        hidden_dim: int = 128,
        output_dim: int = 64,
        num_node_types: int = 5,
        num_edge_types: int = 4,
        num_layers: int = 2,
        heads: int = 4,
        dropout: float = 0.3,
        temporal_dim: int = 16,
        pooling: str = 'attention',
    ):
        super().__init__()
        
        self.node_feature_dim = node_feature_dim
        self.hidden_dim = hidden_dim
        self.output_dim = output_dim
        self.pooling = pooling
        
        # Temporal encoding
        self.temporal_encoder = TemporalEncoding(temporal_dim)
        
        # HTGAT backbone
        self.htgat = HTGAT(
            in_channels=node_feature_dim,
            hidden_channels=hidden_dim,
            out_channels=output_dim,
            num_node_types=num_node_types,
            num_edge_types=num_edge_types,
            num_layers=num_layers,
            heads=heads,
            dropout=dropout,
            edge_dim=temporal_dim,
        )
        
        # Graph-level pooling
        if pooling == 'attention':
            self.pool_attention = nn.Sequential(
                nn.Linear(output_dim, output_dim // 2),
                nn.Tanh(),
                nn.Linear(output_dim // 2, 1),
            )
        
        # Risk prediction head
        self.risk_head = nn.Sequential(
            nn.Linear(output_dim, hidden_dim),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim // 2, 1),
            nn.Sigmoid(),
        )
    
    def forward(
        self,
        x: torch.Tensor,
        edge_index: torch.LongTensor,
        node_type: torch.LongTensor,
        edge_type: torch.LongTensor,
        edge_timestamp: torch.Tensor,
        batch: Optional[torch.LongTensor] = None,
        return_embedding: bool = False,
    ) -> Dict[str, torch.Tensor]:
        """
        Forward pass
        
        Args:
            x: Node features [num_nodes, node_feature_dim]
            edge_index: Edge indices [2, num_edges]
            node_type: Node types [num_nodes]
            edge_type: Edge types [num_edges]
            edge_timestamp: Edge timestamps [num_edges]
            batch: Batch assignment for each node (for batched graphs)
            return_embedding: Whether to return node embeddings
        
        Returns:
            Dictionary containing:
                - 'risk': Risk score [batch_size] or [1]
                - 'embedding': (Optional) Node embeddings
                - 'graph_embedding': Graph-level embedding
        """
        # Encode temporal information
        edge_attr = self.temporal_encoder(edge_timestamp)
        
        # Apply HTGAT
        node_embeddings = self.htgat(
            x=x,
            edge_index=edge_index,
            node_type=node_type,
            edge_type=edge_type,
            edge_attr=edge_attr,
        )
        
        # Graph-level pooling
        if batch is None:
            # Single graph - pool all nodes
            graph_embedding = self._pool_nodes(node_embeddings)
        else:
            # Multiple graphs - pool per graph
            num_graphs = batch.max().item() + 1
            graph_embedding = torch.stack([
                self._pool_nodes(node_embeddings[batch == i])
                for i in range(num_graphs)
            ])
        
        # Predict risk
        risk = self.risk_head(graph_embedding).squeeze(-1)
        
        result = {
            'risk': risk,
            'graph_embedding': graph_embedding,
        }
        
        if return_embedding:
            result['node_embedding'] = node_embeddings
        
        return result
    
    def _pool_nodes(self, node_embeddings: torch.Tensor) -> torch.Tensor:
        """
        Pool node embeddings to graph-level embedding
        
        Args:
            node_embeddings: Node embeddings [num_nodes, output_dim]
        
        Returns:
            Graph embedding [output_dim]
        """
        if self.pooling == 'mean':
            return node_embeddings.mean(dim=0)
        elif self.pooling == 'max':
            return node_embeddings.max(dim=0)[0]
        elif self.pooling == 'sum':
            return node_embeddings.sum(dim=0)
        elif self.pooling == 'attention':
            # Attention-based pooling
            attention_scores = self.pool_attention(node_embeddings)  # [num_nodes, 1]
            attention_weights = F.softmax(attention_scores, dim=0)
            return (node_embeddings * attention_weights).sum(dim=0)
        else:
            raise ValueError(f"Unknown pooling method: {self.pooling}")


class MultiTaskFraudModel(nn.Module):
    """
    Multi-task model that predicts multiple fraud-related objectives:
    - Binary fraud classification
    - Fraud type classification (if applicable)
    - Continuous risk score
    - Node-level mule probability
    
    Args:
        Same as FraudDetectionModel, plus:
        num_fraud_types: Number of fraud type classes
        predict_node_risk: Whether to predict per-node mule probability
    """
    
    def __init__(
        self,
        node_feature_dim: int,
        hidden_dim: int = 128,
        output_dim: int = 64,
        num_node_types: int = 5,
        num_edge_types: int = 4,
        num_layers: int = 2,
        heads: int = 4,
        dropout: float = 0.3,
        temporal_dim: int = 16,
        num_fraud_types: int = 3,
        predict_node_risk: bool = True,
    ):
        super().__init__()
        
        # Shared HTGAT backbone
        self.temporal_encoder = TemporalEncoding(temporal_dim)
        self.htgat = HTGAT(
            in_channels=node_feature_dim,
            hidden_channels=hidden_dim,
            out_channels=output_dim,
            num_node_types=num_node_types,
            num_edge_types=num_edge_types,
            num_layers=num_layers,
            heads=heads,
            dropout=dropout,
            edge_dim=temporal_dim,
        )
        
        # Graph-level pooling
        self.pool_attention = nn.Sequential(
            nn.Linear(output_dim, output_dim // 2),
            nn.Tanh(),
            nn.Linear(output_dim // 2, 1),
        )
        
        # Task-specific heads
        
        # 1. Binary fraud classification
        self.fraud_classifier = nn.Sequential(
            nn.Linear(output_dim, hidden_dim),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim, 1),
        )
        
        # 2. Fraud type classification
        self.fraud_type_classifier = nn.Sequential(
            nn.Linear(output_dim, hidden_dim),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim, num_fraud_types),
        )
        
        # 3. Continuous risk score
        self.risk_regressor = nn.Sequential(
            nn.Linear(output_dim, hidden_dim),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim, 1),
            nn.Sigmoid(),
        )
        
        # 4. Node-level mule probability (optional)
        if predict_node_risk:
            self.node_risk_head = nn.Sequential(
                nn.Linear(output_dim, hidden_dim // 2),
                nn.ReLU(),
                nn.Dropout(dropout),
                nn.Linear(hidden_dim // 2, 1),
                nn.Sigmoid(),
            )
        else:
            self.node_risk_head = None
    
    def forward(
        self,
        x: torch.Tensor,
        edge_index: torch.LongTensor,
        node_type: torch.LongTensor,
        edge_type: torch.LongTensor,
        edge_timestamp: torch.Tensor,
        batch: Optional[torch.LongTensor] = None,
    ) -> Dict[str, torch.Tensor]:
        """
        Forward pass for multi-task model
        
        Returns:
            Dictionary with:
                - 'fraud_logits': Binary fraud logits
                - 'fraud_prob': Binary fraud probability
                - 'fraud_type_logits': Fraud type logits
                - 'risk_score': Continuous risk score
                - 'node_risk': (Optional) Per-node mule probability
        """
        # Encode temporal information
        edge_attr = self.temporal_encoder(edge_timestamp)
        
        # Apply HTGAT
        node_embeddings = self.htgat(
            x=x,
            edge_index=edge_index,
            node_type=node_type,
            edge_type=edge_type,
            edge_attr=edge_attr,
        )
        
        # Graph-level pooling
        attention_scores = self.pool_attention(node_embeddings)
        attention_weights = F.softmax(attention_scores, dim=0)
        graph_embedding = (node_embeddings * attention_weights).sum(dim=0)
        
        # Task-specific predictions
        fraud_logits = self.fraud_classifier(graph_embedding)
        fraud_prob = torch.sigmoid(fraud_logits)
        
        fraud_type_logits = self.fraud_type_classifier(graph_embedding)
        
        risk_score = self.risk_regressor(graph_embedding)
        
        result = {
            'fraud_logits': fraud_logits.squeeze(-1),
            'fraud_prob': fraud_prob.squeeze(-1),
            'fraud_type_logits': fraud_type_logits,
            'risk_score': risk_score.squeeze(-1),
            'graph_embedding': graph_embedding,
        }
        
        # Node-level predictions
        if self.node_risk_head is not None:
            node_risk = self.node_risk_head(node_embeddings)
            result['node_risk'] = node_risk.squeeze(-1)
        
        return result
