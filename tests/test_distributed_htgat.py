"""
Unit tests for Distributed Temporal HTGAT and Dynamic Edge Sampler (Issue #3451).
"""

import torch
import pytest

from src.models.htgat import HTGAT, DynamicTemporalEdgeSampler, DistributedTemporalNeighborLoader
from src.training.distributed_train import setup_distributed, cleanup_distributed


def test_dynamic_temporal_edge_sampler():
    sampler = DynamicTemporalEdgeSampler(num_neighbors=[10], decay_factor=0.05)
    
    # 2x5 edges connecting nodes
    edge_index = torch.tensor([[0, 1, 2, 3, 4], [5, 5, 5, 6, 6]], dtype=torch.long)
    edge_timestamps = torch.tensor([100.0, 200.0, 300.0, 400.0, 500.0])
    seed_nodes = torch.tensor([5])

    sampled_indices = sampler.sample_edges(
        edge_index=edge_index,
        edge_timestamps=edge_timestamps,
        seed_nodes=seed_nodes,
        num_samples=2,
    )

    assert isinstance(sampled_indices, torch.Tensor)
    assert sampled_indices.numel() <= 2


def test_distributed_temporal_neighbor_loader():
    data_meta = {"num_nodes": 100}
    loader = DistributedTemporalNeighborLoader(
        data_or_edges=data_meta,
        num_neighbors=[10, 5],
        batch_size=20,
        rank=0,
        world_size=2,
        shuffle=False,
    )

    batches = list(loader)
    assert len(batches) == 3  # 50 nodes for rank 0 / batch size 20 = 3 batches
    assert batches[0]["batch_size"] == 20
    assert batches[0]["rank"] == 0
