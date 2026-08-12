"""
Distributed Multi-GPU DDP Training Launcher for HTGAT with Dynamic Temporal Sampling.
Scales Heterogeneous Temporal Graph Neural Network training across multi-GPU DDP clusters.
"""

import argparse
import os
import sys
import logging
from typing import Dict, Any

import torch
import torch.nn as nn
import torch.distributed as dist
from torch.nn.parallel import DistributedDataParallel as DDP

from src.models.htgat import HTGAT, DistributedTemporalNeighborLoader

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] (Rank %(rank)s) %(message)s")
logger = logging.getLogger(__name__)


def setup_distributed(rank: int, world_size: int, backend: str = "nccl"):
    """Initialize PyTorch Distributed Process Group.

    Args:
        rank: Rank of current process (0 to world_size-1)
        world_size: Total number of processes
        backend: PyTorch DDP backend ('nccl' for CUDA, 'gloo' for CPU)
    """
    os.environ["MASTER_ADDR"] = os.getenv("MASTER_ADDR", "127.0.0.1")
    os.environ["MASTER_PORT"] = os.getenv("MASTER_PORT", "29500")

    if not torch.cuda.is_available():
        backend = "gloo"

    dist.init_process_group(backend=backend, rank=rank, world_size=world_size)
    if torch.cuda.is_available():
        torch.cuda.set_device(rank)


def cleanup_distributed():
    """Destroy PyTorch Distributed Process Group."""
    if dist.is_initialized():
        dist.destroy_process_group()


def train_distributed_epoch(
    model: nn.Module,
    loader: DistributedTemporalNeighborLoader,
    optimizer: torch.optim.Optimizer,
    criterion: nn.Module,
    device: torch.device,
    rank: int,
) -> float:
    """Train HTGAT for one epoch across DDP ranks using temporal neighbor sampling.

    Args:
        model: Distributed DDP HTGAT model
        loader: DistributedTemporalNeighborLoader instance
        optimizer: PyTorch optimizer
        criterion: Loss criterion function
        device: Torch device (cuda:rank or cpu)
        rank: Current DDP process rank

    Returns:
        Average epoch loss on current rank
    """
    model.train()
    total_loss = 0.0
    num_batches = 0

    for batch in loader:
        optimizer.zero_grad()

        # Dummy node features & topology generation for distributed batch execution
        batch_size = batch["batch_size"]
        x = torch.randn(batch_size, 64, device=device)
        edge_index = torch.stack([
            torch.randint(0, batch_size, (batch_size * 2,), device=device),
            torch.randint(0, batch_size, (batch_size * 2,), device=device),
        ])
        node_type = torch.zeros(batch_size, dtype=torch.long, device=device)
        edge_type = torch.zeros(batch_size * 2, dtype=torch.long, device=device)
        target = torch.randint(0, 2, (batch_size,), device=device).float()

        out = model(x, edge_index, node_type, edge_type)
        if out.dim() > 1 and out.size(-1) > 1:
            out = out.mean(dim=-1)
        else:
            out = out.squeeze(-1)

        loss = criterion(out, target)
        loss.backward()
        optimizer.step()

        total_loss += loss.item()
        num_batches += 1

    return total_loss / max(1, num_batches)


def run_distributed_worker(rank: int, world_size: int, args: argparse.Namespace):
    """Worker function executed per distributed GPU rank."""
    setup_distributed(rank, world_size, backend=args.backend)
    device = torch.device(f"cuda:{rank}" if torch.cuda.is_available() else "cpu")

    # Instantiate HTGAT Architecture
    model = HTGAT(
        in_channels=64,
        out_channels=64,
        num_node_types=2,
        num_edge_types=2,
        num_headers=4,
        num_layers=2,
    ).to(device)

    if torch.cuda.is_available():
        model = DDP(model, device_ids=[rank])

    optimizer = torch.optim.Adam(model.parameters(), lr=args.lr)
    criterion = nn.BCEWithLogitsLoss()

    graph_metadata = {"num_nodes": args.num_nodes}
    loader = DistributedTemporalNeighborLoader(
        data_or_edges=graph_metadata,
        num_neighbors=[15, 10],
        batch_size=args.batch_size,
        rank=rank,
        world_size=world_size,
        shuffle=True,
        decay_factor=0.05,
    )

    for epoch in range(1, args.epochs + 1):
        loss = train_distributed_epoch(model, loader, optimizer, criterion, device, rank)
        if rank == 0:
            print(f"Epoch {epoch}/{args.epochs} | DDP Rank {rank} Loss: {loss:.4f}")

    cleanup_distributed()


def main():
    parser = argparse.ArgumentParser(description="Distributed HTGAT DDP Multi-GPU Trainer")
    parser.add_argument("--world_size", type=int, default=2, help="Number of DDP ranks/GPUs")
    parser.add_argument("--epochs", type=int, default=5, help="Number of training epochs")
    parser.add_argument("--batch_size", type=int, default=256, help="Batch size per GPU rank")
    parser.add_argument("--num_nodes", type=int, default=500000, help="Number of synthetic graph nodes")
    parser.add_argument("--lr", type=float, default=0.001, help="Learning rate")
    parser.add_argument("--backend", type=str, default="nccl", help="Distributed backend (nccl/gloo)")

    args = parser.parse_args()

    if torch.cuda.is_available() and torch.cuda.device_count() >= args.world_size:
        torch.multiprocessing.spawn(
            run_distributed_worker,
            args=(args.world_size, args),
            nprocs=args.world_size,
            join=True,
        )
    else:
        # Fallback to single rank worker for testing / non-CUDA environments
        run_distributed_worker(0, 1, args)


if __name__ == "__main__":
    main()
