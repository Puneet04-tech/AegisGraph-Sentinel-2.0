"""Synthetic heterogeneous temporal graph data generator.

Produces a PyTorch Geometric HeteroData object matching the schema
expected by src.training.data_loader.AegisGraphLoader:
  - node types: 'account', 'device'
  - edge types: ('account','transacts','account'), ('device','logs_into','account')
  - temporal attribute: account.time
  - account.train_mask for train/eval split
"""

import argparse
import hashlib
import logging
import os

logger = logging.getLogger(__name__)


def generate_attack_patterns():
    # Generate synthetic emerging attack data
    return []
# Trigger diff for v4


def generate_synthetic_hetero_temporal_graph(
    num_accounts: int = 1000,
    num_devices: int = 200,
    num_transactions: int = 5000,
    num_logins: int = 2000,
    train_ratio: float = 0.8,
    seed: int = 42,
):
    """Builds a synthetic heterogeneous temporal graph for training/testing."""
    import torch
    from torch_geometric.data import HeteroData

    g = torch.Generator().manual_seed(seed)
    data = HeteroData()

    data["account"].num_nodes = num_accounts
    data["account"].x = torch.randn(num_accounts, 16, generator=g)
    data["account"].time = torch.randint(0, 10_000, (num_accounts,), generator=g).long()
    data["account"].train_mask = torch.rand(num_accounts, generator=g) < train_ratio

    data["device"].num_nodes = num_devices
    data["device"].x = torch.randn(num_devices, 8, generator=g)

    src = torch.randint(0, num_accounts, (num_transactions,), generator=g)
    dst = torch.randint(0, num_accounts, (num_transactions,), generator=g)
    data["account", "transacts", "account"].edge_index = torch.stack([src, dst])
    data["account", "transacts", "account"].amount = torch.rand(num_transactions, generator=g) * 10_000
    data["account", "transacts", "account"].time = data["account"].time[src]

    dev_src = torch.randint(0, num_devices, (num_logins,), generator=g)
    acc_dst = torch.randint(0, num_accounts, (num_logins,), generator=g)
    data["device", "logs_into", "account"].edge_index = torch.stack([dev_src, acc_dst])
    data["device", "logs_into", "account"].time = data["account"].time[acc_dst]

    return data


def save_graph(data, path: str) -> str:
    """Saves the HeteroData to disk and returns its SHA-256 hex digest."""
    import torch

    torch.save(data, path)

    hasher = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", default="synthetic_aegis_graph.pt")
    parser.add_argument("--num-accounts", type=int, default=1000)
    parser.add_argument("--num-devices", type=int, default=200)
    parser.add_argument("--num-transactions", type=int, default=5000)
    parser.add_argument("--num-logins", type=int, default=2000)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO)
    data = generate_synthetic_hetero_temporal_graph(
        num_accounts=args.num_accounts,
        num_devices=args.num_devices,
        num_transactions=args.num_transactions,
        num_logins=args.num_logins,
        seed=args.seed,
    )
    digest = save_graph(data, args.out)

    logger.info("Wrote synthetic graph to %s", args.out)
    logger.info("SHA-256: %s", digest)
    print(f"\nSet these before running training:\n  AEGIS_GRAPH_PATH={args.out}\n  AEGIS_GRAPH_SHA256={digest}")


if __name__ == "__main__":
    main()
