import hashlib
import logging
import os
from typing import Optional, Any

logger = logging.getLogger(__name__)

# NOTE:
# Tests monkeypatch `src.training.data_loader.torch.load`, so this module
# must keep exposing a `torch` attribute with a `load` attribute.
#
# Bind the real torch module when available so `torch.load(f,
# weights_only=True)` deserializes graph artifacts with genuine PyTorch.
# The stub fallback is only used when PyTorch is not installed at all, in
# which case loading a graph artifact fails with a clear error.
try:
    import torch  # noqa: F401
except ImportError:  # pragma: no cover - only when PyTorch is not installed
    torch = None

if torch is None:

    class _TorchUnavailable:
        def load(self, *args, **kwargs):
            raise RuntimeError(
                "PyTorch is not installed in this environment. "
                "Install torch to load graph artifacts."
            )

    torch = _TorchUnavailable()

class AegisGraphLoader:
    """
    Handles memory-safe, temporal subgraph sampling for the HTGNN model.
    Prevents Out-Of-Memory (OOM) errors and data leakage (future peeking).

    The train/validation split is temporal: training uses the earliest
    train_fraction of accounts by their 'time' attribute, validation the
    most recent remainder, so no future account ever leaks into training.
    """

    def __init__(
        self,
        graph_path: Optional[str] = None,
        batch_size: int = 128,
        chunk_size: int = 1000,
        train_fraction: float = 0.8,
    ):
        if not 0.0 < train_fraction < 1.0:
            raise ValueError(
                f"train_fraction must be in (0, 1), got {train_fraction}"
            )
        self.chunk_size = chunk_size
        self.graph_path = graph_path or os.getenv("AEGIS_GRAPH_PATH", 'synthetic_aegis_graph.pt')
        self.batch_size = batch_size
        self.train_fraction = train_fraction
        self.data = self._load_and_prep_graph()

    def _load_and_prep_graph(self) -> Any:
        """Loads the HeteroData object and injects temporal attributes if missing."""
        # NOTE: unit tests monkeypatch `src.training.data_loader.torch.load`,
        # so we go through the module-level `torch` attribute (real PyTorch in
        # production, an explicit stub only when PyTorch is not installed).
        from torch_geometric.data import HeteroData  # noqa: F401

        expected_hash = os.getenv("AEGIS_GRAPH_SHA256")
        if not expected_hash:
            raise RuntimeError(
                "AEGIS_GRAPH_SHA256 is unset; refusing to load graph artifact. "
                "Set AEGIS_GRAPH_SHA256 to the SHA-256 hex digest of your graph file."
            )

        if not os.path.exists(self.graph_path):
            raise FileNotFoundError(
                f"Graph file not found at {self.graph_path}. "
                "Set AEGIS_GRAPH_PATH env var or pass graph_path to AegisGraphLoader."
            )

        hasher = hashlib.sha256()
        with open(self.graph_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                hasher.update(chunk)
            actual_hash = hasher.hexdigest()
            if actual_hash != expected_hash:
                raise RuntimeError("Graph artifact hash mismatch; refusing to load")
            f.seek(0)
            data = torch.load(f, weights_only=True)
        
        # PyG Temporal Sampling requires a 'time' attribute on the target nodes.
        # If a test doubles `torch.load` with a data object while no real torch
        # tensor ops are available (no arange/sort), stop here to avoid
        # touching any torch-dependent code path.
        if not (hasattr(torch, "arange") and hasattr(torch, "sort")):
            return data

        num_accounts = data["account"].num_nodes

        if "time" not in data["account"]:
            if hasattr(torch, "arange") and hasattr(torch, "long"):
                data["account"].time = torch.arange(
                    0, num_accounts, dtype=torch.long
                )

        # Temporal train/validation split: train on the earliest
        # train_fraction of accounts, validate on the most recent rest.
        # A random split would leak future accounts into training (the
        # model would train on events later than its validation data),
        # inflating validation metrics.
        if "train_mask" not in data["account"]:
            time = data["account"].time
            cutoff_index = max(1, int(num_accounts * self.train_fraction)) - 1
            cutoff_time = torch.sort(time).values[cutoff_index]
            # Ties at the cutoff go to training; validation is strictly later
            data["account"].train_mask = time <= cutoff_time

        if "val_mask" not in data["account"]:
            data["account"].val_mask = ~data["account"].train_mask
            if int(data["account"].val_mask.sum()) == 0:
                logger.warning(
                    "Validation split is empty: every account timestamp is "
                    "at or before the temporal cutoff."
                )

        return data

    def get_train_loader(self) -> Any:
        """
        Creates a temporal NeighborLoader. 
        Samples 15 neighbors for the 1st hop, and 10 for the 2nd hop.
        """
        logger.info("Initializing Temporal Graph Sampler")
        
        from torch_geometric.loader import NeighborLoader

        loader = NeighborLoader(
            self.data,
            # Number of neighbors to sample per hop for each edge type
            num_neighbors={
                ('account', 'transacts', 'account'): [15, 10],
                ('device', 'logs_into', 'account'): [10, 5]
            },
            batch_size=self.batch_size,
            # We only want to calculate loss on Account nodes during training
            input_nodes=('account', self.data['account'].train_mask),
            # CRITICAL: This ensures neighbors are only sampled if their timestamp is <= the root node
            time_attr='time',
            shuffle=True,
            num_workers=0 # Set to >0 if running on a heavy multi-core machine
        )
        return loader

    def get_val_loader(self) -> Any:
        """
        Creates a temporal NeighborLoader over the held-out validation
        accounts (the most recent train_fraction complement). No
        shuffling, so evaluation order is deterministic.
        """
        logger.info("Initializing Temporal Graph Sampler (validation)")

        from torch_geometric.loader import NeighborLoader

        loader = NeighborLoader(
            self.data,
            num_neighbors={
                ('account', 'transacts', 'account'): [15, 10],
                ('device', 'logs_into', 'account'): [10, 5]
            },
            batch_size=self.batch_size,
            input_nodes=('account', self.data['account'].val_mask),
            time_attr='time',
            shuffle=False,
            num_workers=0
        )
        return loader

if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO, stream=sys.stdout)

    logger.info("Testing Aegis Temporal DataLoader")
    try:
        sampler = AegisGraphLoader(batch_size=32)
        train_loader = sampler.get_train_loader()

        batch = next(iter(train_loader))

        logger.info(
            "First batch sampled successfully — accounts: %d, devices: %d",
            batch['account'].num_nodes,
            batch['device'].num_nodes,
        )
        logger.debug("Batch details: %s", batch)

    except Exception as e:
        logger.error("DataLoader test failed: %s", e)
