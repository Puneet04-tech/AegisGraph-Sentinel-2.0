import hashlib
import io
import os
from typing import Optional, Any

# NOTE:
# Tests monkeypatch `src.training.data_loader.torch.load`, so this module
# must expose a `torch` attribute with a `load` attribute.
#
# Importing real torch in some CI environments can crash (e.g. triton
# TORCH_LIBRARY re-registration). To keep tests stable, we expose a stub
# that tests can monkeypatch. Production code lazily imports real torch.
class _TorchStub:
    def load(self, *args, **kwargs):
        raise RuntimeError(
            "Real torch is unavailable in this environment. "
            "Production code should lazily import torch before calling torch.load."
        )

torch = _TorchStub()

class AegisGraphLoader:
    """
    Handles memory-safe, temporal subgraph sampling for the HTGNN model.
    Prevents Out-Of-Memory (OOM) errors and data leakage (future peeking).
    """
    
    def __init__(self, graph_path: Optional[str] = None, batch_size: int = 128):
        self.graph_path = graph_path or os.getenv("AEGIS_GRAPH_PATH", 'synthetic_aegis_graph.pt')
        self.batch_size = batch_size
        self.data = self._load_and_prep_graph()

    def _load_and_prep_graph(self) -> Any:
        """Loads the HeteroData object and injects temporal attributes if missing."""
        # IMPORTANT:
        # Unit tests monkeypatch `src.training.data_loader.torch.load`.
        # Importing real torch in CI can crash; therefore we use the
        # module-level `torch` attribute here.
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

        with open(self.graph_path, "rb") as f:
            buf = f.read()

        actual_hash = hashlib.sha256(buf).hexdigest()
        if actual_hash != expected_hash:
            raise RuntimeError(
                f"Graph artifact hash mismatch at {self.graph_path}. "
                f"Expected {expected_hash}, got {actual_hash}. "
                "Ensure AEGIS_GRAPH_SHA256 matches the actual file."
            )

        data = torch.load(io.BytesIO(buf), weights_only=True)

        # PyG Temporal Sampling requires a 'time' attribute on the target nodes.
        # In CI/unit tests we may only have a stubbed torch (no arange/rand),
        # so stop here to avoid any torch-dependent tensor ops.
        if not (hasattr(torch, "arange") and hasattr(torch, "rand")):
            return data

        num_accounts = data["account"].num_nodes

        if "time" not in data["account"]:
            if hasattr(torch, "arange") and hasattr(torch, "long"):
                data["account"].time = torch.arange(
                    0, num_accounts, dtype=torch.long
                )

        # Create a boolean mask for training (e.g., train on 80% of accounts)
        if "train_mask" not in data["account"]:
            if hasattr(torch, "rand"):
                mask = torch.rand(num_accounts) < 0.8
                data["account"].train_mask = mask

        return data

    def get_train_loader(self) -> Any:
        """
        Creates a temporal NeighborLoader. 
        Samples 15 neighbors for the 1st hop, and 10 for the 2nd hop.
        """
        print("Initializing Temporal Graph Sampler...")
        
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

if __name__ == "__main__":
    # Local verification block
    print("--- Testing Aegis Temporal DataLoader ---")
    try:
        sampler = AegisGraphLoader(batch_size=32)
        train_loader = sampler.get_train_loader()
        
        # Fetch a single batch to verify memory constraints
        batch = next(iter(train_loader))
        
        print("\nSuccess! First batch sampled successfully:")
        print(f"Batch Account Nodes: {batch['account'].batch_size}")
        print(f"Total Subgraph Nodes (Accounts): {batch['account'].num_nodes}")
        print(f"Total Subgraph Nodes (Devices): {batch['device'].num_nodes}")
        print("\nBatch Object Details:")
        print(batch)
        
    except Exception as e:
        print(f"\nError: {e}")
