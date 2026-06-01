import hashlib
import os

import torch
from torch_geometric.loader import NeighborLoader
from torch_geometric.data import HeteroData

class AegisGraphLoader:
    """
    Handles memory-safe, temporal subgraph sampling for the HTGNN model.
    Prevents Out-Of-Memory (OOM) errors and data leakage (future peeking).
    """
    
    def __init__(self, graph_path='synthetic_aegis_graph.pt', batch_size=128):
        self.graph_path = graph_path
        self.batch_size = batch_size
        self.data = self._load_and_prep_graph()

    def _load_and_prep_graph(self) -> HeteroData:
        """Loads the HeteroData object and injects temporal attributes if missing."""
        if not os.path.exists(self.graph_path):
            raise FileNotFoundError(f"Graph file not found at {self.graph_path}. Run synthetic generator first.")

        expected_hash = os.getenv("AEGIS_GRAPH_SHA256")
        if not expected_hash:
            raise RuntimeError("AEGIS_GRAPH_SHA256 is unset; refusing to load graph artifact")

        with open(self.graph_path, "rb") as f:
            actual_hash = hashlib.sha256(f.read()).hexdigest()
            if actual_hash != expected_hash:
                raise RuntimeError("Graph artifact hash mismatch; refusing to load")

            f.seek(0)
            data = torch.load(f, weights_only=True)
        
        # PyG Temporal Sampling requires a 'time' attribute on the target nodes.
        # If our synthetic graph didn't explicitly define node timestamps, we mock them sequentially.
        num_accounts = data['account'].num_nodes
        if 'time' not in data['account']:
            data['account'].time = torch.arange(0, num_accounts, dtype=torch.long)
            
        # Create a boolean mask for training (e.g., train on 80% of accounts)
        if 'train_mask' not in data['account']:
            mask = torch.rand(num_accounts) < 0.8
            data['account'].train_mask = mask
            
        return data

    def get_train_loader(self) -> NeighborLoader:
        """
        Creates a temporal NeighborLoader. 
        Samples 15 neighbors for the 1st hop, and 10 for the 2nd hop.
        """
        print("Initializing Temporal Graph Sampler...")
        
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
