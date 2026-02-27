"""
Example: Training the HTGNN Model

This script demonstrates how to train the fraud detection model
"""

import torch
from torch.utils.data import Dataset, DataLoader
import numpy as np
from pathlib import Path

from src.models.risk_model import FraudDetectionModel
from src.training.trainer import Trainer
from src.utils.helpers import load_config, set_seed, get_device


class FraudGraphDataset(Dataset):
    """
    Simple dataset for demonstration
    In practice, you would load real graph data
    """
    
    def __init__(self, num_samples=1000):
        self.num_samples = num_samples
        self.node_feature_dim = 32
        
    def __len__(self):
        return self.num_samples
    
    def __getitem__(self, idx):
        # Generate synthetic graph (for demonstration)
        num_nodes = np.random.randint(10, 50)
        num_edges = np.random.randint(num_nodes, num_nodes * 3)
        
        # Node features
        x = torch.randn(num_nodes, self.node_feature_dim)
        
        # Edge index
        edge_index = torch.randint(0, num_nodes, (2, num_edges))
        
        # Node types (5 types: Account, Device, ATM, Merchant, IP)
        node_type = torch.randint(0, 5, (num_nodes,))
        
        # Edge types (4 types: Transfer, Login, Withdrawal, Association)
        edge_type = torch.randint(0, 4, (num_edges,))
        
        # Edge timestamps
        edge_timestamp = torch.rand(num_edges) * 86400  # Random within 24 hours
        
        # Label (fraud or not)
        label = torch.tensor(1 if np.random.random() < 0.1 else 0)
        
        return {
            'x': x,
            'edge_index': edge_index,
            'node_type': node_type,
            'edge_type': edge_type,
            'edge_timestamp': edge_timestamp,
            'label': label,
        }


def collate_fn(batch):
    """Custom collate function for batching graphs"""
    # For simplicity, we process one graph at a time
    # In practice, you would use PyTorch Geometric's batching
    return batch[0]


def main():
    print("=" * 80)
    print("AegisGraph Sentinel 2.0 - Model Training Example")
    print("=" * 80)
    
    # Set seed for reproducibility
    set_seed(42)
    
    # Get device
    device = get_device()
    print(f"\nUsing device: {device}")
    
    # Load configuration
    try:
        config = load_config('config/config.yaml')
    except FileNotFoundError:
        print("\n⚠ Config file not found, using default settings")
        config = {
            'model': {
                'htgat': {
                    'hidden_dim': 128,
                    'output_dim': 64,
                    'num_layers': 2,
                    'num_heads': 4,
                    'dropout': 0.3,
                }
            },
            'training': {
                'learning_rate': 0.001,
                'batch_size': 32,
                'num_epochs': 10,
                'early_stopping_patience': 5,
                'optimizer': 'adam',
                'weight_decay': 0.0001,
                'scheduler': 'cosine',
                'loss': {
                    'type': 'focal',
                    'alpha': 0.25,
                    'gamma': 2.0,
                }
            }
        }
    
    # Create model
    print("\nCreating model...")
    model_config = config.get('model', {}).get('htgat', {})
    model = FraudDetectionModel(
        node_feature_dim=32,
        hidden_dim=model_config.get('hidden_dim', 128),
        output_dim=model_config.get('output_dim', 64),
        num_node_types=5,
        num_edge_types=4,
        num_layers=model_config.get('num_layers', 2),
        heads=model_config.get('num_heads', 4),
        dropout=model_config.get('dropout', 0.3),
    )
    
    # Count parameters
    num_params = sum(p.numel() for p in model.parameters() if p.requires_grad)
    print(f"Model parameters: {num_params:,}")
    
    # Create datasets
    print("\nCreating datasets...")
    train_dataset = FraudGraphDataset(num_samples=100)
    val_dataset = FraudGraphDataset(num_samples=20)
    
    # Create data loaders
    train_loader = DataLoader(
        train_dataset,
        batch_size=1,
        shuffle=True,
        collate_fn=collate_fn,
    )
    
    val_loader = DataLoader(
        val_dataset,
        batch_size=1,
        shuffle=False,
        collate_fn=collate_fn,
    )
    
    # Create trainer
    print("\nInitializing trainer...")
    trainer = Trainer(model, config, device)
    
    # Train model
    print("\nStarting training...")
    print("Note: This is a demonstration with synthetic data")
    print("-" * 80)
    
    trainer.train(
        train_loader,
        val_loader,
        num_epochs=10,
        early_stopping_patience=5,
        save_dir='models',
    )
    
    print("\n" + "=" * 80)
    print("Training complete!")
    print("=" * 80)
    print(f"\nBest validation F1: {trainer.best_val_f1:.4f}")
    print(f"Model saved to: models/htgnn_best.pt")
    print("\nTo use the trained model:")
    print("   from src.models.risk_model import FraudDetectionModel")
    print("   model = FraudDetectionModel(...)")
    print("   model.load_state_dict(torch.load('models/htgnn_best.pt'))")


if __name__ == "__main__":
    main()
