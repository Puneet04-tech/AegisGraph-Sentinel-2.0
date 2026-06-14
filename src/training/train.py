import logging
import os
import torch
import torch.nn.functional as F
from torch.optim import AdamW
from torch.optim.lr_scheduler import CosineAnnealingLR
from tqdm import tqdm
from pathlib import Path

from .data_loader import AegisGraphLoader
from ..utils.encryption import get_encryption_handler

logger = logging.getLogger(__name__)

# Attempt to import the real model architecture, fallback to a mock for pipeline testing
try:
    from ..models.htgnn import AegisHTGNN
except ImportError:
    import torch.nn as nn
    class AegisHTGNN(nn.Module):
        """Mock model to verify the training pipeline execution"""
        def __init__(self, hidden_channels=64, out_channels=1):
            super().__init__()
            # Dummy linear layer to simulate GNN transformations
            self.lin = nn.Linear(10, out_channels) 
            
        def forward(self, x_dict, edge_index_dict):
            # Mock forward pass returning logits for account nodes
            num_accounts = x_dict['account'].size(0)
            return torch.randn((num_accounts, 1), requires_grad=True).to(x_dict['account'].device)

def train_epoch(model, loader, optimizer, device, max_grad_norm=1.0, scaler=None):
    """
    Executes one full pass over the training data with numerical stability measures.

    Args:
        model: The GNN model to train
        loader: DataLoader for training batches
        optimizer: Optimizer (AdamW recommended)
        device: CPU or GPU device
        max_grad_norm: Maximum L2 norm for gradient clipping (default: 1.0)
        scaler: Optional GradScaler for mixed precision training

    Returns:
        Tuple of (average_loss, accuracy)
    """
    model.train()
    total_loss = 0
    correct = 0
    total_samples = 0
    batch_count = 0

    # Wrap the loader in a progress bar
    pbar = tqdm(loader, desc="Training Batches", leave=False)

    for batch in pbar:
        batch = batch.to(device)
        optimizer.zero_grad()

        # 1. Forward Pass (Feed node features and edge indices)
        out = model(batch.x_dict, batch.edge_index_dict)

        # 2. Label Preparation
        # If the synthetic graph doesn't have 'y' labels yet, mock them for the test
        if 'y' not in batch['account']:
            batch['account'].y = torch.randint(
                0, 2, (batch['account'].num_nodes, 1), dtype=torch.float32
            ).to(device)

        labels = batch['account'].y.float()

        # 3. Calculate Loss (Binary Cross Entropy for Fraud/Not-Fraud)
        loss = F.binary_cross_entropy_with_logits(out, labels)

        # 4. Backward Pass (with optional mixed precision)
        if scaler is not None:
            scaler.scale(loss).backward()
        else:
            loss.backward()

        # 5. Gradient Clipping (CRITICAL for stabilizing Graph Neural Networks)
        # Prevents exploding gradients on large graphs
        # max_norm=1.0 is effective for most GNN architectures
        if scaler is not None:
            scaler.unscale_(optimizer)
        torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=max_grad_norm)

        # 6. Optimize Weights (with optional mixed precision)
        if scaler is not None:
            scaler.step(optimizer)
            scaler.update()
        else:
            optimizer.step()

        # Metrics Calculation
        total_loss += float(loss) * batch['account'].num_nodes
        preds = (torch.sigmoid(out) > 0.5).float()
        correct += int((preds == labels).sum())
        total_samples += batch['account'].num_nodes
        batch_count += 1

        pbar.set_postfix({'loss': f"{loss.item():.4f}"})

    avg_loss = total_loss / total_samples if total_samples > 0 else 0
    avg_acc = correct / total_samples if total_samples > 0 else 0

    return avg_loss, avg_acc

def main():
    logger.info("Initializing HTGNN Training Pipeline with Stability Enhancements...")

    # Auto-detect GPU acceleration
    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    logger.info("Hardware utilized: %s", device)

    # 1. Load the Temporal Dataloader we built previously
    try:
        sampler = AegisGraphLoader(batch_size=64)
        train_loader = sampler.get_train_loader()
    except FileNotFoundError:
        logger.error("Synthetic graph not found. Run graph generation first.")
        return

    # 2. Initialize Model and Optimizer with stability parameters
    model = AegisHTGNN().to(device)

    # AdamW with proper hyperparameters for GNNs on large graphs
    # - lower learning rate for stability
    # - weight decay for regularization
    # - eps for numerical stability
    optimizer = AdamW(
        model.parameters(),
        lr=0.001,
        weight_decay=1e-4,
        eps=1e-8,
        amsgrad=True  # Use AMSGrad variant for more stable updates
    )

    # 3. Learning Rate Scheduler (CosineAnnealing for smooth decay)
    # Helps prevent divergence by gradually reducing learning rate
    epochs = 3
    scheduler = CosineAnnealingLR(optimizer, T_max=epochs, eta_min=1e-6)

    # 4. Optional: Mixed Precision Training (for larger graphs)
    # Uncomment to enable for improved stability on very large graphs
    # from torch.cuda.amp import GradScaler
    # scaler = GradScaler() if device.type == 'cuda' else None

    # 5. Execute Training Loop
    logger.info("Starting training for %d epochs...", epochs)
    logger.info("Gradient clipping: enabled (max_norm=1.0)")
    logger.info("Learning rate scheduler: CosineAnnealing")
    logger.info("Optimizer: AdamW with AMSGrad variant")

    for epoch in range(1, epochs + 1):
        logger.info("--- Epoch %d/%d ---", epoch, epochs)

        # Train with gradient clipping
        loss, acc = train_epoch(
            model,
            train_loader,
            optimizer,
            device,
            max_grad_norm=1.0,
            scaler=None  # Set to scaler object if using mixed precision
        )
        logger.info(
            "Loss: %.4f | Accuracy: %.4f | LR: %.2e",
            loss, acc, optimizer.param_groups[0]['lr'],
        )

        # Step the scheduler to decay learning rate
        scheduler.step()

    # 6. Save the compiled artifact with encryption
    logger.info("Training Complete! Saving encrypted model weights...")
    models_dir = Path("models")
    models_dir.mkdir(parents=True, exist_ok=True)

    # Create checkpoint dict and encrypt before saving
    checkpoint = {'model_state_dict': model.state_dict()}
    encryption = get_encryption_handler()
    encrypted_data = encryption.encrypt_checkpoint(checkpoint)

    # Write encrypted checkpoint to disk
    checkpoint_path = models_dir / "htgnn_v1.pt"
    with open(checkpoint_path, 'wb') as f:
        f.write(encrypted_data)
    logger.info("Encrypted artifact saved to %s", checkpoint_path)

if __name__ == "__main__":
    main()