"""
Training Pipeline for HTGNN Fraud Detection Model
"""

import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader
from typing import Dict, Optional, List, Tuple
import numpy as np
from pathlib import Path
import yaml
from tqdm import tqdm
import time

from .losses import FocalLoss, CombinedLoss
from ..models.risk_model import FraudDetectionModel


class Trainer:
    """
    Training pipeline for fraud detection model
    
    Features:
    - Supports multiple loss functions
    - Early stopping
    - Learning rate scheduling
    - Model checkpointing
    - Metrics tracking
    
    Args:
        model: Fraud detection model
        config: Configuration dictionary
        device: torch device
    """
    
    def __init__(
        self,
        model: nn.Module,
        config: dict,
        device: torch.device = None,
    ):
        self.model = model
        self.config = config
        self.device = device or torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        
        self.model.to(self.device)
        
        # Loss function
        loss_config = config.get('training', {}).get('loss', {})
        loss_type = loss_config.get('type', 'focal')
        
        if loss_type == 'focal':
            self.criterion = FocalLoss(
                alpha=loss_config.get('alpha', 0.25),
                gamma=loss_config.get('gamma', 2.0),
            )
        else:
            self.criterion = CombinedLoss()
        
        # Optimizer
        optimizer_name = config.get('training', {}).get('optimizer', 'adam')
        lr = config.get('training', {}).get('learning_rate', 0.001)
        weight_decay = config.get('training', {}).get('weight_decay', 0.0001)
        
        if optimizer_name == 'adam':
            self.optimizer = optim.Adam(model.parameters(), lr=lr, weight_decay=weight_decay)
        elif optimizer_name == 'adamw':
            self.optimizer = optim.AdamW(model.parameters(), lr=lr, weight_decay=weight_decay)
        else:
            self.optimizer = optim.SGD(model.parameters(), lr=lr, weight_decay=weight_decay, momentum=0.9)
        
        # Learning rate scheduler
        scheduler_type = config.get('training', {}).get('scheduler', 'cosine')
        num_epochs = config.get('training', {}).get('num_epochs', 100)
        
        if scheduler_type == 'cosine':
            self.scheduler = optim.lr_scheduler.CosineAnnealingLR(
                self.optimizer, T_max=num_epochs
            )
        elif scheduler_type == 'step':
            self.scheduler = optim.lr_scheduler.StepLR(
                self.optimizer, step_size=30, gamma=0.1
            )
        else:
            self.scheduler = None
        
        # Training state
        self.current_epoch = 0
        self.best_val_loss = float('inf')
        self.best_val_f1 = 0.0
        self.patience_counter = 0
        
        # Metrics history
        self.history = {
            'train_loss': [],
            'val_loss': [],
            'train_metrics': [],
            'val_metrics': [],
        }
    
    def train_epoch(self, train_loader: DataLoader) -> Dict[str, float]:
        """
        Train for one epoch
        
        Args:
            train_loader: Training data loader
        
        Returns:
            Dictionary with epoch metrics
        """
        self.model.train()
        
        epoch_loss = 0.0
        all_preds = []
        all_labels = []
        
        pbar = tqdm(train_loader, desc=f'Epoch {self.current_epoch} [Train]')
        
        for batch in pbar:
            # Move batch to device
            batch = self._batch_to_device(batch)
            
            # Forward pass
            self.optimizer.zero_grad()
            outputs = self.model(
                x=batch['x'],
                edge_index=batch['edge_index'],
                node_type=batch['node_type'],
                edge_type=batch['edge_type'],
                edge_timestamp=batch['edge_timestamp'],
                batch=batch.get('batch', None),
            )
            
            # Compute loss
            loss = self.criterion(outputs['risk'], batch['label'].float())
            
            # Backward pass
            loss.backward()
            
            # Gradient clipping
            torch.nn.utils.clip_grad_norm_(self.model.parameters(), max_norm=1.0)
            
            self.optimizer.step()
            
            # Track metrics
            epoch_loss += loss.item()
            all_preds.extend(outputs['risk'].detach().cpu().numpy())
            all_labels.extend(batch['label'].cpu().numpy())
            
            # Update progress bar
            pbar.set_postfix({'loss': loss.item()})
        
        # Compute epoch metrics
        avg_loss = epoch_loss / len(train_loader)
        metrics = self._compute_metrics(np.array(all_preds), np.array(all_labels))
        metrics['loss'] = avg_loss
        
        return metrics
    
    def validate(self, val_loader: DataLoader) -> Dict[str, float]:
        """
        Validate model
        
        Args:
            val_loader: Validation data loader
        
        Returns:
            Dictionary with validation metrics
        """
        self.model.eval()
        
        epoch_loss = 0.0
        all_preds = []
        all_labels = []
        
        with torch.no_grad():
            for batch in tqdm(val_loader, desc=f'Epoch {self.current_epoch} [Val]'):
                # Move batch to device
                batch = self._batch_to_device(batch)
                
                # Forward pass
                outputs = self.model(
                    x=batch['x'],
                    edge_index=batch['edge_index'],
                    node_type=batch['node_type'],
                    edge_type=batch['edge_type'],
                    edge_timestamp=batch['edge_timestamp'],
                    batch=batch.get('batch', None),
                )
                
                # Compute loss
                loss = self.criterion(outputs['risk'], batch['label'].float())
                
                # Track metrics
                epoch_loss += loss.item()
                all_preds.extend(outputs['risk'].cpu().numpy())
                all_labels.extend(batch['label'].cpu().numpy())
        
        # Compute epoch metrics
        avg_loss = epoch_loss / len(val_loader)
        metrics = self._compute_metrics(np.array(all_preds), np.array(all_labels))
        metrics['loss'] = avg_loss
        
        return metrics
    
    def train(
        self,
        train_loader: DataLoader,
        val_loader: DataLoader,
        num_epochs: Optional[int] = None,
        early_stopping_patience: Optional[int] = None,
        save_dir: str = 'models',
    ):
        """
        Full training loop
        
        Args:
            train_loader: Training data loader
            val_loader: Validation data loader
            num_epochs: Number of epochs (overrides config)
            early_stopping_patience: Early stopping patience (overrides config)
            save_dir: Directory to save checkpoints
        """
        num_epochs = num_epochs or self.config.get('training', {}).get('num_epochs', 100)
        early_stopping_patience = early_stopping_patience or self.config.get('training', {}).get('early_stopping_patience', 10)
        
        save_path = Path(save_dir)
        save_path.mkdir(parents=True, exist_ok=True)
        
        print(f"Training on device: {self.device}")
        print(f"Total epochs: {num_epochs}")
        print(f"Early stopping patience: {early_stopping_patience}")
        print("-" * 80)
        
        for epoch in range(num_epochs):
            self.current_epoch = epoch
            
            # Train
            train_metrics = self.train_epoch(train_loader)
            self.history['train_loss'].append(train_metrics['loss'])
            self.history['train_metrics'].append(train_metrics)
            
            # Validate
            val_metrics = self.validate(val_loader)
            self.history['val_loss'].append(val_metrics['loss'])
            self.history['val_metrics'].append(val_metrics)
            
            # Learning rate scheduling
            if self.scheduler is not None:
                self.scheduler.step()
            
            # Print metrics
            print(f"\nEpoch {epoch+1}/{num_epochs}")
            print(f"  Train - Loss: {train_metrics['loss']:.4f}, "
                  f"F1: {train_metrics['f1']:.4f}, "
                  f"Precision: {train_metrics['precision']:.4f}, "
                  f"Recall: {train_metrics['recall']:.4f}")
            print(f"  Val   - Loss: {val_metrics['loss']:.4f}, "
                  f"F1: {val_metrics['f1']:.4f}, "
                  f"Precision: {val_metrics['precision']:.4f}, "
                  f"Recall: {val_metrics['recall']:.4f}")
            
            # Model checkpointing
            if val_metrics['f1'] > self.best_val_f1:
                self.best_val_f1 = val_metrics['f1']
                self.best_val_loss = val_metrics['loss']
                self.patience_counter = 0
                
                # Save best model
                self.save_checkpoint(save_path / 'htgnn_best.pt')
                print(f"  ✓ New best model saved (F1: {self.best_val_f1:.4f})")
            else:
                self.patience_counter += 1
            
            # Early stopping
            if self.patience_counter >= early_stopping_patience:
                print(f"\n Early stopping triggered after {epoch+1} epochs")
                break
            
            print("-" * 80)
        
        # Save final model
        self.save_checkpoint(save_path / 'htgnn_final.pt')
        
        # Save training history
        self.save_history(save_path / 'training_history.yaml')
        
        print("\nTraining completed!")
        print(f"Best validation F1: {self.best_val_f1:.4f}")
        print(f"Best validation loss: {self.best_val_loss:.4f}")
    
    def save_checkpoint(self, path: Path):
        """Save model checkpoint"""
        torch.save({
            'epoch': self.current_epoch,
            'model_state_dict': self.model.state_dict(),
            'optimizer_state_dict': self.optimizer.state_dict(),
            'best_val_f1': self.best_val_f1,
            'best_val_loss': self.best_val_loss,
            'config': self.config,
        }, path)
    
    def load_checkpoint(self, path: Path):
        """Load model checkpoint"""
        checkpoint = torch.load(path, map_location=self.device)
        self.model.load_state_dict(checkpoint['model_state_dict'])
        self.optimizer.load_state_dict(checkpoint['optimizer_state_dict'])
        self.current_epoch = checkpoint['epoch']
        self.best_val_f1 = checkpoint['best_val_f1']
        self.best_val_loss = checkpoint['best_val_loss']
    
    def save_history(self, path: Path):
        """Save training history"""
        with open(path, 'w') as f:
            yaml.dump(self.history, f)
    
    def _batch_to_device(self, batch: dict) -> dict:
        """Move batch tensors to device"""
        return {
            k: v.to(self.device) if isinstance(v, torch.Tensor) else v
            for k, v in batch.items()
        }
    
    def _compute_metrics(
        self,
        predictions: np.ndarray,
        labels: np.ndarray,
        threshold: float = 0.5,
    ) -> Dict[str, float]:
        """
        Compute classification metrics
        
        Args:
            predictions: Predicted probabilities
            labels: Ground truth labels
            threshold: Classification threshold
        
        Returns:
            Dictionary with metrics
        """
        from sklearn.metrics import (
            precision_score, recall_score, f1_score,
            roc_auc_score, average_precision_score
        )
        
        # Binary predictions
        pred_labels = (predictions >= threshold).astype(int)
        
        # Compute metrics
        precision = precision_score(labels, pred_labels, zero_division=0)
        recall = recall_score(labels, pred_labels, zero_division=0)
        f1 = f1_score(labels, pred_labels, zero_division=0)
        
        try:
            roc_auc = roc_auc_score(labels, predictions)
            pr_auc = average_precision_score(labels, predictions)
        except:
            roc_auc = 0.0
            pr_auc = 0.0
        
        return {
            'precision': precision,
            'recall': recall,
            'f1': f1,
            'roc_auc': roc_auc,
            'pr_auc': pr_auc,
        }
