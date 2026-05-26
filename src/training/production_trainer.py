"""
Production Training Pipeline for HTGNN

Implements complete training loop with:
- Real metrics (ROC-AUC, PR-AUC, F1, Precision, Recall)
- Focal loss for class imbalance
- Early stopping and checkpointing
- Validation and test sets
- GPU/CPU device management
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import DataLoader, Dataset
import numpy as np
import logging
from typing import Dict, Tuple, List, Optional
from dataclasses import dataclass, asdict
from datetime import datetime
import json
import yaml
from pathlib import Path

from sklearn.metrics import (
    roc_auc_score, precision_recall_curve, auc,
    f1_score, precision_score, recall_score,
    confusion_matrix, classification_report
)

logger = logging.getLogger(__name__)


from .losses import FocalLoss


@dataclass
class TrainingMetrics:
    """Container for training metrics"""
    epoch: int
    loss: float
    accuracy: float
    precision: float
    recall: float
    f1: float
    roc_auc: float
    pr_auc: float
    
    # Confusion matrix
    tp: int
    fp: int
    fn: int
    tn: int
    
    # Per-class metrics
    fraud_precision: float
    fraud_recall: float
    fraud_f1: float
    
    def to_dict(self) -> Dict:
        return asdict(self)
    
    def to_string(self) -> str:
        return (
            f"Epoch {self.epoch}: "
            f"Loss={self.loss:.4f}, "
            f"Acc={self.accuracy:.4f}, "
            f"F1={self.f1:.4f}, "
            f"ROC-AUC={self.roc_auc:.4f}, "
            f"PR-AUC={self.pr_auc:.4f}, "
            f"Fraud-Precision={self.fraud_precision:.4f}, "
            f"Fraud-Recall={self.fraud_recall:.4f}"
        )


class ProductionTrainer:
    """
    Production-grade trainer for HTGNN with:
    - Comprehensive metrics tracking
    - Early stopping
    - Model checkpointing
    - Learning rate scheduling
    - Device management (GPU/CPU)
    """
    
    def __init__(
        self,
        model: nn.Module,
        config: Dict,
        device: Optional[str] = None,
        output_dir: str = "models",
    ):
        """
        Args:
            model: HTGNN model
            config: Training configuration
            device: 'cuda' or 'cpu'
            output_dir: Directory to save checkpoints
        """
        self.model = model
        self.config = config
        self.device = device or ('cuda' if torch.cuda.is_available() else 'cpu')
        self.model.to(self.device)
        
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Training configuration
        self.learning_rate = config.get('learning_rate', 0.001)
        self.weight_decay = config.get('weight_decay', 0.0001)
        self.batch_size = config.get('batch_size', 32)
        self.num_epochs = config.get('num_epochs', 50)
        self.early_stopping_patience = config.get('early_stopping_patience', 10)
        
        # Loss function
        loss_config = config.get('loss', {})
        self.loss_fn = FocalLoss(
            alpha=loss_config.get('alpha', 0.25),
            gamma=loss_config.get('gamma', 2.0),
        )
        
        # Optimizer
        optimizer_type = config.get('optimizer', 'adam').lower()
        if optimizer_type == 'adam':
            self.optimizer = torch.optim.Adam(
                model.parameters(),
                lr=self.learning_rate,
                weight_decay=self.weight_decay,
            )
        elif optimizer_type == 'adamw':
            self.optimizer = torch.optim.AdamW(
                model.parameters(),
                lr=self.learning_rate,
                weight_decay=self.weight_decay,
            )
        else:
            self.optimizer = torch.optim.SGD(
                model.parameters(),
                lr=self.learning_rate,
                weight_decay=self.weight_decay,
            )
        
        # Scheduler
        scheduler_type = config.get('scheduler', 'cosine').lower()
        if scheduler_type == 'cosine':
            self.scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(
                self.optimizer,
                T_max=self.num_epochs,
            )
        else:
            self.scheduler = torch.optim.lr_scheduler.StepLR(
                self.optimizer,
                step_size=10,
                gamma=0.1,
            )
        
        # Metrics tracking
        self.train_metrics: List[TrainingMetrics] = []
        self.val_metrics: List[TrainingMetrics] = []
        self.best_val_f1 = -1.0
        self.best_val_epoch = 0
        self.patience_counter = 0
        
        logger.info(
            f"Trainer initialized on {self.device}: "
            f"LR={self.learning_rate}, "
            f"epochs={self.num_epochs}, "
            f"batch_size={self.batch_size}"
        )
    
    def train(
        self,
        train_loader: DataLoader,
        val_loader: DataLoader,
        test_loader: Optional[DataLoader] = None,
    ) -> Dict:
        """
        Complete training loop.
        
        Args:
            train_loader: Training data loader
            val_loader: Validation data loader
            test_loader: Optional test data loader
        
        Returns:
            Dictionary with final metrics and checkpoints
        """
        logger.info("Starting training...")
        
        for epoch in range(self.num_epochs):
            # Train epoch
            train_metrics = self._train_epoch(epoch, train_loader)
            self.train_metrics.append(train_metrics)
            
            # Validation
            val_metrics = self._validate_epoch(epoch, val_loader)
            self.val_metrics.append(val_metrics)
            
            logger.info(train_metrics.to_string())
            logger.info(f"  VAL: {val_metrics.to_string()}")
            
            # Learning rate scheduling
            self.scheduler.step()
            
            # Early stopping
            if val_metrics.f1 > self.best_val_f1:
                self.best_val_f1 = val_metrics.f1
                self.best_val_epoch = epoch
                self.patience_counter = 0
                
                # Save best model
                self._save_checkpoint(epoch, val_metrics, is_best=True)
                logger.info(f"✓ Best model saved (F1={self.best_val_f1:.4f})")
            else:
                self.patience_counter += 1
                if self.patience_counter >= self.early_stopping_patience:
                    logger.info(
                        f"Early stopping at epoch {epoch} "
                        f"(best: {self.best_val_epoch}, F1={self.best_val_f1:.4f})"
                    )
                    break
        
        # Test set evaluation (if provided)
        results = {
            'best_epoch': self.best_val_epoch,
            'best_val_f1': self.best_val_f1,
            'train_metrics': [m.to_dict() for m in self.train_metrics],
            'val_metrics': [m.to_dict() for m in self.val_metrics],
        }
        
        if test_loader is not None:
            test_metrics = self._validate_epoch(
                epoch=len(self.train_metrics),
                dataloader=test_loader,
                phase='test',
            )
            logger.info(f"TEST: {test_metrics.to_string()}")
            results['test_metrics'] = test_metrics.to_dict()
        
        # Save final results
        self._save_results(results)
        
        return results
    
    def _train_epoch(self, epoch: int, dataloader: DataLoader) -> TrainingMetrics:
        """Train for one epoch"""
        self.model.train()
        
        total_loss = 0.0
        all_preds = []
        all_targets = []
        num_batches = 0
        
        for batch_idx, batch in enumerate(dataloader):
            # Move batch to device
            batch = self._move_batch_to_device(batch)
            
            # Forward pass
            outputs = self.model(batch)
            risk_scores = outputs['risk'] if isinstance(outputs, dict) else outputs
            targets = batch.y.to(device=risk_scores.device, dtype=risk_scores.dtype).reshape_as(risk_scores)
            
            # Loss
            loss = self.loss_fn(risk_scores, targets)
            
            # Backward pass
            self.optimizer.zero_grad()
            loss.backward()
            torch.nn.utils.clip_grad_norm_(self.model.parameters(), max_norm=1.0)
            self.optimizer.step()
            
            # Tracking
            total_loss += loss.item()
            num_batches += 1
            
            # Predictions
            preds = risk_scores.detach().cpu().numpy() > 0.5
            all_preds.extend(preds.flatten().tolist())
            all_targets.extend(targets.detach().cpu().numpy().flatten().tolist())
            
            if (batch_idx + 1) % 10 == 0:
                logger.debug(
                    f"Epoch {epoch} [{batch_idx+1}/{len(dataloader)}] "
                    f"Loss: {loss.item():.4f}"
                )

        if num_batches == 0:
            logger.warning(f"Epoch {epoch}: empty training dataloader; returning default metrics")
            return self._empty_metrics(epoch=epoch, total_loss=0.0)
        
        # Compute metrics
        metrics = self._compute_metrics(
            epoch=epoch,
            total_loss=total_loss / num_batches,
            all_preds=all_preds,
            all_targets=all_targets,
        )
        
        return metrics
    
    def _validate_epoch(
        self,
        epoch: int,
        dataloader: DataLoader,
        phase: str = 'val',
    ) -> TrainingMetrics:
        """Validate on a set"""
        self.model.eval()
        
        total_loss = 0.0
        all_preds = []
        all_probs = []
        all_targets = []
        num_batches = 0
        
        with torch.no_grad():
            for batch in dataloader:
                batch = self._move_batch_to_device(batch)
                
                # Forward pass
                outputs = self.model(batch)
                risk_scores = outputs['risk'] if isinstance(outputs, dict) else outputs
                targets = batch.y.to(device=risk_scores.device, dtype=risk_scores.dtype).reshape_as(risk_scores)
                
                # Loss
                loss = self.loss_fn(risk_scores, targets)
                
                # Tracking
                total_loss += loss.item()
                num_batches += 1
                
                # Predictions
                probs = risk_scores.detach().cpu().numpy()
                preds = (probs > 0.5).astype(int)
                all_probs.extend(probs.flatten().tolist())
                all_preds.extend(preds.flatten().tolist())
                all_targets.extend(targets.detach().cpu().numpy().flatten().tolist())
        
        if num_batches == 0:
            logger.warning(f"Epoch {epoch} ({phase}): empty dataloader; returning default metrics")
            return self._empty_metrics(epoch=epoch, total_loss=0.0)
        
        # Compute metrics with probabilities for ROC-AUC
        metrics = self._compute_metrics(
            epoch=epoch,
            total_loss=total_loss / num_batches,
            all_preds=all_preds,
            all_targets=all_targets,
            all_probs=all_probs,
        )
        
        return metrics
    
    def _compute_metrics(
        self,
        epoch: int,
        total_loss: float,
        all_preds: List,
        all_targets: List,
        all_probs: Optional[List] = None,
    ) -> TrainingMetrics:
        """Compute all evaluation metrics"""
        
        all_preds = np.asarray(all_preds)
        all_targets = np.asarray(all_targets)

        if all_preds.size == 0 or all_targets.size == 0:
            return self._empty_metrics(epoch=epoch, total_loss=total_loss)

        # Ensure sklearn receives integer class labels even if tensors were float.
        all_preds = all_preds.astype(int, copy=False)
        all_targets = all_targets.astype(int, copy=False)
        
        # Basic metrics
        accuracy = np.mean(all_preds == all_targets)
        precision = precision_score(all_targets, all_preds, zero_division=0)
        recall = recall_score(all_targets, all_preds, zero_division=0)
        f1 = f1_score(all_targets, all_preds, zero_division=0)
        
        # ROC-AUC and PR-AUC (if probabilities available)
        if all_probs is not None and len(np.unique(all_targets)) > 1:
            all_probs = np.array(all_probs)
            roc_auc = roc_auc_score(all_targets, all_probs)
            
            # PR curve
            precision_curve, recall_curve, _ = precision_recall_curve(
                all_targets, all_probs
            )
            pr_auc = auc(recall_curve, precision_curve)
        else:
            roc_auc = 0.0
            pr_auc = 0.0
        
        # Confusion matrix (handle single-class edge cases in tiny demo splits)
        cm = confusion_matrix(all_targets, all_preds, labels=[0, 1])
        tn, fp, fn, tp = cm.ravel()
        
        # Per-fraud-class metrics
        fraud_mask = all_targets == 1
        if fraud_mask.sum() > 0:
            fraud_preds = all_preds[fraud_mask]
            fraud_targets = all_targets[fraud_mask]
            fraud_precision = precision_score(fraud_targets, fraud_preds, zero_division=0)
            fraud_recall = recall_score(fraud_targets, fraud_preds, zero_division=0)
            fraud_f1 = f1_score(fraud_targets, fraud_preds, zero_division=0)
        else:
            fraud_precision = fraud_recall = fraud_f1 = 0.0
        
        return TrainingMetrics(
            epoch=epoch,
            loss=total_loss,
            accuracy=accuracy,
            precision=precision,
            recall=recall,
            f1=f1,
            roc_auc=roc_auc,
            pr_auc=pr_auc,
            tp=int(tp),
            fp=int(fp),
            fn=int(fn),
            tn=int(tn),
            fraud_precision=fraud_precision,
            fraud_recall=fraud_recall,
            fraud_f1=fraud_f1,
        )
    
    def _empty_metrics(self, epoch: int, total_loss: float) -> TrainingMetrics:
        """Return safe defaults for empty dataloaders and degenerate splits."""
        return TrainingMetrics(
            epoch=epoch,
            loss=total_loss,
            accuracy=0.0,
            precision=0.0,
            recall=0.0,
            f1=0.0,
            roc_auc=0.0,
            pr_auc=0.0,
            tp=0,
            fp=0,
            fn=0,
            tn=0,
            fraud_precision=0.0,
            fraud_recall=0.0,
            fraud_f1=0.0,
        )
    
    def _move_batch_to_device(self, batch):
        """Move batch tensors to device"""
        if hasattr(batch, 'to'):
            return batch.to(self.device)
        return batch
    
    def _save_checkpoint(self, epoch: int, metrics: TrainingMetrics, is_best: bool = False):
        """Save model checkpoint"""
        checkpoint = {
            'epoch': epoch,
            'model_state': self.model.state_dict(),
            'optimizer_state': self.optimizer.state_dict(),
            'scheduler_state': self.scheduler.state_dict(),
            'metrics': metrics.to_dict(),
            'config': self.config,
        }
        
        # Temporary checkpoint (always save)
        ckpt_path = self.output_dir / "htgnn_checkpoint.pt"
        torch.save(checkpoint, ckpt_path)
        
        # Best checkpoint
        if is_best:
            best_path = self.output_dir / "htgnn_best.pt"
            torch.save(checkpoint, best_path)
            logger.info(f"Saved best model to {best_path}")
    
    def _save_results(self, results: Dict):
        """Save training results to YAML"""
        results_path = self.output_dir / "training_results.yaml"
        with open(results_path, 'w') as f:
            yaml.dump(results, f, default_flow_style=False)
        logger.info(f"Saved results to {results_path}")
    
    def load_best_model(self) -> bool:
        """Load best model from checkpoint"""
        best_path = self.output_dir / "htgnn_best.pt"
        if not best_path.exists():
            logger.warning(f"No best model found at {best_path}")
            return False
        
        checkpoint = torch.load(best_path, map_location=self.device, weights_only=True)
        self.model.load_state_dict(checkpoint['model_state'])
        logger.info(f"Loaded best model from {best_path}")
        return True


class SimpleGraphDataset(Dataset):
    """Simple dataset for testing"""
    
    def __init__(self, graphs: List[Dict], labels: List[int]):
        """
        Args:
            graphs: List of PyG graph dicts
            labels: Binary labels (fraud/normal)
        """
        self.graphs = graphs
        self.labels = labels
    
    def __len__(self):
        return len(self.graphs)
    
    def __getitem__(self, idx):
        graph_dict = self.graphs[idx]
        label = self.labels[idx]
        
        # Create PyG Data object
        from torch_geometric.data import Data
        return Data(
            x=graph_dict['x'],
            edge_index=graph_dict['edge_index'],
            edge_attr=graph_dict['edge_attr'] if 'edge_attr' in graph_dict else None,
            node_type=graph_dict['node_type'],
            edge_type=graph_dict['edge_type'],
            y=torch.tensor(label, dtype=torch.long),
        )


def collate_graphs(batch: List) -> Dict:
    """Collate function for graph batches"""
    from torch_geometric.data import Batch
    return Batch.from_data_list(batch)
