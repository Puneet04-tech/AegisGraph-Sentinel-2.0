"""
Training Pipeline for HTGNN Fraud Detection Model
"""
# Working on model training pipeline improvements

import logging
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader
from typing import Dict, Optional, List, Tuple
import numpy as np
from pathlib import Path
import yaml
from tqdm import tqdm
import logging
from contextlib import contextmanager

try:
    import mlflow
    import mlflow.pytorch
    MLFLOW_AVAILABLE = True
except ImportError:
    mlflow = None  # type: ignore[assignment]
    MLFLOW_AVAILABLE = False

_trainer_logger = logging.getLogger(__name__)

from .losses import FocalLoss, CombinedLoss
from ..utils.helpers import get_device
from ..utils.encryption import get_encryption_handler
from .adversarial import AdversarialTrainer, RobustnessEvaluator

logger = logging.getLogger(__name__)


@contextmanager
def _nullcontext():
    """Fallback context manager for when MLflow is disabled"""
    yield


class Trainer:
    """
    Training pipeline for fraud detection model
    
    Features:
    - Supports multiple loss functions
    - Early stopping
    - Learning rate scheduling
    - Model checkpointing
    - Metrics tracking
    - Optional MLflow experiment tracking

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
        configured_device = config.get('model', {}).get('device')
        self.device = get_device(str(device) if device is not None else configured_device)
        
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

        # MLflow setup
        mlflow_config = config.get('mlflow', {})
        config_requests_mlflow = mlflow_config.get('enabled', False)

        if config_requests_mlflow and not MLFLOW_AVAILABLE:
            _trainer_logger.warning(
                "mlflow is not installed; experiment tracking will be disabled. "
                "Install it with: pip install mlflow"
            )

        self.mlflow_enabled = config_requests_mlflow and MLFLOW_AVAILABLE

        if self.mlflow_enabled:
            mlflow.set_tracking_uri(mlflow_config.get('tracking_uri', 'mlruns'))
            mlflow.set_experiment(mlflow_config.get('experiment_name', 'AegisGraph-Sentinel'))
            logger.info("MLflow tracking enabled")

        # Adversarial training setup
        adversarial_config = config.get('adversarial', {})
        self.adversarial_enabled = adversarial_config.get('enabled', False)
        self.adversarial_trainer = None
        self.robustness_evaluator = None

        if self.adversarial_enabled:
            attack_method = adversarial_config.get('attack_method', 'fgsm')
            epsilon = adversarial_config.get('epsilon', 0.1)
            adversarial_weight = adversarial_config.get('adversarial_weight', 0.5)

            self.adversarial_trainer = AdversarialTrainer(
                model=self.model,
                attack_method=attack_method,
                epsilon=epsilon,
                adversarial_weight=adversarial_weight,
                device=str(self.device),
            )
            self.robustness_evaluator = RobustnessEvaluator(
                model=self.model,
                device=str(self.device),
            )
            print(f"Adversarial training enabled (method: {attack_method}, epsilon: {epsilon})")

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
            if self.adversarial_enabled and self.adversarial_trainer is not None:
                # Combined standard and adversarial loss
                loss, loss_std, loss_adv = self.adversarial_trainer.compute_combined_loss(
                    x=batch['x'],
                    edge_index=batch['edge_index'],
                    node_type=batch['node_type'],
                    edge_type=batch['edge_type'],
                    edge_timestamp=batch['edge_timestamp'],
                    labels=batch['label'],
                    batch=batch.get('batch', None),
                    criterion=self.criterion,
                )
            else:
                loss = self.criterion(outputs['risk'], batch['label'].float())

            # Backward pass
            loss.backward()
            
            # Gradient clipping
            torch.nn.utils.clip_grad_norm_(self.model.parameters(), max_norm=1.0)
            
            self.optimizer.step()
            
            # Track metrics
            epoch_loss += loss.item()
            all_preds.extend(np.atleast_1d(outputs['risk'].detach().cpu().numpy()))
            all_labels.extend(np.atleast_1d(batch['label'].cpu().numpy()))
            
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
                all_preds.extend(np.atleast_1d(outputs['risk'].cpu().numpy()))
                all_labels.extend(np.atleast_1d(batch['label'].cpu().numpy()))
        
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
        
        logger.info("Training on device: %s", self.device)
        logger.info("Total epochs: %d", num_epochs)
        logger.info("Early stopping patience: %d", early_stopping_patience)
        logger.info("-" * 80)

        mlflow_config = self.config.get('mlflow', {})
        run_name = mlflow_config.get('run_name', None)

        with (mlflow.start_run(run_name=run_name) if self.mlflow_enabled else _nullcontext()):

            if self.mlflow_enabled:
                train_cfg = self.config.get('training', {})
                mlflow.log_params({
                    "learning_rate": train_cfg.get('learning_rate'),
                    "batch_size": train_cfg.get('batch_size'),
                    "num_epochs": num_epochs,
                    "optimizer": train_cfg.get('optimizer'),
                    "scheduler": train_cfg.get('scheduler'),
                    "loss_type": train_cfg.get('loss', {}).get('type'),
                    "early_stopping_patience": early_stopping_patience,
                    "device": str(self.device),
                })

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
                
                # Log epoch metrics
                logger.info(
                    "Epoch %d/%d | Train loss=%.4f f1=%.4f precision=%.4f recall=%.4f",
                    epoch + 1, num_epochs,
                    train_metrics['loss'], train_metrics['f1'],
                    train_metrics['precision'], train_metrics['recall'],
                )
                logger.info(
                    "Epoch %d/%d | Val   loss=%.4f f1=%.4f precision=%.4f recall=%.4f",
                    epoch + 1, num_epochs,
                    val_metrics['loss'], val_metrics['f1'],
                    val_metrics['precision'], val_metrics['recall'],
                )

                if self.mlflow_enabled:
                    mlflow.log_metrics({
                        "train_loss": train_metrics['loss'],
                        "train_f1": train_metrics['f1'],
                        "train_precision": train_metrics['precision'],
                        "train_recall": train_metrics['recall'],
                        "train_roc_auc": train_metrics['roc_auc'],
                        "val_loss": val_metrics['loss'],
                        "val_f1": val_metrics['f1'],
                        "val_precision": val_metrics['precision'],
                        "val_recall": val_metrics['recall'],
                        "val_roc_auc": val_metrics['roc_auc'],
                    }, step=epoch)
                
                # Model checkpointing
                if val_metrics['f1'] > self.best_val_f1:
                    self.best_val_f1 = val_metrics['f1']
                    self.best_val_loss = val_metrics['loss']
                    self.patience_counter = 0
                    
                    # Save best model
                    self.save_checkpoint(save_path / 'htgnn_best.pt')
                    logger.info("New best model saved (F1: %.4f)", self.best_val_f1)

                    if self.mlflow_enabled and mlflow_config.get('log_artifacts', True):
                        mlflow.pytorch.log_model(self.model, artifact_path="best_model")
                else:
                    self.patience_counter += 1
                
                # Early stopping
                if self.patience_counter >= early_stopping_patience:
                    logger.info("Early stopping triggered after %d epochs", epoch + 1)
                    break

                logger.info("-" * 80)

            # Save final model
            self.save_checkpoint(save_path / 'htgnn_final.pt')
            
            # Save training history
            self.save_history(save_path / 'training_history.yaml')
            
            logger.info("Training completed!")
            logger.info("Best validation F1: %.4f", self.best_val_f1)
            logger.info("Best validation loss: %.4f", self.best_val_loss)

    def save_checkpoint(self, path: Path):
        """Save model checkpoint with encryption.

        Encrypts checkpoint using AES-256-GCM to protect model weights.
        Encryption key is loaded from environment variables.

        Args:
            path: Destination path for encrypted checkpoint.

        Raises:
            ValueError: If encryption key is not configured.
        """
        checkpoint = {
            'epoch': self.current_epoch,
            'model_state_dict': self.model.state_dict(),
            'optimizer_state_dict': self.optimizer.state_dict(),
            'best_val_f1': self.best_val_f1,
            'best_val_loss': self.best_val_loss,
            'config': self.config,
        }
        if self.scheduler is not None:
            checkpoint['scheduler_state_dict'] = self.scheduler.state_dict()

        # Encrypt checkpoint before saving
        encryption = get_encryption_handler()
        encrypted_data = encryption.encrypt_checkpoint(checkpoint)

        # Write encrypted data to disk
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, 'wb') as f:
            f.write(encrypted_data)

    def load_checkpoint(self, path: Path):
        """Load encrypted model checkpoint.

        Decrypts checkpoint using AES-256-GCM with authentication verification.
        Encryption key is loaded from environment variables.

        Args:
            path: Path to encrypted checkpoint.

        Raises:
            ValueError: If encryption key is not configured.
            cryptography.exceptions.InvalidTag: If checkpoint authentication fails.
        """
        # Read encrypted data from disk
        path = Path(path)
        with open(path, 'rb') as f:
            encrypted_data = f.read()

        # Decrypt checkpoint
        encryption = get_encryption_handler()
        checkpoint = encryption.decrypt_checkpoint(encrypted_data)

        # Load checkpoint state
        self.model.load_state_dict(checkpoint['model_state_dict'])
        self.optimizer.load_state_dict(checkpoint['optimizer_state_dict'])
        self.current_epoch = checkpoint['epoch']
        self.best_val_f1 = checkpoint['best_val_f1']
        self.best_val_loss = checkpoint['best_val_loss']
        if self.scheduler is not None and 'scheduler_state_dict' in checkpoint:
            self.scheduler.load_state_dict(checkpoint['scheduler_state_dict'])

    def save_history(self, path: Path):
        """Save training history"""
        with open(path, 'w') as f:
            yaml.dump(self.history, f)

    def evaluate_robustness(
        self,
        val_loader: DataLoader,
        attack_type: str = 'fgsm',
        epsilons: Optional[List[float]] = None,
    ) -> Dict[str, any]:
        """Evaluate model robustness against adversarial attacks.

        Args:
            val_loader: Validation data loader
            attack_type: Type of attack ('fgsm' or 'pgd')
            epsilons: List of epsilon values to test

        Returns:
            Dictionary with robustness evaluation results
        """
        if self.robustness_evaluator is None:
            raise ValueError("Robustness evaluation requires adversarial training enabled")

        if epsilons is None:
            epsilons = [0.01, 0.05, 0.1, 0.2]

        all_results = {'epsilons': epsilons}

        # Aggregate over all batches
        for batch_idx, batch in enumerate(tqdm(val_loader, desc='Evaluating robustness')):
            batch = self._batch_to_device(batch)

            if attack_type == 'fgsm':
                results = self.robustness_evaluator.evaluate_fgsm_robustness(
                    x=batch['x'],
                    edge_index=batch['edge_index'],
                    node_type=batch['node_type'],
                    edge_type=batch['edge_type'],
                    edge_timestamp=batch['edge_timestamp'],
                    labels=batch['label'],
                    epsilons=epsilons,
                    batch=batch.get('batch', None),
                )
            else:
                results = self.robustness_evaluator.evaluate_pgd_robustness(
                    x=batch['x'],
                    edge_index=batch['edge_index'],
                    node_type=batch['node_type'],
                    edge_type=batch['edge_type'],
                    edge_timestamp=batch['edge_timestamp'],
                    labels=batch['label'],
                    epsilons=epsilons,
                    batch=batch.get('batch', None),
                )

            if batch_idx == 0:
                all_results['clean_accuracy'] = results['clean_accuracy']
                all_results['accuracy'] = np.array(results['accuracy'])
            else:
                all_results['accuracy'] += np.array(results['accuracy'])

        # Average results over all batches
        all_results['accuracy'] = all_results['accuracy'] / (batch_idx + 1)

        return all_results

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
        except ValueError:
            roc_auc = 0.0
            pr_auc = 0.0
        
        return {
            'precision': precision,
            'recall': recall,
            'f1': f1,
            'roc_auc': roc_auc,
            'pr_auc': pr_auc,
        }
