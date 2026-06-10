"""Adversarial training and robustness evaluation for fraud detection models.

This module implements techniques to improve GNN model robustness against adversarial
attacks that could bypass fraud detection. Includes FGSM, PGD attacks and adversarial
training methods.

References:
- Fast Gradient Sign Method (FGSM): Goodfellow et al., 2014
- Projected Gradient Descent (PGD): Madry et al., 2019
- Adversarial Training: Trades-off robustness vs accuracy
"""

from typing import Dict, Tuple, Optional
import torch
import torch.nn as nn
import torch.nn.functional as F
import numpy as np
from copy import deepcopy


class AdversarialAttack:
    """Base class for adversarial attacks on graph neural networks."""

    def __init__(self, model: nn.Module, epsilon: float = 0.1, device: str = 'cpu'):
        """Initialize adversarial attack.

        Args:
            model: The target model to attack
            epsilon: Maximum perturbation magnitude
            device: Device to run attacks on (cpu/cuda)
        """
        self.model = model
        self.epsilon = epsilon
        self.device = device

    def attack(self, x: torch.Tensor, **kwargs) -> torch.Tensor:
        """Generate adversarial examples. Must be implemented by subclasses.

        Args:
            x: Input node features

        Returns:
            Adversarial perturbed features
        """
        raise NotImplementedError


class FGSMAttack(AdversarialAttack):
    """Fast Gradient Sign Method (FGSM) attack.

    Simple and effective attack that perturbs inputs in the direction of the gradient
    of the loss with respect to the inputs. Good for testing basic robustness.

    Reference: Goodfellow et al., 2014
    """

    def attack(
        self,
        x: torch.Tensor,
        edge_index: torch.Tensor,
        node_type: torch.Tensor,
        edge_type: torch.Tensor,
        edge_timestamp: torch.Tensor,
        labels: torch.Tensor,
        batch: Optional[torch.Tensor] = None,
    ) -> torch.Tensor:
        """Generate adversarial examples using FGSM.

        Args:
            x: Node features [num_nodes, feature_dim]
            edge_index: Graph connectivity [2, num_edges]
            node_type: Node type indices [num_nodes]
            edge_type: Edge type indices [num_edges]
            edge_timestamp: Edge timestamps [num_edges]
            labels: Ground truth labels [num_nodes]
            batch: Batch indices for graphs (optional)

        Returns:
            Adversarial node features with bounded perturbations
        """
        # Clone and require grad for perturbation computation
        x_adv = x.clone().detach().requires_grad_(True)

        # Forward pass
        outputs = self.model(
            x=x_adv,
            edge_index=edge_index,
            node_type=node_type,
            edge_type=edge_type,
            edge_timestamp=edge_timestamp,
            batch=batch,
        )

        # Compute loss
        loss = F.binary_cross_entropy_with_logits(
            outputs['risk'].squeeze(), labels.float()
        )

        # Compute gradient
        self.model.zero_grad()
        loss.backward()

        # Apply FGSM perturbation
        with torch.no_grad():
            grad_sign = x_adv.grad.sign()
            x_adv_perturbed = x_adv + self.epsilon * grad_sign
            # Clip to valid range (typically [0, 1] for normalized features)
            x_adv_perturbed = torch.clamp(x_adv_perturbed, min=0, max=1)

        return x_adv_perturbed


class PGDAttack(AdversarialAttack):
    """Projected Gradient Descent (PGD) attack.

    Stronger iterative attack that repeatedly applies gradient steps with projection.
    More effective than FGSM but computationally expensive. Good for evaluating
    robust training.

    Reference: Madry et al., 2019
    """

    def __init__(
        self,
        model: nn.Module,
        epsilon: float = 0.1,
        alpha: float = 0.01,
        num_steps: int = 10,
        device: str = 'cpu',
    ):
        """Initialize PGD attack.

        Args:
            model: Target model
            epsilon: Maximum perturbation magnitude
            alpha: Step size for gradient ascent
            num_steps: Number of PGD iterations
            device: Device to run attacks on
        """
        super().__init__(model, epsilon, device)
        self.alpha = alpha
        self.num_steps = num_steps

    def attack(
        self,
        x: torch.Tensor,
        edge_index: torch.Tensor,
        node_type: torch.Tensor,
        edge_type: torch.Tensor,
        edge_timestamp: torch.Tensor,
        labels: torch.Tensor,
        batch: Optional[torch.Tensor] = None,
    ) -> torch.Tensor:
        """Generate adversarial examples using PGD.

        Args:
            x: Node features [num_nodes, feature_dim]
            edge_index: Graph connectivity
            node_type: Node type indices
            edge_type: Edge type indices
            edge_timestamp: Edge timestamps
            labels: Ground truth labels
            batch: Batch indices (optional)

        Returns:
            Adversarial node features with bounded perturbations
        """
        # Initialize with random perturbation
        x_adv = x.clone().detach()
        x_adv += torch.zeros_like(x).uniform_(-self.epsilon, self.epsilon)
        x_adv = torch.clamp(x_adv, min=0, max=1)

        # Iterative PGD attack
        for _ in range(self.num_steps):
            x_adv.requires_grad = True

            # Forward pass
            outputs = self.model(
                x=x_adv,
                edge_index=edge_index,
                node_type=node_type,
                edge_type=edge_type,
                edge_timestamp=edge_timestamp,
                batch=batch,
            )

            # Compute loss
            loss = F.binary_cross_entropy_with_logits(
                outputs['risk'].squeeze(), labels.float()
            )

            # Compute gradient
            self.model.zero_grad()
            loss.backward()

            # PGD step
            with torch.no_grad():
                grad = x_adv.grad
                x_adv = x_adv + self.alpha * grad.sign()

                # Project back to epsilon-ball around original input
                delta = x_adv - x
                delta = torch.clamp(delta, min=-self.epsilon, max=self.epsilon)
                x_adv = x + delta

                # Clip to valid range
                x_adv = torch.clamp(x_adv, min=0, max=1)
                x_adv = x_adv.detach()

        return x_adv


class AdversarialTrainer:
    """Trainer for adversarial robustness in fraud detection models."""

    def __init__(
        self,
        model: nn.Module,
        attack_method: str = 'fgsm',
        epsilon: float = 0.1,
        adversarial_weight: float = 0.5,
        device: str = 'cpu',
    ):
        """Initialize adversarial trainer.

        Args:
            model: The model to train
            attack_method: Type of attack ('fgsm' or 'pgd')
            epsilon: Perturbation budget
            adversarial_weight: Weight for adversarial loss in combined loss
            device: Device to run on
        """
        self.model = model
        self.epsilon = epsilon
        self.adversarial_weight = adversarial_weight
        self.device = device

        # Initialize attack method
        if attack_method == 'fgsm':
            self.attack = FGSMAttack(model, epsilon, device)
        elif attack_method == 'pgd':
            self.attack = PGDAttack(model, epsilon, alpha=epsilon / 4, num_steps=10, device=device)
        else:
            raise ValueError(f"Unknown attack method: {attack_method}")

    def compute_adversarial_loss(
        self,
        x: torch.Tensor,
        edge_index: torch.Tensor,
        node_type: torch.Tensor,
        edge_type: torch.Tensor,
        edge_timestamp: torch.Tensor,
        labels: torch.Tensor,
        batch: Optional[torch.Tensor] = None,
        criterion: Optional[nn.Module] = None,
    ) -> torch.Tensor:
        """Compute loss on adversarial examples.

        Args:
            x: Node features
            edge_index: Graph connectivity
            node_type: Node type indices
            edge_type: Edge type indices
            edge_timestamp: Edge timestamps
            labels: Ground truth labels
            batch: Batch indices (optional)
            criterion: Loss function (default: BCE with logits)

        Returns:
            Loss computed on adversarial examples
        """
        # Generate adversarial examples
        x_adv = self.attack.attack(
            x=x,
            edge_index=edge_index,
            node_type=node_type,
            edge_type=edge_type,
            edge_timestamp=edge_timestamp,
            labels=labels,
            batch=batch,
        )

        # Forward pass on adversarial examples
        with torch.no_grad():
            # Detach to prevent double backprop through attack
            x_adv = x_adv.detach()

        self.model.train()
        outputs = self.model(
            x=x_adv,
            edge_index=edge_index,
            node_type=node_type,
            edge_type=edge_type,
            edge_timestamp=edge_timestamp,
            batch=batch,
        )

        # Compute loss
        if criterion is None:
            criterion = F.binary_cross_entropy_with_logits

        if isinstance(criterion, nn.Module):
            loss = criterion(outputs['risk'].squeeze(), labels.float())
        else:
            loss = criterion(outputs['risk'].squeeze(), labels.float())

        return loss

    def compute_combined_loss(
        self,
        x: torch.Tensor,
        edge_index: torch.Tensor,
        node_type: torch.Tensor,
        edge_type: torch.Tensor,
        edge_timestamp: torch.Tensor,
        labels: torch.Tensor,
        batch: Optional[torch.Tensor] = None,
        criterion: Optional[nn.Module] = None,
    ) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
        """Compute combined standard and adversarial loss.

        Args:
            x: Node features
            edge_index: Graph connectivity
            node_type: Node type indices
            edge_type: Edge type indices
            edge_timestamp: Edge timestamps
            labels: Ground truth labels
            batch: Batch indices (optional)
            criterion: Loss function

        Returns:
            Tuple of (combined_loss, standard_loss, adversarial_loss)
        """
        # Standard loss
        self.model.train()
        outputs = self.model(
            x=x,
            edge_index=edge_index,
            node_type=node_type,
            edge_type=edge_type,
            edge_timestamp=edge_timestamp,
            batch=batch,
        )

        if criterion is None:
            criterion = F.binary_cross_entropy_with_logits

        if isinstance(criterion, nn.Module):
            loss_standard = criterion(outputs['risk'].squeeze(), labels.float())
        else:
            loss_standard = criterion(outputs['risk'].squeeze(), labels.float())

        # Adversarial loss
        loss_adversarial = self.compute_adversarial_loss(
            x=x,
            edge_index=edge_index,
            node_type=node_type,
            edge_type=edge_type,
            edge_timestamp=edge_timestamp,
            labels=labels,
            batch=batch,
            criterion=criterion,
        )

        # Combined loss
        loss_combined = loss_standard + self.adversarial_weight * loss_adversarial

        return loss_combined, loss_standard, loss_adversarial


class RobustnessEvaluator:
    """Evaluate model robustness against adversarial attacks."""

    def __init__(self, model: nn.Module, device: str = 'cpu'):
        """Initialize robustness evaluator.

        Args:
            model: Model to evaluate
            device: Device to run evaluation on
        """
        self.model = model
        self.device = device

    def evaluate_fgsm_robustness(
        self,
        x: torch.Tensor,
        edge_index: torch.Tensor,
        node_type: torch.Tensor,
        edge_type: torch.Tensor,
        edge_timestamp: torch.Tensor,
        labels: torch.Tensor,
        epsilons: Optional[list] = None,
        batch: Optional[torch.Tensor] = None,
    ) -> Dict[str, np.ndarray]:
        """Evaluate robustness against FGSM attacks.

        Args:
            x: Node features
            edge_index: Graph connectivity
            node_type: Node type indices
            edge_type: Edge type indices
            edge_timestamp: Edge timestamps
            labels: Ground truth labels
            epsilons: List of epsilon values to test (default: [0.01, 0.05, 0.1, 0.2])
            batch: Batch indices (optional)

        Returns:
            Dict with accuracy at each epsilon
        """
        if epsilons is None:
            epsilons = [0.01, 0.05, 0.1, 0.2]

        results = {'epsilons': epsilons, 'accuracy': []}

        self.model.eval()

        with torch.no_grad():
            # Clean accuracy
            outputs = self.model(
                x=x,
                edge_index=edge_index,
                node_type=node_type,
                edge_type=edge_type,
                edge_timestamp=edge_timestamp,
                batch=batch,
            )
            clean_preds = (outputs['risk'].squeeze() > 0.5).long().cpu().numpy()
            clean_labels = labels.cpu().numpy()
            clean_acc = (clean_preds == clean_labels).mean()

        for eps in epsilons:
            attack = FGSMAttack(self.model, epsilon=eps, device=self.device)
            x_adv = attack.attack(
                x=x,
                edge_index=edge_index,
                node_type=node_type,
                edge_type=edge_type,
                edge_timestamp=edge_timestamp,
                labels=labels,
                batch=batch,
            )

            self.model.eval()
            with torch.no_grad():
                outputs = self.model(
                    x=x_adv,
                    edge_index=edge_index,
                    node_type=node_type,
                    edge_type=edge_type,
                    edge_timestamp=edge_timestamp,
                    batch=batch,
                )
                preds = (outputs['risk'].squeeze() > 0.5).long().cpu().numpy()
                acc = (preds == clean_labels).mean()
                results['accuracy'].append(acc)

        results['clean_accuracy'] = clean_acc
        return results

    def evaluate_pgd_robustness(
        self,
        x: torch.Tensor,
        edge_index: torch.Tensor,
        node_type: torch.Tensor,
        edge_type: torch.Tensor,
        edge_timestamp: torch.Tensor,
        labels: torch.Tensor,
        epsilons: Optional[list] = None,
        batch: Optional[torch.Tensor] = None,
    ) -> Dict[str, np.ndarray]:
        """Evaluate robustness against PGD attacks.

        Args:
            x: Node features
            edge_index: Graph connectivity
            node_type: Node type indices
            edge_type: Edge type indices
            edge_timestamp: Edge timestamps
            labels: Ground truth labels
            epsilons: List of epsilon values to test
            batch: Batch indices (optional)

        Returns:
            Dict with accuracy at each epsilon
        """
        if epsilons is None:
            epsilons = [0.01, 0.05, 0.1, 0.2]

        results = {'epsilons': epsilons, 'accuracy': []}

        self.model.eval()

        with torch.no_grad():
            # Clean accuracy
            outputs = self.model(
                x=x,
                edge_index=edge_index,
                node_type=node_type,
                edge_type=edge_type,
                edge_timestamp=edge_timestamp,
                batch=batch,
            )
            clean_preds = (outputs['risk'].squeeze() > 0.5).long().cpu().numpy()
            clean_labels = labels.cpu().numpy()
            clean_acc = (clean_preds == clean_labels).mean()

        for eps in epsilons:
            attack = PGDAttack(
                self.model,
                epsilon=eps,
                alpha=eps / 4,
                num_steps=10,
                device=self.device,
            )
            x_adv = attack.attack(
                x=x,
                edge_index=edge_index,
                node_type=node_type,
                edge_type=edge_type,
                edge_timestamp=edge_timestamp,
                labels=labels,
                batch=batch,
            )

            self.model.eval()
            with torch.no_grad():
                outputs = self.model(
                    x=x_adv,
                    edge_index=edge_index,
                    node_type=node_type,
                    edge_type=edge_type,
                    edge_timestamp=edge_timestamp,
                    batch=batch,
                )
                preds = (outputs['risk'].squeeze() > 0.5).long().cpu().numpy()
                acc = (preds == clean_labels).mean()
                results['accuracy'].append(acc)

        results['clean_accuracy'] = clean_acc
        return results
