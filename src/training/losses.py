"""
Loss Functions for Fraud Detection

Implements specialized loss functions for imbalanced fraud detection:
- Focal Loss
- Weighted Binary Cross-Entropy
- Combined losses
"""
# Working on loss functions for imbalanced data

import torch
import torch.nn as nn
import torch.nn.functional as F
from typing import Optional


class FocalLoss(nn.Module):
    """
    Focal Loss for handling class imbalance
    
    Formula: FL(p_t) = -α_t (1 - p_t)^γ log(p_t)
    
    The focal loss down-weights easy examples and focuses on hard negatives.
    Essential for fraud detection where fraud rate ~ 0.1%
    
    Args:
        alpha: Weighting factor for positive class
        gamma: Focusing parameter (higher = more focus on hard examples)
        reduction: 'mean', 'sum', or 'none'
    
    Reference:
        Lin et al. "Focal Loss for Dense Object Detection" (ICCV 2017)
    """
    
    def __init__(
        self,
        alpha: float = 0.25,
        gamma: float = 2.0,
        reduction: str = 'mean',
    ):
        super().__init__()
        self.alpha = alpha
        self.gamma = gamma
        self.reduction = reduction
    
    def forward(
        self,
        inputs: torch.Tensor,
        targets: torch.Tensor,
    ) -> torch.Tensor:
        """
        Args:
            inputs: Predictions (logits or probabilities) [batch_size]
            targets: Ground truth labels (0 or 1) [batch_size]
        
        Returns:
            Focal loss value
        """
        # Ensure inputs are probabilities
        # Ensure inputs are probabilities and clamped for numerical stability
        if inputs.min() < 0 or inputs.max() > 1:
            p = torch.sigmoid(inputs)
        else:
            p = inputs
        
        eps = 1e-7
        p = torch.clamp(p, min=eps, max=1.0 - eps)

        # Compute focal loss
        targets = targets.view_as(p).float()
        ce_loss = F.binary_cross_entropy(p, targets, reduction='none')
        p_t = p * targets + (1 - p) * (1 - targets)
        p_t = torch.clamp(p_t, min=eps, max=1.0 - eps)
        focal_weight = (1 - p_t) ** self.gamma
        
        if self.alpha >= 0:
            alpha_t = self.alpha * targets + (1 - self.alpha) * (1 - targets)
            focal_weight = alpha_t * focal_weight
        
        loss = focal_weight * ce_loss
        
        if self.reduction == 'mean':
            return loss.mean()
        elif self.reduction == 'sum':
            return loss.sum()
        else:
            return loss



class WeightedBCELoss(nn.Module):
    """
    Weighted Binary Cross-Entropy Loss
    
    Applies class weights to handle imbalance
    
    Args:
        pos_weight: Weight for positive class (fraud)
        reduction: 'mean', 'sum', or 'none'
    """
    
    def __init__(
        self,
        pos_weight: float = 10.0,
        reduction: str = 'mean',
    ):
        super().__init__()
        self.pos_weight = pos_weight
        self.reduction = reduction
    
    def forward(
        self,
        inputs: torch.Tensor,
        targets: torch.Tensor,
    ) -> torch.Tensor:
        """
        Args:
            inputs: Predictions [batch_size]
            targets: Ground truth labels [batch_size]
        
        Returns:
            Weighted BCE loss
        """
        targets = targets.view_as(inputs).float()
        return F.binary_cross_entropy_with_logits(
            inputs,
            targets,
            pos_weight=torch.tensor(self.pos_weight, device=inputs.device),
            reduction=self.reduction,
        )


class CombinedLoss(nn.Module):
    """
    Combined loss function for multi-task learning
    
    Combines multiple objectives:
    - Classification loss (focal or BCE)
    - Regularization terms
    
    Args:
        classification_loss: 'focal' or 'bce'
        focal_alpha: Focal loss alpha
        focal_gamma: Focal loss gamma
        weight_decay: L2 regularization weight
    """
    
    def __init__(
        self,
        classification_loss: str = 'focal',
        focal_alpha: float = 0.25,
        focal_gamma: float = 2.0,
        weight_decay: float = 0.0001,
    ):
        super().__init__()
        
        if classification_loss == 'focal':
            self.cls_loss = FocalLoss(alpha=focal_alpha, gamma=focal_gamma)
        elif classification_loss == 'bce':
            self.cls_loss = WeightedBCELoss()
        else:
            raise ValueError(f"Unknown classification loss: {classification_loss}")
        
        self.weight_decay = weight_decay
    
    def forward(
        self,
        inputs: torch.Tensor,
        targets: torch.Tensor,
        model: Optional[nn.Module] = None,
    ) -> dict:
        """
        Compute combined loss
        
        Args:
            inputs: Model predictions
            targets: Ground truth labels
            model: Model (for regularization)
        
        Returns:
            Dictionary with total loss and components
        """
        # Classification loss
        cls_loss = self.cls_loss(inputs, targets)
        
        # Regularization
        reg_loss = 0.0
        if model is not None and self.weight_decay > 0:
            for param in model.parameters():
                if param.requires_grad:
                    reg_loss += torch.norm(param, p=2) ** 2
            reg_loss = self.weight_decay * reg_loss
        
        # Total loss
        total_loss = cls_loss + reg_loss
        
        return {
            'total': total_loss,
            'classification': cls_loss,
            'regularization': reg_loss,
        }


class ContrastiveLoss(nn.Module):
    """
    Contrastive loss for graph representation learning
    
    Encourages similar graphs to have similar embeddings
    and dissimilar graphs to have dissimilar embeddings
    
    Args:
        temperature: Temperature parameter for scaling
        margin: Margin for negative pairs
    """
    
    def __init__(
        self,
        temperature: float = 0.5,
        margin: float = 1.0,
    ):
        super().__init__()
        self.temperature = temperature
        self.margin = margin
    
    def forward(
        self,
        embeddings: torch.Tensor,
        labels: torch.Tensor,
    ) -> torch.Tensor:
        """
        Args:
            embeddings: Graph embeddings [batch_size, embedding_dim]
            labels: Labels (0 or 1) [batch_size]
        
        Returns:
            Contrastive loss
        """
        # Normalize embeddings
        embeddings = F.normalize(embeddings, p=2, dim=1)
        
        # Compute pairwise similarities
        similarity_matrix = torch.matmul(embeddings, embeddings.T) / self.temperature
        
        # Create label matrix
        labels = labels.unsqueeze(1)
        label_matrix = (labels == labels.T).float()
        
        # Mask out diagonal
        batch_size = embeddings.size(0)
        mask = torch.eye(batch_size, device=embeddings.device).bool()
        label_matrix = label_matrix.masked_fill(mask, 0)
        
        eps = 1e-7

        # Positive pairs (same label)
        pos_mask = label_matrix == 1
        if pos_mask.any():
            pos_similarity = similarity_matrix.masked_select(pos_mask)
            pos_sig = torch.clamp(torch.sigmoid(pos_similarity), min=eps, max=1.0 - eps)
            pos_loss = -torch.log(pos_sig).mean()
        else:
            pos_loss = torch.tensor(0.0, device=embeddings.device)
        
        # Negative pairs (different label)
        neg_mask = label_matrix == 0
        neg_mask = neg_mask.masked_fill(mask, False)
        if neg_mask.any():
            neg_similarity = similarity_matrix.masked_select(neg_mask)
            neg_sig = torch.clamp(torch.sigmoid(self.margin - neg_similarity), min=eps, max=1.0 - eps)
            neg_loss = -torch.log(neg_sig).mean()
        else:
            neg_loss = torch.tensor(0.0, device=embeddings.device)
        
        return pos_loss + neg_loss


class RankingLoss(nn.Module):
    """
    Ranking loss for fraud detection
    
    Ensures fraudulent transactions are ranked higher in risk
    than legitimate transactions
    
    Args:
        margin: Margin between fraud and legitimate scores
    """
    
    def __init__(self, margin: float = 0.5):
        super().__init__()
        self.margin = margin
    
    def forward(
        self,
        fraud_scores: torch.Tensor,
        legit_scores: torch.Tensor,
    ) -> torch.Tensor:
        """
        Args:
            fraud_scores: Risk scores for fraudulent transactions
            legit_scores: Risk scores for legitimate transactions
        
        Returns:
            Ranking loss
        """
        # Compute pairwise differences
        diff = legit_scores.unsqueeze(1) - fraud_scores.unsqueeze(0)
        
        # Hinge loss: max(0, margin + legit_score - fraud_score)
        loss = F.relu(self.margin + diff)
        
        return loss.mean()


class MultiModalTemporalLoss(nn.Module):
    """
    Multi-Modal Temporal Loss with Dynamic Homoscedastic Uncertainty Weighting.
    
    Combines:
    1. Focal Classification Loss (Fraud detection classification)
    2. Temporal Graph Contrastive Loss (Graph embedding similarity)
    3. Behavioral Biometric Stress Loss (Keystroke & voice stress alignment)

    Uses homoscedastic task uncertainty parameters (s_cls, s_contrastive, s_biometric)
    to dynamically balance multi-task loss terms without gradient explosion or NaN divergence.
    """
    
    def __init__(
        self,
        focal_alpha: float = 0.25,
        focal_gamma: float = 2.0,
        contrastive_temp: float = 0.5,
        gradient_clip_val: float = 5.0,
    ):
        super().__init__()
        self.focal_loss = FocalLoss(alpha=focal_alpha, gamma=focal_gamma)
        self.contrastive_loss = ContrastiveLoss(temperature=contrastive_temp)
        self.gradient_clip_val = gradient_clip_val
        
        # Trainable Homoscedastic Uncertainty parameters (log variance)
        self.log_var_cls = nn.Parameter(torch.tensor(0.0))
        self.log_var_contrastive = nn.Parameter(torch.tensor(0.0))
        self.log_var_biometric = nn.Parameter(torch.tensor(0.0))

    def forward(
        self,
        cls_logits: torch.Tensor,
        targets: torch.Tensor,
        embeddings: Optional[torch.Tensor] = None,
        biometric_scores: Optional[torch.Tensor] = None,
    ) -> dict:
        """
        Args:
            cls_logits: Primary model prediction logits [batch_size]
            targets: Ground truth fraud labels (0 or 1) [batch_size]
            embeddings: Optional graph node embeddings [batch_size, dim]
            biometric_scores: Optional behavioral biometric stress scores [batch_size]

        Returns:
            Dictionary containing total weighted loss and individual metrics components
        """
        # 1. Primary Classification Focal Loss
        l_cls = self.focal_loss(cls_logits, targets)
        w_cls = torch.exp(-self.log_var_cls) * l_cls + 0.5 * self.log_var_cls

        # 2. Graph Contrastive Loss
        if embeddings is not None and embeddings.size(0) > 1:
            l_cont = self.contrastive_loss(embeddings, targets)
        else:
            l_cont = torch.tensor(0.0, device=cls_logits.device)
        w_cont = torch.exp(-self.log_var_contrastive) * l_cont + 0.5 * self.log_var_contrastive

        # 3. Behavioral Biometrics Alignment Loss
        if biometric_scores is not None:
            eps = 1e-7
            b_p = torch.clamp(torch.sigmoid(biometric_scores), min=eps, max=1.0 - eps)
            targets_fl = targets.view_as(b_p).float()
            l_bio = F.binary_cross_entropy(b_p, targets_fl)
        else:
            l_bio = torch.tensor(0.0, device=cls_logits.device)
        w_bio = torch.exp(-self.log_var_biometric) * l_bio + 0.5 * self.log_var_biometric

        # Total Weighted Multi-Task Loss
        total_loss = w_cls + w_cont + w_bio

        # Adaptive Gradient Clipping Guardrail check
        if torch.isnan(total_loss) or torch.isinf(total_loss):
            total_loss = torch.clamp(total_loss, min=0.0, max=100.0)

        return {
            'loss': total_loss,
            'focal_cls_loss': l_cls.item(),
            'contrastive_loss': l_cont.item(),
            'biometric_loss': l_bio.item(),
            'weight_cls': float(torch.exp(-self.log_var_cls).item()),
            'weight_contrastive': float(torch.exp(-self.log_var_contrastive).item()),
            'weight_biometric': float(torch.exp(-self.log_var_biometric).item()),
        }

