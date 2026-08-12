"""
Unit tests for numerical stability in MultiModalTemporalLoss (Issue #3454).
"""

import torch
import pytest

from src.training.losses import FocalLoss, ContrastiveLoss, MultiModalTemporalLoss


def test_focal_loss_extreme_values():
    focal = FocalLoss(alpha=0.25, gamma=2.0)
    
    # Test logits with extreme values (+- 100)
    logits = torch.tensor([100.0, -100.0, 0.0, 50.0])
    targets = torch.tensor([1.0, 0.0, 1.0, 0.0])

    loss = focal(logits, targets)
    assert not torch.isnan(loss)
    assert not torch.isinf(loss)
    assert loss.item() >= 0.0


def test_contrastive_loss_stability():
    contrastive = ContrastiveLoss(temperature=0.5)
    
    # Identical embeddings (similarity = 1.0)
    embeddings = torch.tensor([[1.0, 0.0], [1.0, 0.0], [0.0, 1.0], [0.0, 1.0]])
    labels = torch.tensor([1, 1, 0, 0])

    loss = contrastive(embeddings, labels)
    assert not torch.isnan(loss)
    assert not torch.isinf(loss)


def test_multimodal_temporal_loss_forward():
    multimodal_loss = MultiModalTemporalLoss()
    
    logits = torch.tensor([2.5, -3.1, 0.5, -1.2])
    targets = torch.tensor([1.0, 0.0, 1.0, 0.0])
    embeddings = torch.randn(4, 16)
    biometric_scores = torch.tensor([0.8, 0.1, 0.7, 0.2])

    output = multimodal_loss(
        cls_logits=logits,
        targets=targets,
        embeddings=embeddings,
        biometric_scores=biometric_scores,
    )

    assert "loss" in output
    assert not torch.isnan(output["loss"])
    assert not torch.isinf(output["loss"])
    assert output["focal_cls_loss"] >= 0.0
    assert output["contrastive_loss"] >= 0.0
