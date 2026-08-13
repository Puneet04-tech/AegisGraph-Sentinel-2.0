"""
Unit tests for Adaptive Streaming Keystroke Hesitation Transformer (Issue #3457).
"""

import torch
import pytest

from src.models.keystroke_transformer import KeystrokeTransformer
from src.features.behavioral_biometrics import analyze_keystroke_data


def test_keystroke_transformer_forward_pass():
    model = KeystrokeTransformer(input_dim=2, d_model=32, nhead=2, num_layers=2)
    model.eval()

    # Batch of 2 sequences, each of length 10
    x = torch.randn(2, 10, 2)
    with torch.no_grad():
        out = model(x)

    assert out.shape == (2, 1)
    assert (out >= 0.0).all() and (out <= 1.0).all()


def test_keystroke_transformer_padding_mask():
    model = KeystrokeTransformer(input_dim=2, d_model=32)
    model.eval()

    x = torch.randn(2, 5, 2)
    mask = torch.tensor([[False, False, False, True, True], [False, False, False, False, False]])

    with torch.no_grad():
        out = model(x, src_key_padding_mask=mask)

    assert out.shape == (2, 1)


def test_behavioral_biometrics_integration():
    press_times = [0.0, 0.15, 0.35, 0.55]
    release_times = [0.10, 0.25, 0.45, 0.65]

    res = analyze_keystroke_data(press_times, release_times)
    assert "transformer_stress_score" in res
    assert 0.0 <= res["transformer_stress_score"] <= 1.0
