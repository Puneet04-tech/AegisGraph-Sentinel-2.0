"""Unit tests for risk score calibration (temperature scaling + ECE).

Covers:
    - probs/logits conversion and TemperatureScaler fitting on a model
      with a known miscalibration (sharpened logits), so the recovered
      temperature is predictable
    - temperature scaling preserves score ranking (AUC-safe)
    - positive-class ECE against hand-computed values
    - reliability curve bin statistics
    - Trainer integration: ece metric, calibrate(), and calibration
      state surviving a checkpoint round-trip
"""
from __future__ import annotations
import io
import os
import sys
import types

import pytest

if os.getenv("RUN_TORCH_TESTS", "").lower() != "true":
    pytest.skip("PyTorch tests require RUN_TORCH_TESTS=true", allow_module_level=True)

# src.utils.encryption imports a non-existent `PBKDF2` name from the
# cryptography package (it is `PBKDF2HMAC`), which makes the Trainer
# un-importable. Stub the module so these tests exercise calibration;
# the checkpoint tests monkeypatch get_encryption_handler anyway.
try:
    import src.utils.encryption  # noqa: F401
except ImportError:
    _encryption_stub = types.ModuleType("src.utils.encryption")
    _encryption_stub.get_encryption_handler = lambda: None
    sys.modules["src.utils.encryption"] = _encryption_stub

# Handle optional torch dependency
try:
    import numpy as np
    import torch
    import torch.nn as nn
    from src.training.calibration import (TemperatureScaler,
                                          expected_calibration_error,
                                          probs_to_logits, reliability_curve)
    from src.training.trainer import Trainer
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False

pytestmark = pytest.mark.skipif(not TORCH_AVAILABLE, reason="PyTorch not installed")


SHARPEN = 3.0


if TORCH_AVAILABLE:

    class OverconfidentModel(nn.Module):
        """Model whose true logit is x[:, 0] but which reports it
        sharpened by a factor of SHARPEN — a known miscalibration that
        temperature scaling with T = SHARPEN exactly undoes."""

        def __init__(self):
            super().__init__()
            self.dummy = nn.Parameter(torch.zeros(1))

        def forward(self, x, edge_index=None, node_type=None,
                    edge_type=None, edge_timestamp=None, batch=None):
            risk = torch.sigmoid(x[:, 0] * SHARPEN + self.dummy * 0)
            return {"risk": risk}

    class _FakeEncryption:
        """Pass-through stand-in for the AES checkpoint encryption."""

        def encrypt_checkpoint(self, checkpoint):
            buffer = io.BytesIO()
            torch.save(checkpoint, buffer)
            return buffer.getvalue()

        def decrypt_checkpoint(self, data):
            return torch.load(io.BytesIO(data), weights_only=False)


def _synthetic_data(n=4000, seed=0):
    """Labels drawn from sigmoid(z), so sigmoid(z) is the calibrated
    probability and sigmoid(SHARPEN * z) is overconfident."""
    generator = torch.Generator().manual_seed(seed)
    z = torch.empty(n).uniform_(-2.0, 2.0, generator=generator)
    labels = (torch.rand(n, generator=generator) < torch.sigmoid(z)).float()
    return z, labels


def _make_batches(z, labels, batch_size=500):
    batches = []
    for i in range(0, len(z), batch_size):
        z_chunk = z[i:i + batch_size]
        batches.append({
            "x": z_chunk.unsqueeze(1),
            "edge_index": torch.zeros(2, 0, dtype=torch.long),
            "node_type": torch.zeros(len(z_chunk), dtype=torch.long),
            "edge_type": torch.zeros(0, dtype=torch.long),
            "edge_timestamp": torch.zeros(0),
            "label": labels[i:i + batch_size],
        })
    return batches


def _make_trainer():
    return Trainer(
        model=OverconfidentModel(),
        config={"model": {"device": "cpu"}},
    )


class TestCalibrationPrimitives:
    def test_probs_to_logits_roundtrip(self):
        probs = torch.tensor([0.1, 0.5, 0.9])
        recovered = torch.sigmoid(probs_to_logits(probs))

        assert torch.allclose(recovered, probs, atol=1e-5)

    def test_unfitted_scaler_is_identity(self):
        probs = np.array([0.2, 0.5, 0.8])
        calibrated = TemperatureScaler().transform(probs)

        assert np.allclose(calibrated, probs, atol=1e-5)

    def test_fit_recovers_known_sharpening(self):
        z, labels = _synthetic_data()
        overconfident = torch.sigmoid(z * SHARPEN)

        scaler = TemperatureScaler()
        temperature = scaler.fit(overconfident, labels)

        # True miscalibration factor is SHARPEN = 3.0
        assert 2.0 < temperature < 4.0

    def test_calibration_reduces_ece(self):
        z, labels = _synthetic_data()
        overconfident = torch.sigmoid(z * SHARPEN)

        scaler = TemperatureScaler()
        scaler.fit(overconfident, labels)
        calibrated = scaler.transform(overconfident)

        ece_before = expected_calibration_error(overconfident, labels)
        ece_after = expected_calibration_error(calibrated, labels)

        assert ece_after < ece_before
        assert ece_after < 0.05

    def test_transform_preserves_ranking(self):
        z, labels = _synthetic_data(n=200)
        overconfident = torch.sigmoid(z * SHARPEN)

        scaler = TemperatureScaler()
        scaler.fit(overconfident, labels)
        calibrated = scaler.transform(overconfident)

        assert (np.argsort(calibrated) == np.argsort(overconfident.numpy())).all()

    def test_load_temperature_roundtrip(self):
        scaler = TemperatureScaler()
        scaler.load_temperature(2.5)

        assert scaler.temperature == pytest.approx(2.5, abs=1e-5)

    @pytest.mark.parametrize("bad_temperature", [0.0, -1.0])
    def test_load_temperature_rejects_nonpositive(self, bad_temperature):
        with pytest.raises(ValueError):
            TemperatureScaler().load_temperature(bad_temperature)


class TestExpectedCalibrationError:
    def test_hand_computed_single_bin(self):
        # All predictions in one bin: mean predicted 0.8, observed 0.5
        probs = [0.8, 0.8, 0.8, 0.8]
        labels = [1, 1, 0, 0]

        assert expected_calibration_error(probs, labels) == pytest.approx(0.3)

    def test_perfectly_calibrated_is_zero(self):
        probs = [0.7] * 10
        labels = [1] * 7 + [0] * 3

        assert expected_calibration_error(probs, labels) == pytest.approx(0.0, abs=1e-6)

    def test_empty_input_is_zero(self):
        assert expected_calibration_error([], []) == 0.0

    def test_boundary_probability_counted(self):
        # p == 1.0 must land in the last bin, not fall off the edge
        assert expected_calibration_error([1.0], [0]) == pytest.approx(1.0)


class TestReliabilityCurve:
    def test_bin_statistics(self):
        probs = [0.05, 0.15, 0.15, 0.95]
        labels = [0, 1, 0, 1]
        curve = reliability_curve(probs, labels, n_bins=10)

        assert sum(bin_["count"] for bin_ in curve) == 4
        for bin_ in curve:
            assert bin_["bin_lower"] <= bin_["mean_predicted"] <= bin_["bin_upper"]

        second_bin = next(b for b in curve if b["bin_lower"] == pytest.approx(0.1))
        assert second_bin["count"] == 2
        assert second_bin["observed_frequency"] == pytest.approx(0.5)

    def test_empty_bins_excluded(self):
        curve = reliability_curve([0.05, 0.95], [0, 1], n_bins=10)

        assert len(curve) == 2


class TestTrainerIntegration:
    def test_compute_metrics_includes_ece(self):
        trainer = _make_trainer()
        metrics = trainer._compute_metrics(
            np.array([0.9, 0.8, 0.2, 0.1]),
            np.array([1, 1, 0, 0]),
        )

        assert "ece" in metrics
        assert 0.0 <= metrics["ece"] <= 1.0

    def test_calibrate_fits_and_stores_state(self):
        z, labels = _synthetic_data()
        trainer = _make_trainer()
        report = trainer.calibrate(_make_batches(z, labels))

        assert 2.0 < report["temperature"] < 4.0
        assert report["ece_after"] < report["ece_before"]
        assert report["reliability_before"] and report["reliability_after"]
        assert trainer.temperature_scaler is not None
        assert trainer.calibration_report is report

    def test_checkpoint_roundtrip_persists_calibration(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            "src.training.trainer.get_encryption_handler",
            lambda: _FakeEncryption(),
        )

        z, labels = _synthetic_data()
        trainer = _make_trainer()
        report = trainer.calibrate(_make_batches(z, labels))
        trainer.save_checkpoint(tmp_path / "calibrated.pt")

        restored = _make_trainer()
        restored.load_checkpoint(tmp_path / "calibrated.pt")

        assert restored.calibration_report["temperature"] == pytest.approx(
            report["temperature"]
        )
        assert restored.temperature_scaler.temperature == pytest.approx(
            report["temperature"], abs=1e-4
        )

    def test_checkpoint_without_calibration_loads_cleanly(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.setattr(
            "src.training.trainer.get_encryption_handler",
            lambda: _FakeEncryption(),
        )

        trainer = _make_trainer()
        trainer.save_checkpoint(tmp_path / "plain.pt")

        restored = _make_trainer()
        restored.load_checkpoint(tmp_path / "plain.pt")

        assert restored.calibration_report is None
        assert restored.temperature_scaler is None
