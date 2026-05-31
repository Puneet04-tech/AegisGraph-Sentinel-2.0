"""Regression tests for hardware device selection fallback."""

from __future__ import annotations

import pytest

torch = pytest.importorskip("torch")

from src.utils.helpers import get_device


def _force_cpu_only(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(torch.cuda, "is_available", lambda: False)
    if hasattr(torch.backends, "mps"):
        monkeypatch.setattr(torch.backends.mps, "is_available", lambda: False, raising=False)


def test_explicit_cuda_falls_back_to_cpu_when_cuda_unavailable(monkeypatch):
    _force_cpu_only(monkeypatch)

    assert get_device("cuda").type == "cpu"


def test_explicit_mps_falls_back_to_cpu_when_mps_unavailable(monkeypatch):
    _force_cpu_only(monkeypatch)

    assert get_device("mps").type == "cpu"


def test_explicit_cpu_is_preserved(monkeypatch):
    monkeypatch.setattr(torch.cuda, "is_available", lambda: True)

    assert get_device("cpu").type == "cpu"


def test_auto_device_prefers_cuda_when_available(monkeypatch):
    monkeypatch.setattr(torch.cuda, "is_available", lambda: True)

    assert get_device().type == "cuda"


def test_invalid_device_name_is_rejected():
    with pytest.raises(ValueError, match="Unsupported torch device"):
        get_device("quantum")
