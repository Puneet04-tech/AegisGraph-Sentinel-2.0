"""Unit tests for the temporal train/validation split in AegisGraphLoader.

The previous split was random (torch.rand < 0.8), which leaks future
accounts into training relative to validation. These tests pin the
temporal contract: every training timestamp precedes every validation
timestamp, ties at the cutoff go to training, and the split is
deterministic.

Real torch is used for tensor operations (via a proxy that fakes only
torch.load); torch_geometric is stubbed like in test_data_loader.py.
"""
from __future__ import annotations
import hashlib
import os
import sys
import types

import pytest

if os.getenv("RUN_TORCH_TESTS", "").lower() != "true":
    pytest.skip("PyTorch tests require RUN_TORCH_TESTS=true", allow_module_level=True)

# Handle optional torch dependency
try:
    import torch
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False

pytestmark = pytest.mark.skipif(not TORCH_AVAILABLE, reason="PyTorch not installed")


class _AccountStorage:
    """Minimal stand-in for a HeteroData node storage."""

    def __init__(self, num_nodes, time=None, train_mask=None):
        self.num_nodes = num_nodes
        if time is not None:
            self.time = time
        if train_mask is not None:
            self.train_mask = train_mask

    def __contains__(self, item):
        return hasattr(self, item)


class _TorchProxy:
    """Real torch for tensor ops; only .load is faked to return the graph."""

    def __init__(self, graph):
        self._graph = graph

    def load(self, file_obj, weights_only=True):
        assert weights_only is True
        return self._graph

    def __getattr__(self, name):
        return getattr(torch, name)


def _stub_torch_geometric(monkeypatch, neighbor_loader=None):
    torch_geometric = types.ModuleType("torch_geometric")
    loader_mod = types.ModuleType("torch_geometric.loader")
    data_mod = types.ModuleType("torch_geometric.data")

    loader_mod.NeighborLoader = neighbor_loader or (lambda *a, **k: None)
    data_mod.HeteroData = dict

    torch_geometric.loader = loader_mod
    torch_geometric.data = data_mod

    monkeypatch.setitem(sys.modules, "torch_geometric", torch_geometric)
    monkeypatch.setitem(sys.modules, "torch_geometric.loader", loader_mod)
    monkeypatch.setitem(sys.modules, "torch_geometric.data", data_mod)


def _make_loader(monkeypatch, tmp_path, account, neighbor_loader=None, **kwargs):
    from src.training import data_loader as dl_module

    _stub_torch_geometric(monkeypatch, neighbor_loader)

    graph_path = tmp_path / "graph.pt"
    graph_path.write_bytes(b"graph-bytes")
    monkeypatch.setenv(
        "AEGIS_GRAPH_SHA256",
        hashlib.sha256(graph_path.read_bytes()).hexdigest(),
    )

    graph = {"account": account}
    monkeypatch.setattr(
        "src.training.data_loader.torch", _TorchProxy(graph)
    )

    return dl_module.AegisGraphLoader(graph_path=str(graph_path), **kwargs)


# Shuffled, distinct timestamps for 10 accounts
SHUFFLED_TIMES = [5, 1, 4, 0, 3, 2, 9, 7, 8, 6]


class TestTemporalSplit:
    def test_every_training_time_precedes_every_validation_time(
        self, monkeypatch, tmp_path
    ):
        account = _AccountStorage(10, time=torch.tensor(SHUFFLED_TIMES))
        loader = _make_loader(monkeypatch, tmp_path, account)

        time = loader.data["account"].time
        train_mask = loader.data["account"].train_mask
        val_mask = loader.data["account"].val_mask

        assert int(time[train_mask].max()) < int(time[val_mask].min())

    def test_default_fraction_puts_earliest_80_percent_in_training(
        self, monkeypatch, tmp_path
    ):
        account = _AccountStorage(10, time=torch.tensor(SHUFFLED_TIMES))
        loader = _make_loader(monkeypatch, tmp_path, account)

        train_mask = loader.data["account"].train_mask
        time = loader.data["account"].time

        assert int(train_mask.sum()) == 8
        # The two most recent accounts (times 8, 9) are held out
        assert sorted(time[~train_mask].tolist()) == [8, 9]

    def test_val_mask_is_exact_complement(self, monkeypatch, tmp_path):
        account = _AccountStorage(10, time=torch.tensor(SHUFFLED_TIMES))
        loader = _make_loader(monkeypatch, tmp_path, account)

        train_mask = loader.data["account"].train_mask
        val_mask = loader.data["account"].val_mask

        assert bool((train_mask ^ val_mask).all())

    def test_custom_train_fraction(self, monkeypatch, tmp_path):
        account = _AccountStorage(10, time=torch.tensor(SHUFFLED_TIMES))
        loader = _make_loader(
            monkeypatch, tmp_path, account, train_fraction=0.5
        )

        assert int(loader.data["account"].train_mask.sum()) == 5

    def test_split_is_deterministic(self, monkeypatch, tmp_path):
        first = _make_loader(
            monkeypatch, tmp_path,
            _AccountStorage(10, time=torch.tensor(SHUFFLED_TIMES)),
        )
        second = _make_loader(
            monkeypatch, tmp_path,
            _AccountStorage(10, time=torch.tensor(SHUFFLED_TIMES)),
        )

        assert torch.equal(
            first.data["account"].train_mask,
            second.data["account"].train_mask,
        )

    def test_ties_at_cutoff_go_to_training(self, monkeypatch, tmp_path):
        # Six accounts share the cutoff timestamp
        times = torch.tensor([0, 1, 2, 2, 2, 2, 2, 2, 8, 9])
        account = _AccountStorage(10, time=times)
        loader = _make_loader(monkeypatch, tmp_path, account)

        time = loader.data["account"].time
        train_mask = loader.data["account"].train_mask
        val_mask = loader.data["account"].val_mask

        # All tied accounts train together; validation stays strictly later
        assert int(train_mask.sum()) == 8
        assert int(time[train_mask].max()) < int(time[val_mask].min())


class TestEdgeCases:
    @pytest.mark.parametrize("bad_fraction", [0.0, 1.0, 1.5, -0.2])
    def test_invalid_train_fraction_rejected(
        self, monkeypatch, tmp_path, bad_fraction
    ):
        account = _AccountStorage(10, time=torch.tensor(SHUFFLED_TIMES))
        with pytest.raises(ValueError, match="train_fraction"):
            _make_loader(
                monkeypatch, tmp_path, account, train_fraction=bad_fraction
            )

    def test_existing_train_mask_respected(self, monkeypatch, tmp_path):
        preset = torch.tensor([True] * 5 + [False] * 5)
        account = _AccountStorage(
            10, time=torch.tensor(SHUFFLED_TIMES), train_mask=preset
        )
        loader = _make_loader(monkeypatch, tmp_path, account)

        assert torch.equal(loader.data["account"].train_mask, preset)
        assert torch.equal(loader.data["account"].val_mask, ~preset)

    def test_all_equal_timestamps_warns_and_keeps_val_empty(
        self, monkeypatch, tmp_path, caplog
    ):
        account = _AccountStorage(4, time=torch.tensor([3, 3, 3, 3]))
        with caplog.at_level("WARNING"):
            loader = _make_loader(monkeypatch, tmp_path, account)

        assert int(loader.data["account"].val_mask.sum()) == 0
        assert "Validation split is empty" in caplog.text


class TestLoaders:
    def test_val_loader_targets_val_mask_without_shuffling(
        self, monkeypatch, tmp_path
    ):
        captured = {}

        class _CapturingNeighborLoader:
            def __init__(self, data, **kwargs):
                captured.update(kwargs)

        account = _AccountStorage(10, time=torch.tensor(SHUFFLED_TIMES))
        loader = _make_loader(
            monkeypatch, tmp_path, account,
            neighbor_loader=_CapturingNeighborLoader,
        )
        loader.get_val_loader()

        node_type, mask = captured["input_nodes"]
        assert node_type == "account"
        assert torch.equal(mask, loader.data["account"].val_mask)
        assert captured["shuffle"] is False

    def test_train_loader_targets_train_mask_with_shuffling(
        self, monkeypatch, tmp_path
    ):
        captured = {}

        class _CapturingNeighborLoader:
            def __init__(self, data, **kwargs):
                captured.update(kwargs)

        account = _AccountStorage(10, time=torch.tensor(SHUFFLED_TIMES))
        loader = _make_loader(
            monkeypatch, tmp_path, account,
            neighbor_loader=_CapturingNeighborLoader,
        )
        loader.get_train_loader()

        node_type, mask = captured["input_nodes"]
        assert node_type == "account"
        assert torch.equal(mask, loader.data["account"].train_mask)
        assert captured["shuffle"] is True
