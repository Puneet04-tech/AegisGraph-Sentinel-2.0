import hashlib
import sys
import types


class _DummyAccountNode:
    def __init__(self, num_nodes: int = 4):
        self.num_nodes = num_nodes
        self.time = None
        self.train_mask = None

    def __contains__(self, item):
        return item in {"time", "train_mask"}


class _DummyHeteroData(dict):
    def __getitem__(self, item):
        return super().__getitem__(item)


def test_loader_uses_safe_torch_deserialization(tmp_path, monkeypatch):
    torch_geometric = types.ModuleType("torch_geometric")
    loader_mod = types.ModuleType("torch_geometric.loader")
    data_mod = types.ModuleType("torch_geometric.data")

    class _NeighborLoader:
        pass

    class _HeteroData(dict):
        pass

    loader_mod.NeighborLoader = _NeighborLoader
    data_mod.HeteroData = _HeteroData
    torch_geometric.loader = loader_mod
    torch_geometric.data = data_mod

    monkeypatch.setitem(sys.modules, "torch_geometric", torch_geometric)
    monkeypatch.setitem(sys.modules, "torch_geometric.loader", loader_mod)
    monkeypatch.setitem(sys.modules, "torch_geometric.data", data_mod)

    from src.training.data_loader import AegisGraphLoader

    graph_path = tmp_path / "graph.pt"
    graph_path.write_bytes(b"safe-graph-bytes")

    monkeypatch.setenv(
        "AEGIS_GRAPH_SHA256",
        hashlib.sha256(graph_path.read_bytes()).hexdigest(),
    )

    captured = {}

    def fake_torch_load(file_obj, weights_only):
        captured["weights_only"] = weights_only
        return _DummyHeteroData({"account": _DummyAccountNode()})

    monkeypatch.setattr("src.training.data_loader.torch.load", fake_torch_load)

    loader = AegisGraphLoader(graph_path=str(graph_path), batch_size=16)

    assert captured["weights_only"] is True
    assert loader.data["account"].num_nodes == 4
