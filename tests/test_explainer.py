import importlib
import os
import sys
import types

import pytest

if os.getenv("RUN_TORCH_TESTS", "").lower() != "true":
    pytest.skip("PyTorch tests require RUN_TORCH_TESTS=true", allow_module_level=True)

import torch


def _load_explainer_module():
    loaded_module = sys.modules.get("src.inference.explainer")
    if loaded_module is not None:
        return loaded_module

    tg_module = types.ModuleType("torch_geometric")
    explain_module = types.ModuleType("torch_geometric.explain")

    class PlaceholderExplainer:
        pass

    class PlaceholderGNNExplainer:
        pass

    explain_module.Explainer = PlaceholderExplainer
    explain_module.GNNExplainer = PlaceholderGNNExplainer
    tg_module.explain = explain_module

    sys.modules["torch_geometric"] = tg_module
    sys.modules["torch_geometric.explain"] = explain_module
    return importlib.import_module("src.inference.explainer")


def test_aegis_model_explainer_defers_gnn_explainer_construction(monkeypatch):
    explainer_mod = _load_explainer_module()

    calls = {"gnn": 0, "explainer": 0}

    class DummyModel:
        def to(self, device):
            return self

        def eval(self):
            return self

    class FakeExplainerInstance:
        def __call__(self, x, edge_index, index=None):
            return type("FakeExplanation", (), {"edge_mask": torch.tensor([0.9, 0.1])})()

    class FakeGNNExplainer:
        def __init__(self, epochs=200):
            calls["gnn"] += 1
            self.epochs = epochs

    def fake_explainer(*args, **kwargs):
        calls["explainer"] += 1
        assert isinstance(kwargs["algorithm"], FakeGNNExplainer)
        return FakeExplainerInstance()

    monkeypatch.setattr(explainer_mod, "GNNExplainer", FakeGNNExplainer)
    monkeypatch.setattr(explainer_mod, "Explainer", fake_explainer)

    model_explainer = explainer_mod.AegisModelExplainer(DummyModel())

    assert calls == {"gnn": 0, "explainer": 0}
    assert model_explainer._explainer is None

    result = model_explainer.extract_critical_topology(
        node_features=torch.ones((2, 3)),
        edge_index=torch.tensor([[0, 1], [1, 0]]),
        target_node_idx=0,
    )

    assert calls == {"gnn": 1, "explainer": 1}
    assert result[0]["source_node"] == 0
    assert result[0]["target_node"] == 1
    assert result[0]["fraud_contribution"] == pytest.approx(0.9)
