"""Unit tests for the real AegisHTGNN model (issue #3580).

The training pipeline previously fell back to a mock module that returned
random noise with no gradient flow into parameters, so the persisted
artifact was never actually trained. These tests pin the contract that the
real model consumes the heterogeneous batch, produces one logit per
account, and learns (parameters change after an optimizer step).
"""
from __future__ import annotations
import os

import pytest

if os.getenv("RUN_TORCH_TESTS", "").lower() != "true":
    pytest.skip("PyTorch tests require RUN_TORCH_TESTS=true", allow_module_level=True)

try:
    import torch
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False

pytestmark = pytest.mark.skipif(not TORCH_AVAILABLE, reason="PyTorch not installed")


def _make_batch(num_accounts=6, num_devices=4):
    x_dict = {
        "account": torch.randn(num_accounts, 16),
        "device": torch.randn(num_devices, 8),
    }
    edge_index_dict = {
        ("account", "transacts", "account"): torch.tensor(
            [
                [0, 1, 2, 3, 4],
                [1, 2, 3, 4, 5],
            ]
        ),
        ("device", "logs_into", "account"): torch.tensor(
            [
                [0, 1, 2, 3],
                [0, 1, 2, 3],
            ]
        ),
    }
    return x_dict, edge_index_dict


class TestAegisHTGNN:
    def test_forward_output_shape(self):
        from src.models.htgnn import AegisHTGNN

        model = AegisHTGNN()
        x_dict, edge_index_dict = _make_batch()
        out = model(x_dict, edge_index_dict)

        assert out.shape == (6, 1)

    def test_forward_is_deterministic_given_weights(self):
        from src.models.htgnn import AegisHTGNN

        torch.manual_seed(0)
        model = AegisHTGNN()
        model.eval()
        x_dict, edge_index_dict = _make_batch()
        first = model(x_dict, edge_index_dict)
        second = model(x_dict, edge_index_dict)

        assert torch.equal(first, second)

    def test_output_depends_on_node_features(self):
        from src.models.htgnn import AegisHTGNN

        torch.manual_seed(0)
        model = AegisHTGNN()
        x_dict, edge_index_dict = _make_batch()

        base = model(x_dict, edge_index_dict)
        perturbed = dict(x_dict)
        perturbed["account"] = x_dict["account"] + 1.0
        shifted = model(perturbed, edge_index_dict)

        assert not torch.allclose(base, shifted, atol=1e-6)

    def test_gradients_flow_into_real_parameters(self):
        from src.models.htgnn import AegisHTGNN

        model = AegisHTGNN()
        x_dict, edge_index_dict = _make_batch()
        labels = torch.randint(0, 2, (6, 1), dtype=torch.float32)

        optimizer = torch.optim.AdamW(model.parameters(), lr=0.01)
        before = [p.detach().clone() for p in model.parameters()]

        optimizer.zero_grad()
        out = model(x_dict, edge_index_dict)
        loss = torch.nn.functional.binary_cross_entropy_with_logits(
            out, labels
        )
        loss.backward()

        assert any(p.grad is not None for p in model.parameters())

        optimizer.step()

        changed = [
            not torch.equal(b, a)
            for b, a in zip(before, (p.detach() for p in model.parameters()))
        ]
        assert any(changed), "optimizer did not update any parameter"

    def test_missing_account_node_type_raises(self):
        from src.models.htgnn import AegisHTGNN

        model = AegisHTGNN()
        x_dict, edge_index_dict = _make_batch()
        x_dict = {"device": x_dict["device"]}

        with pytest.raises(ValueError, match="account"):
            model(x_dict, edge_index_dict)

    def test_empty_edge_batches_do_not_crash(self):
        from src.models.htgnn import AegisHTGNN

        model = AegisHTGNN()
        x_dict, edge_index_dict = _make_batch()
        edge_index_dict = {
            ("account", "transacts", "account"): torch.zeros(
                (2, 0), dtype=torch.long
            ),
            ("device", "logs_into", "account"): torch.zeros(
                (2, 0), dtype=torch.long
            ),
        }
        out = model(x_dict, edge_index_dict)
        assert out.shape == (6, 1)


class TestRealModelIsUsedByTrainingPipeline:
    def test_train_module_imports_real_model(self):
        from src.training import train

        from src.models.htgnn import AegisHTGNN

        assert train.AegisHTGNN is AegisHTGNN

    def test_model_state_dict_contains_encoder_and_head_weights(self):
        from src.models.htgnn import AegisHTGNN

        state = AegisHTGNN().state_dict()

        assert "node_encoders.account.weight" in state
        assert "node_encoders.device.weight" in state
        assert "head.weight" in state
        assert "hgt.convs.0.k_linears.0.weight" in state
