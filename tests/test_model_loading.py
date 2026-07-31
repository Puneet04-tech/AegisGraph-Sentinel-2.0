import os
import tempfile
import pytest
from src.adaptive_auth.models import load_model_weights


def test_weights_only_false_raises_security_violation():
    with pytest.raises(ValueError, match="Security violation: weights_only must be True"):
        load_model_weights("models/test.pt", weights_only=False)


def test_unauthorized_directory_raises_value_error():
    with tempfile.NamedTemporaryFile(suffix=".pt", delete=False) as tmp:
        tmp.write(b"PK\x03\x04header")
        tmp_path = tmp.name

    try:
        with pytest.raises(ValueError, match="Unauthorized model loading directory"):
            load_model_weights(tmp_path, allowed_dirs=["/custom/models/only"])
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


def test_invalid_magic_bytes_header_raises_value_error():
    models_dir = os.path.join(os.getcwd(), "models")
    os.makedirs(models_dir, exist_ok=True)
    fake_model_path = os.path.join(models_dir, "fake_corrupt.pt")

    try:
        with open(fake_model_path, "wb") as f:
            f.write(b"MALICIOUS_UNPICKLE_PAYLOAD_HERE")

        with pytest.raises(ValueError, match="Unverified or corrupt PyTorch file signature"):
            load_model_weights(fake_model_path)
    finally:
        if os.path.exists(fake_model_path):
            os.remove(fake_model_path)


@pytest.mark.xfail(reason="PyTorch TORCH_LIBRARY namespace conflict in CI with triton", strict=False)
def test_valid_pytorch_header_passes_verification():
    models_dir = os.path.join(os.getcwd(), "models")
    os.makedirs(models_dir, exist_ok=True)
    valid_model_path = os.path.join(models_dir, "valid_test_model.pt")

    try:
        import torch
        torch.save({"state_dict": {}}, valid_model_path)

        result = load_model_weights(valid_model_path)
        assert result is not None
        assert "state_dict" in result
    finally:
        if os.path.exists(valid_model_path):
            os.remove(valid_model_path)
