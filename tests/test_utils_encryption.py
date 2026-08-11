import os
import base64
import pytest
import torch
from cryptography.exceptions import InvalidTag

from src.utils.encryption import ModelEncryption, get_encryption_handler


class TestModelEncryptionValidateKey:
    def test_validate_key_accepts_32_bytes(self):
        key = os.urandom(32)
        ModelEncryption._validate_key(key)

    def test_validate_key_rejects_31_bytes(self):
        key = os.urandom(31)
        with pytest.raises(ValueError, match="must be 32 bytes, got 31 bytes"):
            ModelEncryption._validate_key(key)

    def test_validate_key_rejects_33_bytes(self):
        key = os.urandom(33)
        with pytest.raises(ValueError, match="must be 32 bytes, got 33 bytes"):
            ModelEncryption._validate_key(key)

    def test_validate_key_rejects_empty(self):
        key = b""
        with pytest.raises(ValueError, match="must be 32 bytes, got 0 bytes"):
            ModelEncryption._validate_key(key)


class TestModelEncryptionLoadKeyFromEnvironment:
    def test_load_key_from_direct_base64(self, monkeypatch):
        key = os.urandom(32)
        b64_key = base64.b64encode(key).decode()
        monkeypatch.setenv("MODEL_ENCRYPTION_KEY", b64_key)
        monkeypatch.delenv("MODEL_ENCRYPTION_PASSWORD", raising=False)

        loaded = ModelEncryption._load_key_from_environment()
        assert loaded == key

    def test_load_key_from_password_with_salt(self, monkeypatch):
        password = "test-password-123"
        salt = "custom-salt-value"
        monkeypatch.setenv("MODEL_ENCRYPTION_PASSWORD", password)
        monkeypatch.setenv("MODEL_ENCRYPTION_SALT", salt)
        monkeypatch.delenv("MODEL_ENCRYPTION_KEY", raising=False)

        loaded = ModelEncryption._load_key_from_environment()
        assert len(loaded) == 32

        loaded2 = ModelEncryption._load_key_from_environment()
        assert loaded == loaded2

    def test_load_key_from_password_default_salt(self, monkeypatch):
        password = "another-password"
        monkeypatch.setenv("MODEL_ENCRYPTION_PASSWORD", password)
        monkeypatch.delenv("MODEL_ENCRYPTION_KEY", raising=False)
        monkeypatch.delenv("MODEL_ENCRYPTION_SALT", raising=False)

        loaded = ModelEncryption._load_key_from_environment()
        assert len(loaded) == 32

    def test_load_key_raises_when_neither_set(self, monkeypatch):
        monkeypatch.delenv("MODEL_ENCRYPTION_KEY", raising=False)
        monkeypatch.delenv("MODEL_ENCRYPTION_PASSWORD", raising=False)
        monkeypatch.delenv("MODEL_ENCRYPTION_SALT", raising=False)

        with pytest.raises(ValueError, match="No encryption key configured"):
            ModelEncryption._load_key_from_environment()

    def test_load_key_rejects_invalid_base64(self, monkeypatch):
        monkeypatch.setenv("MODEL_ENCRYPTION_KEY", "not-valid-base64!")
        monkeypatch.delenv("MODEL_ENCRYPTION_PASSWORD", raising=False)

        with pytest.raises(ValueError, match="MODEL_ENCRYPTION_KEY is invalid"):
            ModelEncryption._load_key_from_environment()

    def test_load_key_rejects_wrong_size_base64(self, monkeypatch):
        short_key = base64.b64encode(os.urandom(16)).decode()
        monkeypatch.setenv("MODEL_ENCRYPTION_KEY", short_key)
        monkeypatch.delenv("MODEL_ENCRYPTION_PASSWORD", raising=False)

        with pytest.raises(ValueError, match="must be 32 bytes, got 16 bytes"):
            ModelEncryption._load_key_from_environment()


class TestModelEncryptionRoundTrip:
    @pytest.fixture
    def encryption(self):
        key = os.urandom(32)
        return ModelEncryption(key)

    def test_encrypt_decrypt_roundtrip(self, encryption):
        checkpoint = {
            "model_state_dict": {
                "layer1.weight": torch.randn(10, 5),
                "layer1.bias": torch.randn(10),
                "layer2.weight": torch.randn(1, 10),
                "layer2.bias": torch.randn(1),
            },
            "optimizer_state_dict": {"param_groups": []},
            "epoch": 42,
            "loss": 0.0234,
        }

        encrypted = encryption.encrypt_checkpoint(checkpoint)
        decrypted = encryption.decrypt_checkpoint(encrypted)

        assert decrypted["epoch"] == checkpoint["epoch"]
        assert decrypted["loss"] == checkpoint["loss"]
        for k in checkpoint["model_state_dict"]:
            assert torch.allclose(decrypted["model_state_dict"][k], checkpoint["model_state_dict"][k])

    def test_encrypt_decrypt_empty_checkpoint(self, encryption):
        checkpoint = {}
        encrypted = encryption.encrypt_checkpoint(checkpoint)
        decrypted = encryption.decrypt_checkpoint(encrypted)
        assert decrypted == {}

    def test_encrypt_decrypt_large_checkpoint(self, encryption):
        large_tensor = torch.randn(1000, 1000)
        checkpoint = {"weights": large_tensor, "metadata": {"size": large_tensor.numel()}}

        encrypted = encryption.encrypt_checkpoint(checkpoint)
        decrypted = encryption.decrypt_checkpoint(encrypted)

        assert torch.allclose(decrypted["weights"], large_tensor)
        assert decrypted["metadata"]["size"] == large_tensor.numel()

    def test_encrypted_format_contains_nonce_ciphertext_tag(self, encryption):
        checkpoint = {"test": torch.tensor([1.0, 2.0, 3.0])}
        encrypted = encryption.encrypt_checkpoint(checkpoint)

        assert len(encrypted) >= encryption.NONCE_SIZE + encryption.TAG_SIZE
        nonce = encrypted[:encryption.NONCE_SIZE]
        assert len(nonce) == encryption.NONCE_SIZE

    def test_decrypt_with_wrong_key_fails(self, encryption):
        checkpoint = {"weights": torch.randn(10, 10)}
        encrypted = encryption.encrypt_checkpoint(checkpoint)

        wrong_key = os.urandom(32)
        other_encryption = ModelEncryption(wrong_key)

        with pytest.raises(InvalidTag):
            other_encryption.decrypt_checkpoint(encrypted)

    def test_tampered_ciphertext_raises_invalid_tag(self, encryption):
        checkpoint = {"weights": torch.randn(5, 5)}
        encrypted = encryption.encrypt_checkpoint(checkpoint)

        tampered = bytearray(encrypted)
        tampered[encryption.NONCE_SIZE] ^= 0xFF

        with pytest.raises(InvalidTag):
            encryption.decrypt_checkpoint(bytes(tampered))

    def test_decrypt_uses_weights_only_true(self, encryption, monkeypatch):
        checkpoint = {"model_state_dict": {"w": torch.randn(3, 3)}}
        encrypted = encryption.encrypt_checkpoint(checkpoint)

        original_load = torch.load

        def mock_load(*args, **kwargs):
            assert kwargs.get("weights_only") is True
            return original_load(*args, **kwargs)

        monkeypatch.setattr(torch, "load", mock_load)
        encryption.decrypt_checkpoint(encrypted)


class TestModelEncryptionInitialization:
    def test_init_with_explicit_key(self):
        key = os.urandom(32)
        enc = ModelEncryption(key)
        assert enc.key == key

    def test_init_without_key_loads_from_env(self, monkeypatch):
        key = os.urandom(32)
        b64_key = base64.b64encode(key).decode()
        monkeypatch.setenv("MODEL_ENCRYPTION_KEY", b64_key)
        monkeypatch.delenv("MODEL_ENCRYPTION_PASSWORD", raising=False)

        enc = ModelEncryption()
        assert enc.key == key

    def test_init_rejects_invalid_key_size(self):
        with pytest.raises(ValueError, match="must be 32 bytes"):
            ModelEncryption(os.urandom(16))


class TestGetEncryptionHandler:
    def test_returns_configured_instance(self, monkeypatch):
        key = os.urandom(32)
        b64_key = base64.b64encode(key).decode()
        monkeypatch.setenv("MODEL_ENCRYPTION_KEY", b64_key)
        monkeypatch.delenv("MODEL_ENCRYPTION_PASSWORD", raising=False)

        handler = get_encryption_handler()
        assert isinstance(handler, ModelEncryption)
        assert handler.key == key

    def test_returns_new_instance_each_call(self, monkeypatch):
        key = os.urandom(32)
        b64_key = base64.b64encode(key).decode()
        monkeypatch.setenv("MODEL_ENCRYPTION_KEY", b64_key)
        monkeypatch.delenv("MODEL_ENCRYPTION_PASSWORD", raising=False)

        h1 = get_encryption_handler()
        h2 = get_encryption_handler()
        assert h1 is not h2
        assert h1.key == h2.key


class TestEdgeCases:
    def test_encrypt_with_nested_dicts(self):
        key = os.urandom(32)
        enc = ModelEncryption(key)

        checkpoint = {
            "model": {"layer": {"weight": torch.randn(4, 4)}},
            "config": {"lr": 0.001, "batch_size": 32},
            "metrics": {"train_loss": [0.5, 0.3, 0.2], "val_acc": 0.95},
        }

        encrypted = enc.encrypt_checkpoint(checkpoint)
        decrypted = enc.decrypt_checkpoint(encrypted)

        assert decrypted["config"]["lr"] == checkpoint["config"]["lr"]
        assert decrypted["config"]["batch_size"] == checkpoint["config"]["batch_size"]
        assert decrypted["metrics"]["val_acc"] == checkpoint["metrics"]["val_acc"]
        assert torch.allclose(decrypted["model"]["layer"]["weight"], checkpoint["model"]["layer"]["weight"])

    def test_encrypt_with_list_tensors(self):
        key = os.urandom(32)
        enc = ModelEncryption(key)

        checkpoint = {
            "gradients": [torch.randn(10), torch.randn(10), torch.randn(10)],
            "params": [torch.nn.Parameter(torch.randn(5, 5)) for _ in range(3)],
        }

        encrypted = enc.encrypt_checkpoint(checkpoint)
        decrypted = enc.decrypt_checkpoint(encrypted)

        for orig, dec in zip(checkpoint["gradients"], decrypted["gradients"]):
            assert torch.allclose(orig, dec)
        for orig, dec in zip(checkpoint["params"], decrypted["params"]):
            assert torch.allclose(orig.data, dec.data)

    def test_different_nonces_produce_different_ciphertext(self):
        key = os.urandom(32)
        enc = ModelEncryption(key)
        checkpoint = {"data": torch.tensor([1.0])}

        e1 = enc.encrypt_checkpoint(checkpoint)
        e2 = enc.encrypt_checkpoint(checkpoint)

        assert e1 != e2
        assert e1[:enc.NONCE_SIZE] != e2[:enc.NONCE_SIZE]

        d1 = enc.decrypt_checkpoint(e1)
        d2 = enc.decrypt_checkpoint(e2)
        assert torch.allclose(d1["data"], d2["data"])