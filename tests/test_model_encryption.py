"""Tests for src/utils/encryption.py.

The module was previously unimportable because it referenced a class name that
cryptography does not export, and its dependency was not declared. These tests
exercise the import path and the password derivation branch so both regress
loudly rather than silently.
"""

import base64
import secrets

import pytest

# src/utils/encryption.py imports torch at module level.
pytest.importorskip("torch")

from src.utils.encryption import ModelEncryption


def test_module_exposes_working_key_derivation():
    """PBKDF2HMAC is the name cryptography exports, so the import must resolve."""
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

    import src.utils.encryption as encryption_module

    assert encryption_module.PBKDF2HMAC is PBKDF2HMAC


def test_password_derivation_produces_a_valid_key(monkeypatch):
    monkeypatch.delenv("MODEL_ENCRYPTION_KEY", raising=False)
    monkeypatch.setenv("MODEL_ENCRYPTION_PASSWORD", "correct-horse-battery-staple")

    key = ModelEncryption._load_key_from_environment()

    assert isinstance(key, bytes)
    assert len(key) == ModelEncryption.KEY_SIZE


def test_password_derivation_is_deterministic_for_a_fixed_salt(monkeypatch):
    monkeypatch.delenv("MODEL_ENCRYPTION_KEY", raising=False)
    monkeypatch.setenv("MODEL_ENCRYPTION_PASSWORD", "another-password")
    monkeypatch.setenv("MODEL_ENCRYPTION_SALT", "fixed-salt-value")

    first = ModelEncryption._load_key_from_environment()
    second = ModelEncryption._load_key_from_environment()

    assert first == second


def test_missing_configuration_raises_value_error(monkeypatch):
    monkeypatch.delenv("MODEL_ENCRYPTION_KEY", raising=False)
    monkeypatch.delenv("MODEL_ENCRYPTION_PASSWORD", raising=False)

    with pytest.raises(ValueError, match="No encryption key configured"):
        ModelEncryption._load_key_from_environment()


def test_constructing_with_an_explicit_key_is_accepted():
    key = secrets.token_bytes(ModelEncryption.KEY_SIZE)

    assert ModelEncryption(encryption_key=key) is not None


def test_constructing_with_a_wrong_length_key_is_rejected():
    with pytest.raises(ValueError):
        ModelEncryption(encryption_key=secrets.token_bytes(8))


def test_environment_key_is_accepted_as_base64(monkeypatch):
    key = secrets.token_bytes(ModelEncryption.KEY_SIZE)
    monkeypatch.setenv("MODEL_ENCRYPTION_KEY", base64.b64encode(key).decode())

    assert ModelEncryption._load_key_from_environment() == key
