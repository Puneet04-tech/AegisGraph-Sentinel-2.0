"""
Tests for SECRET_KEY configuration behavior.

Verifies that:
1. Production environments require explicit SECRET_KEY
2. Non-production environments use generated key without warning (current behavior)
3. Explicit SECRET_KEY is used when provided
"""

import os
import sys
from pathlib import Path
import importlib.util
import logging

import pytest
from pydantic import ValidationError

# Import config.py directly (the file, not the package)
config_path = Path(__file__).parent.parent / "src" / "config.py"
spec = importlib.util.spec_from_file_location("config_module", config_path)
config_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(config_module)

AppSettings = config_module.AppSettings
generate_secure_key = config_module.generate_secure_key


class TestSecretKeyProductionValidation:
    """Test that production enforces explicit SECRET_KEY."""

    def test_production_requires_explicit_secret_key(self, monkeypatch):
        """ENV=prod without SECRET_KEY should raise ValueError."""
        monkeypatch.setenv("ENV", "prod")
        monkeypatch.delenv("SECRET_KEY", raising=False)

        with pytest.raises(ValueError, match="SECRET_KEY must be explicitly set"):
            AppSettings()

    def test_production_accepts_explicit_secret_key(self, monkeypatch):
        """ENV=prod with explicit SECRET_KEY should succeed."""
        monkeypatch.setenv("ENV", "prod")
        monkeypatch.setenv("SECRET_KEY", "explicit-production-key-32-chars-long")

        settings = AppSettings()
        assert settings.SECRET_KEY.get_secret_value() == "explicit-production-key-32-chars-long"

    def test_production_rejects_short_secret_key(self, monkeypatch):
        """ENV=prod with short SECRET_KEY should raise ValueError."""
        monkeypatch.setenv("ENV", "prod")
        monkeypatch.setenv("SECRET_KEY", "short")

        with pytest.raises(ValueError, match="at least 32 characters"):
            AppSettings()


class TestSecretKeyDevelopmentBehavior:
    """Test that development uses generated key with warning (new behavior)."""

    def test_dev_without_secret_key_uses_generated_and_warns(self, monkeypatch, caplog):
        """ENV=dev without SECRET_KEY should use generated key and emit warning."""
        monkeypatch.setenv("ENV", "dev")
        monkeypatch.delenv("SECRET_KEY", raising=False)

        with caplog.at_level(logging.WARNING):
            settings = AppSettings()
        
        secret = settings.SECRET_KEY.get_secret_value()
        
        # Should be a 64-character hex string (32 bytes)
        assert len(secret) == 64
        assert all(c in "0123456789abcdef" for c in secret)
        
        # Should have logged a warning about generated key
        assert any(
            "auto-generated development key" in record.message
            for record in caplog.records
        )
        assert settings.is_generated_secret_key() is True

    def test_dev_with_explicit_secret_key_no_warning(self, monkeypatch, caplog):
        """ENV=dev with explicit SECRET_KEY should use provided key without warning."""
        monkeypatch.setenv("ENV", "dev")
        monkeypatch.setenv("SECRET_KEY", "my-dev-secret-key")

        with caplog.at_level(logging.WARNING):
            settings = AppSettings()
        
        assert settings.SECRET_KEY.get_secret_value() == "my-dev-secret-key"
        
        # Should NOT have logged a warning
        assert not any(
            "auto-generated development key" in record.message
            for record in caplog.records
        )
        assert settings.is_generated_secret_key() is False


class TestSecretKeyTestBehavior:
    """Test that test environment uses generated key with warning (new behavior)."""

    def test_test_without_secret_key_uses_generated_and_warns(self, monkeypatch, caplog):
        """ENV=test without SECRET_KEY should use generated key and emit warning."""
        monkeypatch.setenv("ENV", "test")
        monkeypatch.delenv("SECRET_KEY", raising=False)

        with caplog.at_level(logging.WARNING):
            settings = AppSettings()
        
        secret = settings.SECRET_KEY.get_secret_value()
        
        # Should be a 64-character hex string (32 bytes)
        assert len(secret) == 64
        assert all(c in "0123456789abcdef" for c in secret)
        
        # Should have logged a warning about generated key
        assert any(
            "auto-generated development key" in record.message
            for record in caplog.records
        )
        assert settings.is_generated_secret_key() is True

    def test_test_with_explicit_secret_key_no_warning(self, monkeypatch, caplog):
        """ENV=test with explicit SECRET_KEY should use provided key without warning."""
        monkeypatch.setenv("ENV", "test")
        monkeypatch.setenv("SECRET_KEY", "my-test-secret-key")

        with caplog.at_level(logging.WARNING):
            settings = AppSettings()
        
        assert settings.SECRET_KEY.get_secret_value() == "my-test-secret-key"
        
        # Should NOT have logged a warning
        assert not any(
            "auto-generated development key" in record.message
            for record in caplog.records
        )
        assert settings.is_generated_secret_key() is False


class TestGenerateSecureKey:
    """Test the generate_secure_key function."""

    def test_generate_secure_key_length(self):
        """Generated key should be 64 hex characters (32 bytes)."""
        key = generate_secure_key()
        assert len(key) == 64

    def test_generate_secure_key_is_hex(self):
        """Generated key should be valid hex."""
        key = generate_secure_key()
        assert all(c in "0123456789abcdef" for c in key)

    def test_generate_secure_key_is_unique(self):
        """Each call should generate a unique key."""
        key1 = generate_secure_key()
        key2 = generate_secure_key()
        assert key1 != key2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
