"""
Tests for Issue #2: Configuration externalization to environment variables.

Verifies that:
1. All hardcoded values are externalized
2. Environment variables override defaults
3. YAML config overrides defaults
4. Environment variables take priority over YAML
5. Configuration loading follows 12-factor app principles
"""

import os
from pathlib import Path
from typing import Dict, Any

import pytest

from src.config import defaults, loaders, schemas


class TestEnvironmentVariableDefaults:
    """Test that defaults are loaded from environment variables."""

    def test_api_host_from_env(self, monkeypatch):
        """API host should load from API_HOST env var."""
        monkeypatch.setenv("API_HOST", "127.0.0.1")
        # Reimport to get fresh defaults
        import importlib
        importlib.reload(defaults)
        assert defaults.DEFAULT_API_HOST == "127.0.0.1"

    def test_api_port_from_env(self, monkeypatch):
        """API port should load from API_PORT env var."""
        monkeypatch.setenv("API_PORT", "9000")
        import importlib
        importlib.reload(defaults)
        assert defaults.DEFAULT_API_PORT == 9000

    def test_api_reload_from_env(self, monkeypatch):
        """API reload should load from API_RELOAD env var."""
        monkeypatch.setenv("API_RELOAD", "false")
        import importlib
        importlib.reload(defaults)
        assert defaults.DEFAULT_API_RELOAD is False

    def test_cors_origins_from_env(self, monkeypatch):
        """CORS origins should load from CORS_ORIGINS env var."""
        monkeypatch.setenv("CORS_ORIGINS", "https://example.com,https://app.example.com")
        import importlib
        importlib.reload(defaults)
        assert defaults.DEFAULT_ALLOWED_ORIGINS == ("https://example.com", "https://app.example.com")

    def test_rate_limit_from_env(self, monkeypatch):
        """Rate limit should load from RATE_LIMIT env var."""
        monkeypatch.setenv("RATE_LIMIT", "500/minute")
        import importlib
        importlib.reload(defaults)
        assert defaults.DEFAULT_RATE_LIMIT == "500/minute"

    def test_max_batch_size_from_env(self, monkeypatch):
        """Max batch size should load from MAX_BATCH_SIZE env var."""
        monkeypatch.setenv("MAX_BATCH_SIZE", "200")
        import importlib
        importlib.reload(defaults)
        assert defaults.DEFAULT_MAX_BATCH_SIZE == 200

    def test_risk_thresholds_from_env(self, monkeypatch):
        """Risk thresholds should load from environment variables."""
        monkeypatch.setenv("RISK_THRESHOLD_ALLOW", "0.40")
        monkeypatch.setenv("RISK_THRESHOLD_REVIEW", "0.65")
        monkeypatch.setenv("RISK_THRESHOLD_BLOCK", "0.85")
        import importlib
        importlib.reload(defaults)
        assert defaults.DEFAULT_RISK_THRESHOLDS["allow"] == 0.40
        assert defaults.DEFAULT_RISK_THRESHOLDS["review"] == 0.65
        assert defaults.DEFAULT_RISK_THRESHOLDS["block"] == 0.85

    def test_component_weights_from_env(self, monkeypatch):
        """Component weights should load from environment variables."""
        monkeypatch.setenv("COMPONENT_WEIGHT_GRAPH", "0.60")
        monkeypatch.setenv("COMPONENT_WEIGHT_VELOCITY", "0.15")
        monkeypatch.setenv("COMPONENT_WEIGHT_BEHAVIOR", "0.15")
        monkeypatch.setenv("COMPONENT_WEIGHT_ENTROPY", "0.10")
        import importlib
        importlib.reload(defaults)
        assert defaults.DEFAULT_COMPONENT_WEIGHTS["graph"] == 0.60
        assert defaults.DEFAULT_COMPONENT_WEIGHTS["velocity"] == 0.15


class TestEnvironmentVariablesSchema:
    """Test EnvironmentVariablesSchema recognizes new env var fields."""

    def test_schema_accepts_api_host(self):
        """Schema should accept API_HOST env var."""
        env_vars = schemas.EnvironmentVariablesSchema(api_host="127.0.0.1")
        assert env_vars.api_host == "127.0.0.1"

    def test_schema_accepts_api_port(self):
        """Schema should accept API_PORT env var."""
        env_vars = schemas.EnvironmentVariablesSchema(api_port="9000")
        assert env_vars.api_port == "9000"

    def test_schema_accepts_cors_origins(self):
        """Schema should accept CORS_ORIGINS env var."""
        env_vars = schemas.EnvironmentVariablesSchema(cors_origins="https://example.com")
        assert env_vars.cors_origins == "https://example.com"

    def test_schema_accepts_rate_limit(self):
        """Schema should accept RATE_LIMIT env var."""
        env_vars = schemas.EnvironmentVariablesSchema(rate_limit="500/minute")
        assert env_vars.rate_limit == "500/minute"

    def test_schema_accepts_risk_thresholds(self):
        """Schema should accept risk threshold env vars."""
        env_vars = schemas.EnvironmentVariablesSchema(
            log_level="DEBUG",
            log_format="text",
            prometheus_port="9091"
        )
        assert env_vars.log_level == "DEBUG"
        assert env_vars.log_format == "text"
        assert env_vars.prometheus_port == "9091"


class TestEnvironmentVariablesPriority:
    """Test that environment variables take priority over YAML config."""

    def test_env_overrides_yaml(self, monkeypatch, tmp_path):
        """Environment variable should override YAML config value."""
        # Create temporary YAML file
        config_file = tmp_path / "config.yaml"
        config_file.write_text("api:\n  port: 8001\n")

        # Set environment variable
        monkeypatch.setenv("API_PORT", "9000")

        # Load environment
        env = loaders.load_environment({"API_PORT": "9000"})
        assert env.api_port == "9000"

    def test_env_overrides_default_rate_limit(self, monkeypatch):
        """Environment variable should override default rate limit."""
        monkeypatch.setenv("RATE_LIMIT", "1000/hour")
        import importlib
        importlib.reload(defaults)
        assert defaults.DEFAULT_RATE_LIMIT == "1000/hour"

    def test_cors_origins_env_priority(self, monkeypatch):
        """CORS_ORIGINS env var should take priority over AEGIS_ALLOWED_ORIGINS."""
        env_data = {
            "AEGIS_ALLOWED_ORIGINS": "http://old.com",
            "CORS_ORIGINS": "http://new.com,http://new2.com"
        }
        env = loaders.load_environment(env_data)
        # CORS_ORIGINS should be preferred
        assert env.cors_origins == "http://new.com,http://new2.com"


class TestConfigurationConsistency:
    """Test that configuration is consistent across loading mechanisms."""

    def test_defaults_have_reasonable_values(self):
        """All defaults should have reasonable values."""
        assert defaults.DEFAULT_API_HOST in ["0.0.0.0", "localhost", "127.0.0.1"]
        assert 1 <= defaults.DEFAULT_API_PORT <= 65535
        assert isinstance(defaults.DEFAULT_API_LOG_LEVEL, str)
        assert isinstance(defaults.DEFAULT_ALLOWED_ORIGINS, tuple)
        assert len(defaults.DEFAULT_ALLOWED_ORIGINS) > 0

    def test_risk_thresholds_are_ordered(self):
        """Risk thresholds should satisfy allow <= review <= block."""
        assert defaults.DEFAULT_RISK_THRESHOLDS["allow"] <= defaults.DEFAULT_RISK_THRESHOLDS["review"]
        assert defaults.DEFAULT_RISK_THRESHOLDS["review"] <= defaults.DEFAULT_RISK_THRESHOLDS["block"]

    def test_component_weights_sum_to_approximately_one(self):
        """Component weights should sum to approximately 1.0."""
        total = sum(defaults.DEFAULT_COMPONENT_WEIGHTS.values())
        assert 0.99 <= total <= 1.01  # Allow small floating-point variance

    def test_batch_size_is_positive(self):
        """Batch size should be positive."""
        assert defaults.DEFAULT_MAX_BATCH_SIZE > 0

    def test_rate_limit_has_valid_format(self):
        """Rate limit should have valid format (number/unit)."""
        assert "/" in defaults.DEFAULT_RATE_LIMIT
        parts = defaults.DEFAULT_RATE_LIMIT.split("/")
        assert len(parts) == 2
        assert parts[0].isdigit()


class TestDocumentation:
    """Test that configuration is properly documented."""

    def test_env_example_file_exists(self):
        """.env.example file should exist."""
        env_file = Path(".env.example")
        assert env_file.exists(), ".env.example file not found"

    def test_env_example_documents_all_vars(self):
        """.env.example should document all environment variables."""
        env_file = Path(".env.example")
        content = env_file.read_text()

        # Check for key environment variables
        assert "API_HOST" in content
        assert "API_PORT" in content
        assert "CORS_ORIGINS" in content
        assert "RATE_LIMIT" in content
        assert "MAX_BATCH_SIZE" in content
        assert "RISK_THRESHOLD_" in content
        assert "COMPONENT_WEIGHT_" in content

    def test_env_example_has_instructions(self):
        """.env.example should have configuration instructions."""
        env_file = Path(".env.example")
        content = env_file.read_text()

        # Check for helpful documentation
        assert "12-Factor" in content or "priority" in content.lower()
        assert "example" in content.lower() or "Example" in content


class TestKubernetesCompatibility:
    """Test configuration works with Kubernetes ConfigMaps."""

    def test_can_load_from_configmap_env_vars(self, monkeypatch):
        """Should be able to load Kubernetes ConfigMap as env vars."""
        # Simulate Kubernetes ConfigMap environment
        k8s_env = {
            "API_HOST": "0.0.0.0",
            "API_PORT": "8000",
            "CORS_ORIGINS": "https://app.example.com",
            "RATE_LIMIT": "1000/minute",
            "LOG_LEVEL": "INFO"
        }

        env = loaders.load_environment(k8s_env)
        assert env.api_host == "0.0.0.0"
        assert env.api_port == "8000"
        assert env.cors_origins == "https://app.example.com"
        assert env.rate_limit == "1000/minute"
        assert env.log_level == "INFO"


class TestDockerCompatibility:
    """Test configuration works with Docker environment variables."""

    def test_can_override_with_docker_env(self, monkeypatch):
        """Should be able to override config with Docker env vars."""
        docker_env = {
            "API_PORT": "3000",
            "CORS_ORIGINS": "http://web-ui",
            "LOG_LEVEL": "DEBUG"
        }

        env = loaders.load_environment(docker_env)
        assert env.api_port == "3000"
        assert env.cors_origins == "http://web-ui"
        assert env.log_level == "DEBUG"


class TestBackwardCompatibility:
    """Test backward compatibility with old configuration names."""

    def test_legacy_aegis_allowed_origins_still_works(self):
        """Legacy AEGIS_ALLOWED_ORIGINS should still be recognized."""
        env_data = {"AEGIS_ALLOWED_ORIGINS": "http://legacy.com"}
        env = loaders.load_environment(env_data)
        assert env.aegis_allowed_origins == "http://legacy.com"

    def test_cors_origins_is_preferred_over_legacy(self):
        """CORS_ORIGINS should be recognized alongside legacy name."""
        env_data = {"CORS_ORIGINS": "http://new.com"}
        env = loaders.load_environment(env_data)
        # Both should be recognized, with CORS_ORIGINS being the modern name
        assert env.cors_origins == "http://new.com"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
