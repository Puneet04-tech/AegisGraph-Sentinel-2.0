from pathlib import Path

import pytest

from src.config.loaders import load_settings
from src.config.settings import RuntimeSettings
from src.config.validators import validate_runtime_settings


def test_load_settings_uses_defaults_when_optional_yaml_missing(tmp_path):
    settings = load_settings(
        config_path=tmp_path / "missing-config.yaml",
        thresholds_path=tmp_path / "missing-thresholds.yaml",
        environ={"AEGIS_ENV": "test"},
    )

    assert isinstance(settings, RuntimeSettings)
    assert settings.runtime.environment == "test"
    assert settings.api.port == 8000
    assert settings.api.allowed_origins == [
        "http://localhost:3000",
        "http://localhost:8501",
        "http://127.0.0.1:8501",
    ]
    assert settings.scoring.thresholds.block == 0.90


def test_environment_overrides_yaml_values(tmp_path):
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        """
api:
  port: 7000
  allowed_origins:
    - http://yaml.example
graph:
  path: data/from-yaml.graphml
""",
        encoding="utf-8",
    )

    settings = load_settings(
        config_path=config_path,
        thresholds_path=tmp_path / "missing-thresholds.yaml",
        environ={
            "AEGIS_ENV": "test",
            "AEGIS_ALLOWED_ORIGINS": "http://env.example,http://second.example",
            "AEGIS_GRAPH_PATH": "data/from-env.graphml",
            "DEBUG": "true",
        },
    )

    assert settings.api.port == 7000
    assert settings.api.allowed_origins == ["http://env.example", "http://second.example"]
    assert settings.graph.graph_path == Path("data/from-env.graphml")
    assert settings.runtime.debug is True


@pytest.mark.parametrize(
    "environ",
    [
        {"AEGIS_ENV": "test", "AEGIS_ALLOWED_ORIGINS": "*"},
        {"AEGIS_ENV": "test", "AEGIS_ALLOWED_ORIGINS": "https://app.example,*"},
        {"AEGIS_ENV": "test", "AEGIS_ALLOWED_ORIGINS": " * "},
    ],
)
def test_wildcard_cors_origins_are_rejected_from_environment(tmp_path, environ):
    with pytest.raises(ValueError, match="wildcard origins cannot be used"):
        load_settings(
            config_path=tmp_path / "missing-config.yaml",
            thresholds_path=tmp_path / "missing-thresholds.yaml",
            environ=environ,
        )


def test_wildcard_cors_origins_are_rejected_from_yaml(tmp_path):
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        """
api:
  allowed_origins:
    - https://app.example.test
    - "*"
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="wildcard origins cannot be used"):
        load_settings(
            config_path=config_path,
            thresholds_path=tmp_path / "missing-thresholds.yaml",
            environ={"AEGIS_ENV": "test"},
        )


def test_threshold_yaml_is_loaded_into_typed_settings(tmp_path):
    thresholds_path = tmp_path / "thresholds.yaml"
    thresholds_path.write_text(
        """
risk_scoring:
  allow: 0.05
  review: 0.40
  block: 0.80
graph_analysis:
  lateral_movement_threshold_multiplier: 4.0
""",
        encoding="utf-8",
    )

    settings = load_settings(
        config_path=tmp_path / "missing-config.yaml",
        thresholds_path=thresholds_path,
        environ={"AEGIS_ENV": "test"},
    )

    assert settings.scoring.thresholds.as_dict() == {
        "allow": 0.05,
        "review": 0.40,
        "block": 0.80,
    }
    assert settings.innovations.lateral_movement_threshold_multiplier == 4.0


def test_invalid_yaml_shape_raises_clear_error(tmp_path):
    config_path = tmp_path / "config.yaml"
    config_path.write_text("- not\n- a\n- mapping\n", encoding="utf-8")

    with pytest.raises(ValueError, match="must contain a mapping"):
        load_settings(
            config_path=config_path,
            thresholds_path=tmp_path / "missing-thresholds.yaml",
            environ={"AEGIS_ENV": "test"},
        )


def test_invalid_threshold_order_fails_during_loading(tmp_path):
    thresholds_path = tmp_path / "thresholds.yaml"
    thresholds_path.write_text(
        """
risk_scoring:
  allow: 0.90
  review: 0.40
  block: 0.80
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="allow <= review <= block"):
        load_settings(
            config_path=tmp_path / "missing-config.yaml",
            thresholds_path=thresholds_path,
            environ={"AEGIS_ENV": "test"},
        )


def test_development_validation_warns_for_missing_required_env(tmp_path):
    settings = load_settings(
        config_path=tmp_path / "missing-config.yaml",
        thresholds_path=tmp_path / "missing-thresholds.yaml",
        environ={"AEGIS_ENV": "development"},
    )

    report = validate_runtime_settings(settings)

    assert report.ok
    assert report.warnings
    assert "API_URL" in report.warnings[0]
    assert "AEGIS_ALLOWED_ORIGINS" in report.warnings[0]


def test_production_validation_raises_for_missing_required_env(tmp_path):
    settings = load_settings(
        config_path=tmp_path / "missing-config.yaml",
        thresholds_path=tmp_path / "missing-thresholds.yaml",
        environ={"AEGIS_ENV": "production"},
    )

    with pytest.raises(ValueError, match="API_URL"):
        validate_runtime_settings(settings)


def test_production_validation_accepts_required_env(tmp_path):
    settings = load_settings(
        config_path=tmp_path / "missing-config.yaml",
        thresholds_path=tmp_path / "missing-thresholds.yaml",
        environ={
            "AEGIS_ENV": "production",
            "API_URL": "https://api.example.test",
            "AEGIS_ALLOWED_ORIGINS": "https://app.example.test",
        },
    )

    report = validate_runtime_settings(settings)

    assert report.ok
    assert report.warnings == []
    assert settings.to_runtime_dict()["api"]["api_url"] == "https://api.example.test"
