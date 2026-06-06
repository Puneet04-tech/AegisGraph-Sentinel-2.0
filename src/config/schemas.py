"""Typed configuration schemas used by the settings loader."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from . import defaults


class ConfigBaseModel(BaseModel):
    model_config = ConfigDict(extra="ignore", validate_assignment=True)


class EnvironmentVariablesSchema(ConfigBaseModel):
    """Raw environment values recognized by the runtime configuration layer."""

    aegis_env: Optional[str] = Field(default=None, description="AEGIS_ENV override.")
    app_env: Optional[str] = Field(default=None, description="APP_ENV compatibility override.")
    environment: Optional[str] = Field(default=None, description="ENVIRONMENT compatibility override.")
    api_url: Optional[str] = Field(default=None, description="External API URL required in production.")
    aegis_allowed_origins: Optional[str] = Field(default=None, description="Comma-separated CORS origins (deprecated: use CORS_ORIGINS).")
    cors_origins: Optional[str] = Field(default=None, description="Comma-separated CORS origins.")
    debug: Optional[str] = Field(default=None, description="Enables debug-only routes when true.")
    aegis_graph_path: Optional[str] = Field(default=None, description="Optional verified graph artifact path.")
    aegis_graph_sha256: Optional[str] = Field(default=None, description="Expected SHA256 for graph artifact.")
    redis_url: Optional[str] = Field(default=None, description="Optional Redis backend URL.")
    aegis_config_path: Optional[str] = Field(default=None, description="Optional runtime YAML path.")
    aegis_thresholds_path: Optional[str] = Field(default=None, description="Optional thresholds YAML path.")
    api_host: Optional[str] = Field(default=None, description="API host address (default: 0.0.0.0).")
    api_port: Optional[str] = Field(default=None, description="API port number (default: 8000).")
    api_reload: Optional[str] = Field(default=None, description="Enable API auto-reload on code changes.")
    api_log_level: Optional[str] = Field(default=None, description="API logging level (default: info).")
    rate_limit: Optional[str] = Field(default=None, description="Rate limit configuration (default: 100/minute).")
    max_batch_size: Optional[str] = Field(default=None, description="Maximum batch processing size (default: 100).")
    log_level: Optional[str] = Field(default=None, description="Application logging level (default: INFO).")
    log_format: Optional[str] = Field(default=None, description="Log format: json or text (default: json).")
    log_output_dir: Optional[str] = Field(default=None, description="Log output directory (default: logs).")
    prometheus_port: Optional[str] = Field(default=None, description="Prometheus metrics port (default: 9090).")

    @property
    def runtime_environment(self) -> str:
        return (
            self.aegis_env
            or self.app_env
            or self.environment
            or defaults.DEFAULT_ENVIRONMENT
        ).lower()


class APISettings(ConfigBaseModel):
    host: str = Field(default=defaults.DEFAULT_API_HOST)
    port: int = Field(default=defaults.DEFAULT_API_PORT, ge=1, le=65535)
    reload: bool = Field(default=defaults.DEFAULT_API_RELOAD)
    log_level: str = Field(default=defaults.DEFAULT_API_LOG_LEVEL)
    allowed_origins: List[str] = Field(default_factory=lambda: list(defaults.DEFAULT_ALLOWED_ORIGINS))
    api_url: Optional[str] = Field(default=None)
    rate_limit: str = Field(default=defaults.DEFAULT_RATE_LIMIT)

    @field_validator("allowed_origins", mode="before")
    @classmethod
    def normalize_origins(cls, value: Any) -> List[str]:
        if value is None:
            return list(defaults.DEFAULT_ALLOWED_ORIGINS)
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        if isinstance(value, (list, tuple)):
            return [str(item).strip() for item in value if str(item).strip()]
        raise TypeError("allowed_origins must be a comma-separated string or list")

    @field_validator("allowed_origins")
    @classmethod
    def reject_wildcard_origins(cls, value: List[str]) -> List[str]:
        if "*" in value:
            raise ValueError(
                "Unsafe CORS configuration: wildcard origins cannot be used "
                "while credentialed requests are enabled"
            )
        return value


class GraphRuntimeSettings(ConfigBaseModel):
    graph_path: Path = Field(default=defaults.DEFAULT_GRAPH_PATH)
    graph_sha256: Optional[str] = Field(default=None)
    allowed_suffix: str = Field(default=defaults.DEFAULT_GRAPH_ALLOWED_SUFFIX)
    load_timeout_seconds: int = Field(default=defaults.DEFAULT_GRAPH_LOAD_TIMEOUT_SECONDS, ge=1)
    k_hop_neighbors: int = Field(default=3, ge=1)
    max_subgraph_nodes: int = Field(default=1000, ge=1)
    max_subgraph_edges: int = Field(default=5000, ge=1)


class ObservabilitySettings(ConfigBaseModel):
    log_level: str = Field(default=defaults.DEFAULT_OBSERVABILITY_LOG_LEVEL)
    log_format: Literal["json", "text"] = Field(default=defaults.DEFAULT_OBSERVABILITY_LOG_FORMAT)
    output_dir: Path = Field(default=defaults.DEFAULT_OBSERVABILITY_OUTPUT_DIR)
    prometheus_enabled: bool = Field(default=False)
    prometheus_port: int = Field(default=defaults.DEFAULT_PROMETHEUS_PORT, ge=1, le=65535)


class ScoringThresholdSettings(ConfigBaseModel):
    allow: float = Field(default=defaults.DEFAULT_RISK_THRESHOLDS["allow"], ge=0.0, le=1.0)
    review: float = Field(default=defaults.DEFAULT_RISK_THRESHOLDS["review"], ge=0.0, le=1.0)
    block: float = Field(default=defaults.DEFAULT_RISK_THRESHOLDS["block"], ge=0.0, le=1.0)

    @model_validator(mode="after")
    def validate_order(self) -> "ScoringThresholdSettings":
        if not (self.allow <= self.review <= self.block):
            raise ValueError("scoring thresholds must satisfy allow <= review <= block")
        return self

    def as_dict(self) -> Dict[str, float]:
        return {"allow": self.allow, "review": self.review, "block": self.block}


class ScoringSettings(ConfigBaseModel):
    thresholds: ScoringThresholdSettings = Field(default_factory=ScoringThresholdSettings)
    weights: Dict[str, float] = Field(default_factory=lambda: dict(defaults.DEFAULT_COMPONENT_WEIGHTS))
    thresholds_path: Path = Field(default=defaults.DEFAULT_THRESHOLDS_PATH)


class InnovationSettings(ConfigBaseModel):
    redis_url: Optional[str] = Field(default=None)
    lateral_movement_history_size: int = Field(default=defaults.DEFAULT_LATERAL_MOVEMENT_HISTORY_SIZE, ge=1)
    lateral_movement_std_multiplier: float = Field(default=defaults.DEFAULT_LATERAL_MOVEMENT_STD_MULTIPLIER, ge=0.0)
    lateral_movement_threshold_multiplier: float = Field(
        default=defaults.DEFAULT_LATERAL_MOVEMENT_THRESHOLD_MULTIPLIER,
        ge=1.0,
    )
    lateral_movement_risk_increment: float = Field(
        default=defaults.DEFAULT_LATERAL_MOVEMENT_RISK_INCREMENT,
        ge=0.0,
        le=1.0,
    )
    voice_stress_threshold: float = Field(default=defaults.DEFAULT_VOICE_STRESS_THRESHOLD, ge=0.0, le=100.0)
    voice_coercion_threshold: float = Field(default=defaults.DEFAULT_VOICE_COERCION_THRESHOLD, ge=0.0, le=100.0)
    predictive_mule_risk_threshold: float = Field(
        default=defaults.DEFAULT_PREDICTIVE_MULE_RISK_THRESHOLD,
        ge=0.0,
        le=100.0,
    )
    honeypot_activation_threshold: float = Field(
        default=defaults.DEFAULT_HONEYPOT_ACTIVATION_THRESHOLD,
        ge=0.0,
        le=1.0,
    )
    honeypot_critical_indicator_threshold: float = Field(
        default=defaults.DEFAULT_HONEYPOT_CRITICAL_INDICATOR_THRESHOLD,
        ge=0.0,
        le=1.0,
    )
    honeypot_escrow_seconds: int = Field(default=defaults.DEFAULT_HONEYPOT_ESCROW_SECONDS, ge=60)


class RuntimeFlags(ConfigBaseModel):
    environment: str = Field(default=defaults.DEFAULT_ENVIRONMENT)
    debug: bool = Field(default=False)
    strict_validation: Optional[bool] = Field(default=None)
    config_path: Path = Field(default=defaults.DEFAULT_CONFIG_PATH)

    @property
    def is_production(self) -> bool:
        return self.environment.lower() == "production"

    @property
    def is_test(self) -> bool:
        return self.environment.lower() == "test"
