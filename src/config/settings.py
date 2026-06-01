"""Central typed runtime settings."""

from __future__ import annotations

from typing import Any, Dict, Optional

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .schemas import (
    APISettings,
    EnvironmentVariablesSchema,
    GraphRuntimeSettings,
    InnovationSettings,
    ObservabilitySettings,
    RuntimeFlags,
    ScoringSettings,
)


class RuntimeSettings(BaseModel):
    """Complete runtime configuration grouped by operational concern."""

    model_config = ConfigDict(extra="ignore", validate_assignment=True)

    api: APISettings = Field(default_factory=APISettings)
    graph: GraphRuntimeSettings = Field(default_factory=GraphRuntimeSettings)
    observability: ObservabilitySettings = Field(default_factory=ObservabilitySettings)
    scoring: ScoringSettings = Field(default_factory=ScoringSettings)
    innovations: InnovationSettings = Field(default_factory=InnovationSettings)
    runtime: RuntimeFlags = Field(default_factory=RuntimeFlags)
    raw_config: Dict[str, Any] = Field(default_factory=dict)
    raw_environment: EnvironmentVariablesSchema = Field(default_factory=EnvironmentVariablesSchema)

    @model_validator(mode="after")
    def validate_cors_configuration(self) -> "RuntimeSettings":
        if any(origin.strip() == "*" for origin in self.api.allowed_origins):
            raise RuntimeError(
                "Unsafe CORS configuration: wildcard origins cannot be used with credentials enabled."
            )
        return self

    def to_runtime_dict(self) -> Dict[str, Any]:
        """Return a JSON-safe dict for service registration and tests."""
        return self.model_dump(mode="json", exclude={"raw_environment"})


_settings_cache: Optional[RuntimeSettings] = None


def get_settings(*, refresh: bool = False, config_path: Optional[str] = None) -> RuntimeSettings:
    """Return cached runtime settings, loading them on first use."""
    global _settings_cache
    if refresh or _settings_cache is None:
        from .loaders import load_settings

        _settings_cache = load_settings(config_path=config_path)
    return _settings_cache


def reset_settings_cache() -> None:
    """Clear cached settings for tests and controlled reloads."""
    global _settings_cache
    _settings_cache = None
