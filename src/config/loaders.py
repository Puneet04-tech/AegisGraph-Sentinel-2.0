"""Configuration loading helpers for env and optional YAML files."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, Mapping, MutableMapping, Optional

import yaml
from dotenv import load_dotenv

from . import defaults
from .schemas import (
    APISettings,
    EnvironmentVariablesSchema,
    GraphRuntimeSettings,
    InnovationSettings,
    ObservabilitySettings,
    RuntimeFlags,
    ScoringSettings,
    ScoringThresholdSettings,
)
from .settings import RuntimeSettings


ENV_ALIASES = {
    "aegis_env": "AEGIS_ENV",
    "app_env": "APP_ENV",
    "environment": "ENVIRONMENT",
    "api_url": "API_URL",
    "aegis_allowed_origins": "AEGIS_ALLOWED_ORIGINS",
    "cors_origins": "CORS_ORIGINS",
    "debug": "DEBUG",
    "aegis_graph_path": "AEGIS_GRAPH_PATH",
    "aegis_graph_sha256": "AEGIS_GRAPH_SHA256",
    "redis_url": "REDIS_URL",
    "aegis_config_path": "AEGIS_CONFIG_PATH",
    "aegis_thresholds_path": "AEGIS_THRESHOLDS_PATH",
    "api_host": "API_HOST",
    "api_port": "API_PORT",
    "api_reload": "API_RELOAD",
    "api_log_level": "API_LOG_LEVEL",
    "rate_limit": "RATE_LIMIT",
    "max_batch_size": "MAX_BATCH_SIZE",
    "log_level": "LOG_LEVEL",
    "log_format": "LOG_FORMAT",
    "log_output_dir": "LOG_OUTPUT_DIR",
    "prometheus_port": "PROMETHEUS_PORT",
}


def _deep_merge(base: MutableMapping[str, Any], override: Mapping[str, Any]) -> MutableMapping[str, Any]:
    for key, value in override.items():
        if isinstance(value, Mapping) and isinstance(base.get(key), MutableMapping):
            _deep_merge(base[key], value)
        else:
            base[key] = value
    return base


def _load_yaml(path: Path, *, optional: bool = True) -> Dict[str, Any]:
    if not path.exists():
        if optional:
            return {}
        raise FileNotFoundError(f"Configuration file not found: {path}")
    with path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    if not isinstance(data, dict):
        raise ValueError(f"Configuration file must contain a mapping: {path}")
    return data



def load_environment(
    environ: Optional[Mapping[str, str]] = None,
) -> EnvironmentVariablesSchema:
    """Load recognized environment variables into a typed raw schema."""
    if environ is None:
        load_dotenv()
        source = os.environ
    else:
        source = environ
    mapped = {}

    # First, copy any existing lowercase keys directly passed
    # (e.g. from tests)
    for k, v in source.items():
        if k in EnvironmentVariablesSchema.model_fields:
            mapped[k] = v

    # Then overlay mapped uppercase environment keys
    for field_name, env_var in ENV_ALIASES.items():
        if env_var in source:
            mapped[field_name] = source[env_var]

    return EnvironmentVariablesSchema(**mapped)


def load_runtime_yaml(config_path: Optional[str | Path] = None) -> Dict[str, Any]:
    path = Path(config_path or defaults.DEFAULT_CONFIG_PATH)
    return _load_yaml(path, optional=True)


def load_threshold_yaml(thresholds_path: Optional[str | Path] = None) -> Dict[str, Any]:
    path = Path(thresholds_path or defaults.DEFAULT_THRESHOLDS_PATH)
    return _load_yaml(path, optional=True)


def _bool_from_env(value: Optional[str], default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _build_settings_dict(
    runtime_config: Dict[str, Any],
    thresholds_config: Dict[str, Any],
    env: EnvironmentVariablesSchema,
    config_path: Path,
    thresholds_path: Path,
) -> Dict[str, Any]:
    api_config = dict(runtime_config.get("api", {}))
    graph_config = dict(runtime_config.get("graph", {}))
    monitoring_config = dict(runtime_config.get("monitoring", {}))
    logging_config = dict(monitoring_config.get("logging", {}))
    prometheus_config = dict(monitoring_config.get("prometheus", {}))
    risk_config = dict(runtime_config.get("risk_scoring", {}))
    advanced_config = dict(runtime_config.get("advanced_features", {}))

    risk_thresholds = dict(risk_config.get("thresholds", {}))
    threshold_risk_config = thresholds_config.get("risk_scoring")
    if isinstance(threshold_risk_config, dict):
        _deep_merge(risk_thresholds, threshold_risk_config)

    graph_analysis = thresholds_config.get("graph_analysis", {})
    if not isinstance(graph_analysis, dict):
        graph_analysis = {}

    honeypot_thresholds = thresholds_config.get("honeypot_escrow", {})
    if not isinstance(honeypot_thresholds, dict):
        honeypot_thresholds = {}

    voice_thresholds = thresholds_config.get("voice_stress", {})
    if not isinstance(voice_thresholds, dict):
        voice_thresholds = {}

    predictive_thresholds = thresholds_config.get("predictive_mule", {})
    if not isinstance(predictive_thresholds, dict):
        predictive_thresholds = {}

    environment = (
        env.aegis_env
        or env.app_env
        or env.environment
        or defaults.DEFAULT_ENVIRONMENT
    )
    system_config = runtime_config.get("system", {})
    if isinstance(system_config, dict) and not (env.aegis_env or env.app_env or env.environment):
        environment = system_config.get("environment", defaults.DEFAULT_ENVIRONMENT)

    api_port_val = env.api_port or api_config.get("port", defaults.DEFAULT_API_PORT)
    try:
        api_port_val = int(api_port_val)
    except (ValueError, TypeError):
        pass

    api_reload_raw = api_config.get("reload")
    if api_reload_raw is None:
        api_reload_val = defaults.DEFAULT_API_RELOAD
    elif not isinstance(api_reload_raw, bool):
        api_reload_val = str(api_reload_raw).strip().lower() in {"true", "1", "yes", "on"}
    else:
        api_reload_val = api_reload_raw

    reload_bool = _bool_from_env(env.api_reload, api_reload_val) if env.api_reload is not None else api_reload_val

    prometheus_port_val = env.prometheus_port or prometheus_config.get("port", defaults.DEFAULT_PROMETHEUS_PORT)
    try:
        prometheus_port_val = int(prometheus_port_val)
    except (ValueError, TypeError):
        pass

    return {
        "api": {
            "host": env.api_host or api_config.get("host", defaults.DEFAULT_API_HOST),
            "port": api_port_val,
            "reload": reload_bool,
            "log_level": env.api_log_level or api_config.get("log_level", defaults.DEFAULT_API_LOG_LEVEL),
            "allowed_origins": env.cors_origins or env.aegis_allowed_origins or api_config.get("allowed_origins"),
            "api_url": env.api_url or api_config.get("api_url"),
            "rate_limit": env.rate_limit or api_config.get("rate_limit", defaults.DEFAULT_RATE_LIMIT),
        },
        "graph": {
            "graph_path": env.aegis_graph_path or graph_config.get("path") or defaults.DEFAULT_GRAPH_PATH,
            "graph_sha256": env.aegis_graph_sha256 or graph_config.get("sha256"),
            "k_hop_neighbors": graph_config.get("k_hop_neighbors", 3),
            "max_subgraph_nodes": graph_config.get("max_subgraph_nodes", 1000),
            "max_subgraph_edges": graph_config.get("max_subgraph_edges", 5000),
        },
        "observability": {
            "log_level": env.log_level or logging_config.get("level", defaults.DEFAULT_OBSERVABILITY_LOG_LEVEL),
            "log_format": env.log_format or logging_config.get("format", defaults.DEFAULT_OBSERVABILITY_LOG_FORMAT),
            "output_dir": env.log_output_dir or logging_config.get("output_dir", defaults.DEFAULT_OBSERVABILITY_OUTPUT_DIR),
            "prometheus_enabled": prometheus_config.get("enabled", False),
            "prometheus_port": prometheus_port_val,
        },
        "scoring": {
            "thresholds": risk_thresholds,
            "weights": risk_config.get("weights", defaults.DEFAULT_COMPONENT_WEIGHTS),
            "thresholds_path": thresholds_path,
        },
        "innovations": {
            "redis_url": env.redis_url,
            "lateral_movement_history_size": graph_analysis.get(
                "history_size",
                defaults.DEFAULT_LATERAL_MOVEMENT_HISTORY_SIZE,
            ),
            "lateral_movement_std_multiplier": graph_analysis.get(
                "lateral_movement_std_multiplier",
                defaults.DEFAULT_LATERAL_MOVEMENT_STD_MULTIPLIER,
            ),
            "lateral_movement_threshold_multiplier": graph_analysis.get(
                "lateral_movement_threshold_multiplier",
                defaults.DEFAULT_LATERAL_MOVEMENT_THRESHOLD_MULTIPLIER,
            ),
            "lateral_movement_risk_increment": graph_analysis.get(
                "lateral_movement_risk_increment",
                defaults.DEFAULT_LATERAL_MOVEMENT_RISK_INCREMENT,
            ),
            "voice_stress_threshold": voice_thresholds.get(
                "stress_threshold",
                defaults.DEFAULT_VOICE_STRESS_THRESHOLD,
            ),
            "voice_coercion_threshold": voice_thresholds.get(
                "coercion_threshold",
                defaults.DEFAULT_VOICE_COERCION_THRESHOLD,
            ),
            "predictive_mule_risk_threshold": predictive_thresholds.get(
                "risk_threshold",
                defaults.DEFAULT_PREDICTIVE_MULE_RISK_THRESHOLD,
            ),
            "honeypot_activation_threshold": honeypot_thresholds.get(
                "activation_threshold",
                defaults.DEFAULT_HONEYPOT_ACTIVATION_THRESHOLD,
            ),
            "honeypot_critical_indicator_threshold": honeypot_thresholds.get(
                "critical_indicator_threshold",
                defaults.DEFAULT_HONEYPOT_CRITICAL_INDICATOR_THRESHOLD,
            ),
            "honeypot_escrow_seconds": honeypot_thresholds.get(
                "escrow_duration_seconds",
                advanced_config.get("honeypot_escrow", {}).get(
                    "escrow_duration_seconds",
                    defaults.DEFAULT_HONEYPOT_ESCROW_SECONDS,
                )
                if isinstance(advanced_config.get("honeypot_escrow"), dict)
                else defaults.DEFAULT_HONEYPOT_ESCROW_SECONDS,
            ),
        },
        "runtime": {
            "environment": environment,
            "debug": _bool_from_env(env.debug, default=False),
            "strict_validation": None,
            "config_path": config_path,
        },
        "raw_config": runtime_config,
        "raw_environment": env,
    }


def load_settings(
    *,
    config_path: Optional[str | Path] = None,
    thresholds_path: Optional[str | Path] = None,
    environ: Optional[Mapping[str, str]] = None,
) -> RuntimeSettings:
    """Load typed runtime settings from defaults, YAML, and environment."""
    env = load_environment(environ)
    resolved_config_path = Path(config_path or env.aegis_config_path or defaults.DEFAULT_CONFIG_PATH)
    resolved_thresholds_path = Path(
        thresholds_path or env.aegis_thresholds_path or defaults.DEFAULT_THRESHOLDS_PATH
    )

    runtime_config = load_runtime_yaml(resolved_config_path)
    thresholds_config = load_threshold_yaml(resolved_thresholds_path)
    settings_dict = _build_settings_dict(
        runtime_config,
        thresholds_config,
        env,
        resolved_config_path,
        resolved_thresholds_path,
    )

    return RuntimeSettings(
        api=APISettings(**settings_dict["api"]),
        graph=GraphRuntimeSettings(**settings_dict["graph"]),
        observability=ObservabilitySettings(**settings_dict["observability"]),
        scoring=ScoringSettings(
            thresholds=ScoringThresholdSettings(**settings_dict["scoring"]["thresholds"]),
            weights=settings_dict["scoring"]["weights"],
            thresholds_path=settings_dict["scoring"]["thresholds_path"],
        ),
        innovations=InnovationSettings(**settings_dict["innovations"]),
        runtime=RuntimeFlags(**settings_dict["runtime"]),
        raw_config=settings_dict["raw_config"],
        raw_environment=settings_dict["raw_environment"],
    )