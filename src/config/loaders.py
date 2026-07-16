"""Configuration loading helpers for env and optional YAML files."""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any, Dict, Mapping, MutableMapping, Optional

import yaml
from dotenv import load_dotenv

logger = logging.getLogger(__name__)

from . import defaults
from .schemas import (
    APISettings,
    EnvironmentVariablesSchema,
    DatabaseConnectionSettings,
    GraphRuntimeSettings,
    InnovationSettings,
    ObservabilitySettings,
    RuntimeFlags,
    ScoringSettings,
    ScoringThresholdSettings,
    WebhookSettings,
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
    "redis_max_connections": "REDIS_MAX_CONNECTIONS",
    "redis_socket_timeout": "REDIS_SOCKET_TIMEOUT",
    "redis_socket_connect_timeout": "REDIS_SOCKET_CONNECT_TIMEOUT",
    "redis_retry_on_timeout": "REDIS_RETRY_ON_TIMEOUT",
    "redis_health_check_interval": "REDIS_HEALTH_CHECK_INTERVAL",
    "redis_socket_keepalive": "REDIS_SOCKET_KEEPALIVE",
    "neo4j_enabled": "NEO4J_ENABLED",
    "neo4j_uri": "NEO4J_URI",
    "neo4j_user": "NEO4J_USER",
    "neo4j_password": "NEO4J_PASSWORD",
    "neo4j_max_connection_pool_size": "NEO4J_MAX_CONNECTION_POOL_SIZE",
    "neo4j_connection_timeout": "NEO4J_CONNECTION_TIMEOUT",
    "neo4j_connection_acquisition_timeout": "NEO4J_CONNECTION_ACQUISITION_TIMEOUT",
    "neo4j_max_connection_lifetime": "NEO4J_MAX_CONNECTION_LIFETIME",
    "neo4j_max_transaction_retry_time": "NEO4J_MAX_TRANSACTION_RETRY_TIME",
    "neo4j_keep_alive": "NEO4J_KEEP_ALIVE",
    "neo4j_liveness_check_timeout": "NEO4J_LIVENESS_CHECK_TIMEOUT",
    "backup_directory": "BACKUP_DIRECTORY",
    "backup_encryption_key": "BACKUP_ENCRYPTION_KEY",
    "backup_database_url": "BACKUP_DATABASE_URL",
    "backup_tool_path": "BACKUP_TOOL_PATH",
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
    "discord_webhook_url": "DISCORD_WEBHOOK_URL",
    "slack_webhook_url": "SLACK_WEBHOOK_URL",
    "teams_webhook_url": "TEAMS_WEBHOOK_URL",
    "enable_discord_webhook": "ENABLE_DISCORD_WEBHOOK",
    "enable_slack_webhook": "ENABLE_SLACK_WEBHOOK",
    "enable_teams_webhook": "ENABLE_TEAMS_WEBHOOK",
    "enable_webhook_alerts": "ENABLE_WEBHOOK_ALERTS",
}


def _deep_merge(base: MutableMapping[str, Any], override: Mapping[str, Any]) -> MutableMapping[str, Any]:
    for key, value in override.items():
        if isinstance(value, Mapping) and isinstance(base.get(key), MutableMapping):
            _deep_merge(base[key], value)
        else:
            base[key] = value
    return base


def _substitute_env_vars(raw: str) -> str:
    """Replace ${VAR_NAME} placeholders with os.environ values."""
    import re as _re

    def _replace(match: "_re.Match[str]") -> str:
        return os.environ.get(match.group(1), "")

    return _re.sub(r"\$\{([^}]+)\}", _replace, raw)


def _load_yaml(path: Path, *, optional: bool = True) -> Dict[str, Any]:
    if not path.exists():
        if optional:
            return {}
        raise FileNotFoundError(f"Configuration file not found: {path}")
    with path.open("r", encoding="utf-8") as handle:
        raw = handle.read()
    raw = _substitute_env_vars(raw)
    data = yaml.safe_load(raw) or {}
    if not isinstance(data, dict):
        raise ValueError(f"Configuration file must contain a mapping: {path}")
    return data



def load_environment(
    environ: Optional[Mapping[str, str]] = None,
) -> EnvironmentVariablesSchema:
    """Load recognized environment variables into a typed raw schema."""
    load_dotenv()
    if environ is None:
        source = os.environ
    else:
        source = environ
    
    mapped = {}

    for key, value in source.items():
        if key in EnvironmentVariablesSchema.model_fields:
            mapped[key] = value

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

    normalized = value.strip().lower()

    truthy = {"1", "true", "yes", "on"}
    falsy = {"0", "false", "no", "off", "release"}

    if normalized in truthy:
        return True

    if normalized in falsy:
        return False

    raise ValueError(
        f"Invalid boolean environment value: {value!r}. "
        f"Expected one of: true, false, yes, no, on, off, 1, 0"
    )


def _bool_from_env_or_default(value: Optional[str], default: bool = False) -> bool:
    try:
        return _bool_from_env(value, default=default)
    except ValueError:
        logger.warning("Ignoring invalid boolean environment value for debug flag: %r", value)
        return default


def _float_from_env(value: Optional[str]) -> Optional[float]:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Invalid numeric environment value: {value!r}") from exc


def _int_from_env(value: Optional[str]) -> Optional[int]:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Invalid integer environment value: {value!r}") from exc


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
    webhook_config = dict(runtime_config.get("webhook", {}))
    database_config = dict(runtime_config.get("database", {}))
    redis_config = dict(database_config.get("redis", {}))
    neo4j_config = dict(database_config.get("neo4j", {}))
    runtime_policy_config = dict(runtime_config.get("runtime", {}))

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
    except (ValueError, TypeError) as exc:
        logger.warning("Invalid api_port value %r, falling back to %s: %s",
                       api_port_val, defaults.DEFAULT_API_PORT, exc)
        api_port_val = defaults.DEFAULT_API_PORT

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
    except (ValueError, TypeError) as exc:
        logger.warning("Invalid prometheus_port value %r, falling back to %s: %s",
                       prometheus_port_val, defaults.DEFAULT_PROMETHEUS_PORT, exc)
        prometheus_port_val = defaults.DEFAULT_PROMETHEUS_PORT

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
            "high_value_threshold": float(risk_config.get("high_value_threshold", 500000.0)),
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
        "database": {
            "redis_url": env.redis_url or database_config.get("redis_url") or redis_config.get("url"),
            "redis_max_connections": _int_from_env(env.redis_max_connections)
            if env.redis_max_connections is not None
            else redis_config.get("max_connections", 50),
            "redis_socket_timeout": _float_from_env(env.redis_socket_timeout)
            if env.redis_socket_timeout is not None
            else redis_config.get("socket_timeout"),
            "redis_socket_connect_timeout": _float_from_env(env.redis_socket_connect_timeout)
            if env.redis_socket_connect_timeout is not None
            else redis_config.get("socket_connect_timeout"),
            "redis_retry_on_timeout": _bool_from_env(env.redis_retry_on_timeout)
            if env.redis_retry_on_timeout is not None
            else redis_config.get("retry_on_timeout", False),
            "redis_health_check_interval": _int_from_env(env.redis_health_check_interval)
            if env.redis_health_check_interval is not None
            else redis_config.get("health_check_interval"),
            "redis_socket_keepalive": _bool_from_env(env.redis_socket_keepalive)
            if env.redis_socket_keepalive is not None
            else redis_config.get("socket_keepalive", False),
            "neo4j_enabled": _bool_from_env(env.neo4j_enabled)
            if env.neo4j_enabled is not None
            else neo4j_config.get("enabled", False),
            "neo4j_uri": env.neo4j_uri or neo4j_config.get("uri"),
            "neo4j_user": env.neo4j_user or neo4j_config.get("user"),
            "neo4j_password": env.neo4j_password or neo4j_config.get("password"),
            "neo4j_max_connection_pool_size": _int_from_env(env.neo4j_max_connection_pool_size)
            if env.neo4j_max_connection_pool_size is not None
            else neo4j_config.get("max_connection_pool_size", 50),
            "neo4j_connection_timeout": _float_from_env(env.neo4j_connection_timeout)
            if env.neo4j_connection_timeout is not None
            else neo4j_config.get("connection_timeout"),
            "neo4j_connection_acquisition_timeout": _float_from_env(env.neo4j_connection_acquisition_timeout)
            if env.neo4j_connection_acquisition_timeout is not None
            else neo4j_config.get("connection_acquisition_timeout"),
            "neo4j_max_connection_lifetime": _float_from_env(env.neo4j_max_connection_lifetime)
            if env.neo4j_max_connection_lifetime is not None
            else neo4j_config.get("max_connection_lifetime", 3600.0),
            "neo4j_max_transaction_retry_time": _float_from_env(env.neo4j_max_transaction_retry_time)
            if env.neo4j_max_transaction_retry_time is not None
            else neo4j_config.get("max_transaction_retry_time"),
            "neo4j_keep_alive": _bool_from_env(env.neo4j_keep_alive)
            if env.neo4j_keep_alive is not None
            else neo4j_config.get("keep_alive", True),
            "neo4j_liveness_check_timeout": _float_from_env(env.neo4j_liveness_check_timeout)
            if env.neo4j_liveness_check_timeout is not None
            else neo4j_config.get("liveness_check_timeout"),
        },
        "webhook": {
            "discord_url": env.discord_webhook_url or webhook_config.get("discord_url", defaults.DEFAULT_DISCORD_WEBHOOK_URL),
            "slack_url": env.slack_webhook_url or webhook_config.get("slack_url", defaults.DEFAULT_SLACK_WEBHOOK_URL),
            "teams_url": env.teams_webhook_url or webhook_config.get("teams_url", defaults.DEFAULT_TEAMS_WEBHOOK_URL),
            "enable_discord": _bool_from_env(env.enable_discord_webhook, webhook_config.get("enable_discord", defaults.DEFAULT_ENABLE_DISCORD_WEBHOOK)) if env.enable_discord_webhook is not None else webhook_config.get("enable_discord", defaults.DEFAULT_ENABLE_DISCORD_WEBHOOK),
            "enable_slack": _bool_from_env(env.enable_slack_webhook, webhook_config.get("enable_slack", defaults.DEFAULT_ENABLE_SLACK_WEBHOOK)) if env.enable_slack_webhook is not None else webhook_config.get("enable_slack", defaults.DEFAULT_ENABLE_SLACK_WEBHOOK),
            "enable_teams": _bool_from_env(env.enable_teams_webhook, webhook_config.get("enable_teams", defaults.DEFAULT_ENABLE_TEAMS_WEBHOOK)) if env.enable_teams_webhook is not None else webhook_config.get("enable_teams", defaults.DEFAULT_ENABLE_TEAMS_WEBHOOK),
            "enable_alerts": _bool_from_env(getattr(env, "enable_webhook_alerts", None), webhook_config.get("enable_alerts", defaults.DEFAULT_ENABLE_WEBHOOK_ALERTS)) if getattr(env, "enable_webhook_alerts", None) is not None else webhook_config.get("enable_alerts", defaults.DEFAULT_ENABLE_WEBHOOK_ALERTS),
        },
        "runtime": {
            "environment": environment,
            "debug": _bool_from_env_or_default(env.debug, default=False),
            "strict_validation": None,
            "config_path": config_path,
            "failure_mode": (
                (env.runtime_failure_mode or runtime_policy_config.get("failure_mode", "degraded"))
                .strip()
                .lower()
            ),
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
            high_value_threshold=settings_dict["scoring"]["high_value_threshold"],
        ),
        innovations=InnovationSettings(**settings_dict["innovations"]),
        database=DatabaseConnectionSettings(**settings_dict["database"]),
        webhook=WebhookSettings(**settings_dict["webhook"]),
        runtime=RuntimeFlags(**settings_dict["runtime"]),
        raw_config=settings_dict["raw_config"],
        raw_environment=settings_dict["raw_environment"],
    )
