"""Runtime configuration defaults.

Defaults live here so runtime code and tests can share one deterministic source
without reaching directly into environment variables.
"""

from __future__ import annotations

from pathlib import Path

import os

DEFAULT_ENVIRONMENT = os.getenv("AEGIS_ENVIRONMENT", "development")
DEFAULT_CONFIG_PATH = Path(os.getenv("AEGIS_CONFIG_PATH", "config/config.yaml"))
DEFAULT_THRESHOLDS_PATH = Path(os.getenv("AEGIS_THRESHOLDS_PATH", "config/thresholds.yaml"))

DEFAULT_API_HOST = os.getenv("API_HOST", "0.0.0.0")
DEFAULT_API_PORT = int(os.getenv("API_PORT", "8000"))
DEFAULT_API_RELOAD = os.getenv("API_RELOAD", "true").lower() in ("true", "1", "yes")
DEFAULT_API_LOG_LEVEL = os.getenv("API_LOG_LEVEL", "info")
# CORS origins as comma-separated string
DEFAULT_ALLOWED_ORIGINS_STR = os.getenv(
    "CORS_ORIGINS",
    "http://localhost:3000,http://localhost:8501,http://127.0.0.1:8501"
)
DEFAULT_ALLOWED_ORIGINS = tuple(
    origin.strip() for origin in DEFAULT_ALLOWED_ORIGINS_STR.split(",") if origin.strip()
)
DEFAULT_RATE_LIMIT = os.getenv("RATE_LIMIT", "100/minute")
DEFAULT_MAX_BATCH_SIZE = int(os.getenv("MAX_BATCH_SIZE", "100"))

DEFAULT_GRAPH_PATH = Path(os.getenv("GRAPH_PATH", "data/synthetic/graph.graphml"))
DEFAULT_GRAPH_ALLOWED_SUFFIX = os.getenv("GRAPH_ALLOWED_SUFFIX", ".graphml")
DEFAULT_GRAPH_LOAD_TIMEOUT_SECONDS = int(os.getenv("GRAPH_LOAD_TIMEOUT_SECONDS", "30"))

DEFAULT_RISK_THRESHOLDS = {
    "allow": float(os.getenv("RISK_THRESHOLD_ALLOW", "0.50")),
    "review": float(os.getenv("RISK_THRESHOLD_REVIEW", "0.70")),
    "block": float(os.getenv("RISK_THRESHOLD_BLOCK", "0.90")),
}
DEFAULT_COMPONENT_WEIGHTS = {
    "graph": float(os.getenv("COMPONENT_WEIGHT_GRAPH", "0.50")),
    "velocity": float(os.getenv("COMPONENT_WEIGHT_VELOCITY", "0.20")),
    "behavior": float(os.getenv("COMPONENT_WEIGHT_BEHAVIOR", "0.20")),
    "entropy": float(os.getenv("COMPONENT_WEIGHT_ENTROPY", "0.10")),
}

DEFAULT_LATERAL_MOVEMENT_STD_MULTIPLIER = float(os.getenv("LATERAL_MOVEMENT_STD_MULTIPLIER", "2.0"))
DEFAULT_LATERAL_MOVEMENT_THRESHOLD_MULTIPLIER = float(os.getenv("LATERAL_MOVEMENT_THRESHOLD_MULTIPLIER", "3.0"))
DEFAULT_LATERAL_MOVEMENT_RISK_INCREMENT = float(os.getenv("LATERAL_MOVEMENT_RISK_INCREMENT", "0.25"))
DEFAULT_LATERAL_MOVEMENT_HISTORY_SIZE = int(os.getenv("LATERAL_MOVEMENT_HISTORY_SIZE", "10"))

DEFAULT_HONEYPOT_ESCROW_SECONDS = int(os.getenv("HONEYPOT_ESCROW_SECONDS", "900"))
DEFAULT_HONEYPOT_ACTIVATION_THRESHOLD = float(os.getenv("HONEYPOT_ACTIVATION_THRESHOLD", "0.90"))
DEFAULT_HONEYPOT_CRITICAL_INDICATOR_THRESHOLD = float(os.getenv("HONEYPOT_CRITICAL_INDICATOR_THRESHOLD", "0.80"))
DEFAULT_VOICE_STRESS_THRESHOLD = float(os.getenv("VOICE_STRESS_THRESHOLD", "30.0"))
DEFAULT_VOICE_COERCION_THRESHOLD = float(os.getenv("VOICE_COERCION_THRESHOLD", "75.0"))
DEFAULT_PREDICTIVE_MULE_RISK_THRESHOLD = float(os.getenv("PREDICTIVE_MULE_RISK_THRESHOLD", "75.0"))

DEFAULT_API_KEY = os.getenv("AEGIS_API_KEY", "")

DEFAULT_OBSERVABILITY_LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
DEFAULT_OBSERVABILITY_LOG_FORMAT = os.getenv("LOG_FORMAT", "json")
DEFAULT_OBSERVABILITY_OUTPUT_DIR = Path(os.getenv("LOG_OUTPUT_DIR", "logs"))
DEFAULT_PROMETHEUS_PORT = int(os.getenv("PROMETHEUS_PORT", "9090"))

DEFAULT_DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL", "")
DEFAULT_SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL", "")
DEFAULT_ENABLE_DISCORD_WEBHOOK = os.getenv("ENABLE_DISCORD_WEBHOOK", "false").lower() in ("true", "1", "yes")
DEFAULT_ENABLE_SLACK_WEBHOOK = os.getenv("ENABLE_SLACK_WEBHOOK", "false").lower() in ("true", "1", "yes")
# Global kill-switch: when False, all webhook notifications are suppressed
# regardless of the per-service ENABLE_DISCORD_WEBHOOK / ENABLE_SLACK_WEBHOOK flags.
DEFAULT_ENABLE_WEBHOOK_ALERTS = os.getenv("ENABLE_WEBHOOK_ALERTS", "false").lower() in ("true", "1", "yes")
