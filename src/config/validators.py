"""Centralized runtime configuration validation."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, List, Optional

from .settings import RuntimeSettings


@dataclass
class ValidationReport:
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors

    def as_metadata(self) -> dict:
        return {"errors": self.errors, "warnings": self.warnings}


def _emit(logger: Any, level: str, message: str, event_type: str, metadata: Optional[dict] = None) -> None:
    if logger and hasattr(logger, level):
        try:
            getattr(logger, level)(message, event_type=event_type, metadata=metadata or {})
        except TypeError:
            getattr(logger, level)("%s %s", message, metadata or {})


def validate_runtime_settings(
    settings: RuntimeSettings,
    *,
    strict: Optional[bool] = None,
    logger: Any = None,
) -> ValidationReport:
    """Validate runtime settings with production-strict/dev-relaxed behavior."""
    strict_mode = settings.runtime.is_production if strict is None else strict
    report = ValidationReport()

    missing_required_env = []
    if not settings.raw_environment.api_url:
        missing_required_env.append("API_URL")
    if not (settings.raw_environment.cors_origins or settings.raw_environment.aegis_allowed_origins):
        missing_required_env.append("CORS_ORIGINS (or legacy AEGIS_ALLOWED_ORIGINS)")

    if missing_required_env:
        message = f"Missing environment variables: {', '.join(missing_required_env)}"
        if strict_mode:
            report.errors.append(message)
        else:
            report.warnings.append(message)

    if settings.graph.graph_path and settings.graph.graph_path.suffix:
        if settings.graph.graph_path.suffix.lower() != settings.graph.allowed_suffix:
            report.errors.append(
                f"Graph artifact must use {settings.graph.allowed_suffix}: {settings.graph.graph_path}"
            )

    if settings.graph.graph_path != Path("") and settings.raw_environment.aegis_graph_path:
        graph_exists = settings.graph.graph_path.exists()
        if not graph_exists:
            message = f"Graph artifact does not exist: {settings.graph.graph_path}"
            if strict_mode:
                report.errors.append(message)
            else:
                report.warnings.append(message)

    if settings.graph.graph_path.exists() and not settings.graph.graph_sha256:
        message = "AEGIS_GRAPH_SHA256 is required when loading an existing graph artifact"
        if strict_mode:
            report.errors.append(message)
        else:
            report.warnings.append(message)

    if report.errors:
        _emit(
            logger,
            "error",
            "Runtime configuration validation failed",
            "config_validation_failed",
            report.as_metadata(),
        )
        raise ValueError(
            "Runtime configuration validation failed: "
            + "; ".join(report.errors)
        )

    if report.warnings:
        _emit(
            logger,
            "warning",
            "Runtime configuration validation completed with warnings",
            "config_validation_warning",
            report.as_metadata(),
        )
    else:
        _emit(
            logger,
            "info",
            "Runtime configuration validation passed",
            "config_validation_passed",
            report.as_metadata(),
        )

    return report
