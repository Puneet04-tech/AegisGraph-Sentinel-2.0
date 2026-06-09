"""Reusable runtime policy guardrails."""

from __future__ import annotations

from typing import Any, Dict


def max_recovery_attempts_guardrail(context: Dict[str, Any]) -> bool:
    return int(context.get("restart_attempts", 0)) < int(context.get("max_attempts", 1))


def resource_throttled_guardrail(context: Dict[str, Any]) -> bool:
    if context.get("resource_throttled", False):
        return False
    return context.get("backpressure_state") != "throttled"


def healthy_runtime_guardrail(context: Dict[str, Any]) -> bool:
    if context.get("shutting_down", False):
        return False
    return context.get("runtime_status", "healthy") in {"healthy", "degraded"}


def config_reload_allowed_guardrail(context: Dict[str, Any]) -> bool:
    if context.get("shutting_down", False):
        return False
    return bool(context.get("config_reload_allowed", True))
