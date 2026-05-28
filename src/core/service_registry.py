"""Centralized helpers for service registration and configuration."""

from __future__ import annotations

from typing import Any
from .dependency_container import DependencyContainer


def register_core_services(container: DependencyContainer, settings: Any, config: Any) -> None:
    """Register runtime configuration and settings services."""
    container.register("settings", settings, replace=True)
    container.register("config", config, replace=True)


def register_graph_services(
    container: DependencyContainer,
    transaction_graph: Any,
    fraud_chains: Any,
    account_profiles: Any,
) -> None:
    """Register graph database and associated static lookup data."""
    container.register("transaction_graph", transaction_graph, replace=True)
    container.register("fraud_chains", fraud_chains, replace=True)
    container.register("account_profiles", account_profiles, replace=True)


def register_innovation_services(
    container: DependencyContainer,
    voice_analyzer: Any = None,
    mule_scorer: Any = None,
    honeypot_manager: Any = None,
    blockchain_manager: Any = None,
    aegis_oracle: Any = None,
    lateral_movement_detector: Any = None,
) -> None:
    """Register active threat detection and explainability innovations."""
    if voice_analyzer is not None:
        container.register("voice_analyzer", voice_analyzer, replace=True)
    if mule_scorer is not None:
        container.register("mule_scorer", mule_scorer, replace=True)
    if honeypot_manager is not None:
        container.register("honeypot_manager", honeypot_manager, replace=True)
    if blockchain_manager is not None:
        container.register("blockchain_manager", blockchain_manager, replace=True)
    if aegis_oracle is not None:
        container.register("aegis_oracle", aegis_oracle, replace=True)
    if lateral_movement_detector is not None:
        container.register("lateral_movement_detector", lateral_movement_detector, replace=True)
