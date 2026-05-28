"""Tests for centralized Dependency Injection and service boundaries."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from src.core import (
    DependencyContainer,
    register_core_services,
    register_graph_services,
    register_innovation_services,
)
from src.api.main import AppState, app, state


def test_dependency_container_registration_and_lookup() -> None:
    """Verify standard registration, resolution, optional lookup, and replace behavior."""
    container = DependencyContainer()
    service_a = object()
    service_b = object()

    # Register and verify
    container.register("service_a", service_a)
    assert container.has("service_a") is True
    assert container.get("service_a") is service_a
    assert container.optional_get("service_a") is service_a

    # Duplicate registration raises error by default
    with pytest.raises(KeyError, match="is already registered"):
        container.register("service_a", service_b)

    # replace=True allows updates
    container.register("service_a", service_b, replace=True)
    assert container.get("service_a") is service_b

    # Missing required service raises KeyError
    with pytest.raises(KeyError, match="not registered or is not available"):
        container.get("nonexistent_service")

    # Optional get on missing service returns None
    assert container.optional_get("nonexistent_service") is None


def test_dependency_container_handles_none_value() -> None:
    """Verify that registering None is supported, but acts as absent in get/has."""
    container = DependencyContainer()
    container.register("null_service", None)

    # optional_get returns None
    assert container.optional_get("null_service") is None

    # get raises KeyError
    with pytest.raises(KeyError, match="not registered or is not available"):
        container.get("null_service")

    # has returns False
    assert container.has("null_service") is False


def test_app_state_property_delegation() -> None:
    """Verify AppState property getters/setters delegate to the services container."""
    app_state = AppState()
    analyzer = object()

    # Before setting, property and optional_get return None
    assert app_state.voice_analyzer is None
    assert app_state.services.optional_get("voice_analyzer") is None

    # Set property and verify in container
    app_state.voice_analyzer = analyzer
    assert app_state.voice_analyzer is analyzer
    assert app_state.services.get("voice_analyzer") is analyzer

    # Reset property to None and verify container state
    app_state.voice_analyzer = None
    assert app_state.voice_analyzer is None
    assert app_state.services.optional_get("voice_analyzer") is None


def test_service_registry_helpers() -> None:
    """Verify that service registration helpers correctly populate the container."""
    container = DependencyContainer()

    # Core configuration
    settings_mock = object()
    config_mock = object()
    register_core_services(container, settings_mock, config_mock)
    assert container.get("settings") is settings_mock
    assert container.get("config") is config_mock

    # Graph configuration
    graph_mock = object()
    chains_mock = object()
    profiles_mock = object()
    register_graph_services(container, graph_mock, chains_mock, profiles_mock)
    assert container.get("transaction_graph") is graph_mock
    assert container.get("fraud_chains") is chains_mock
    assert container.get("account_profiles") is profiles_mock

    # Innovation configuration
    voice_mock = object()
    mule_mock = object()
    register_innovation_services(container, voice_analyzer=voice_mock, mule_scorer=mule_mock)
    assert container.get("voice_analyzer") is voice_mock
    assert container.get("mule_scorer") is mule_mock
    assert container.optional_get("honeypot_manager") is None


def test_api_lifespan_service_registration(monkeypatch) -> None:
    """Verify that the FastAPI lifespan startup correctly registers innovation services."""
    monkeypatch.setenv("AEGIS_ENV", "test")
    # Reset state to None first
    state.voice_analyzer = None
    state.mule_scorer = None
    state.honeypot_manager = None
    state.blockchain_manager = None
    state.aegis_oracle = None

    try:
        with TestClient(app):
            # Once context manager is entered, services should be registered in the container
            # check both via property and container lookup
            assert state.services.has("settings") is True
            assert state.services.has("config") is True
            assert state.services.optional_get("transaction_graph") is state.transaction_graph
            assert state.services.optional_get("fraud_chains") is state.fraud_chains
            assert state.services.optional_get("account_profiles") is state.account_profiles
            assert state.services.has("lifecycle_manager") is True

            # Innovations (which might or might not be available depending on imports)
            # should be bound consistently
            if state.voice_analyzer is not None:
                assert state.services.get("voice_analyzer") is state.voice_analyzer
            if state.blockchain_manager is not None:
                assert state.services.get("blockchain_manager") is state.blockchain_manager
    finally:
        state.voice_analyzer = None
        state.mule_scorer = None
        state.honeypot_manager = None
        state.blockchain_manager = None
        state.aegis_oracle = None
