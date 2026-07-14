"""Regression tests for configurable runtime failure handling."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest


def _make_settings(failure_mode: str):
    return SimpleNamespace(
        runtime=SimpleNamespace(failure_mode=failure_mode),
        innovations=SimpleNamespace(redis_url="redis://localhost:6379/0"),
    )


def test_health_response_reflects_maintenance_mode(monkeypatch):
    from src.api import main as api_main

    runtime_state = SimpleNamespace(
        runtime=SimpleNamespace(health_monitor=SimpleNamespace(get_overall_status=lambda: "healthy", get_health_snapshot=lambda: {})),
        settings=_make_settings("maintenance"),
        start_time=0,
        model_loaded=True,
        graph_loaded=True,
        requests_processed=0,
    )
    monkeypatch.setattr(api_main, "state", runtime_state)

    response = api_main._build_health_response(include_details=False)

    assert response["status"] == "maintenance"
    assert response["runtime_mode"] == "maintenance"


def test_neo4j_provider_fail_fast_raises_on_connectivity_error(monkeypatch):
    from src.core.providers import neo4j as neo4j_module

    mock_driver = MagicMock()
    mock_driver.verify_connectivity.side_effect = RuntimeError("boom")
    mock_neo4j_lib = MagicMock()
    mock_neo4j_lib.GraphDatabase.driver.return_value = mock_driver

    monkeypatch.setattr(neo4j_module, "neo4j", mock_neo4j_lib)
    monkeypatch.setattr(neo4j_module, "NEO4J_AVAILABLE", True)
    monkeypatch.setattr(neo4j_module, "get_settings", lambda: _make_settings("fail_fast"))

    with pytest.raises(RuntimeError, match="boom"):
        neo4j_module.Neo4jGraphProvider(
            uri="bolt://localhost:7687",
            user="neo4j",
            password="password",
            enabled=True,
        )


def test_neo4j_provider_degraded_mode_preserves_fallback(monkeypatch):
    from src.core.providers import neo4j as neo4j_module

    mock_driver = MagicMock()
    mock_driver.verify_connectivity.side_effect = RuntimeError("boom")
    mock_neo4j_lib = MagicMock()
    mock_neo4j_lib.GraphDatabase.driver.return_value = mock_driver

    monkeypatch.setattr(neo4j_module, "neo4j", mock_neo4j_lib)
    monkeypatch.setattr(neo4j_module, "NEO4J_AVAILABLE", True)
    monkeypatch.setattr(neo4j_module, "get_settings", lambda: _make_settings("degraded"))

    provider = neo4j_module.Neo4jGraphProvider(
        uri="bolt://localhost:7687",
        user="neo4j",
        password="password",
        enabled=True,
    )

    assert provider.enabled is False
    assert provider.is_active is False


def test_graph_cache_fail_fast_raises_on_redis_error(monkeypatch):
    from src.utils import cache as cache_module

    monkeypatch.setattr(cache_module, "REDIS_AVAILABLE", True)
    monkeypatch.setattr(cache_module, "get_settings", lambda: _make_settings("fail_fast"))
    monkeypatch.setattr(cache_module, "RedisGraphCache", MagicMock(side_effect=RuntimeError("redis down")))

    with pytest.raises(RuntimeError, match="redis down"):
        cache_module.GraphOperationCache()


def test_lateral_movement_redis_fail_fast_raises(monkeypatch):
    from src.features import lateral_movement as lm_module

    monkeypatch.setattr(lm_module, "REDIS_AVAILABLE", True)
    monkeypatch.setattr(lm_module, "get_settings", lambda: _make_settings("fail_fast"))
    monkeypatch.setattr(lm_module, "get_redis_client", MagicMock(side_effect=RuntimeError("redis down")))

    with pytest.raises(RuntimeError, match="redis down"):
        lm_module.LateralMovementDetector()


@pytest.mark.asyncio
async def test_lifecycle_fail_fast_aborts_on_optional_step_failure(monkeypatch):
    from src.runtime import LifecycleManager, RuntimeState

    state = RuntimeState()
    state.settings = _make_settings("fail_fast")
    lifecycle = LifecycleManager(state)

    lifecycle.register_startup("optional", lambda: (_ for _ in ()).throw(RuntimeError("step failed")), critical=False)

    with pytest.raises(RuntimeError, match="step failed"):
        await lifecycle.startup()
