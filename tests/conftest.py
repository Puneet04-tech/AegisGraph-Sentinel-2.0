"""Shared pytest fixtures for the AegisGraph Sentinel 2.0 test suite.

Three concerns handled here:

1. ``api_client`` — the original fixture (restored verbatim from the
   maintainer's commit). Runs the app lifespan via TestClient's context
   manager so innovation managers are initialised, then resets that
   state to None on teardown so tests that rely on an uninitialised
   ``state.aegis_oracle`` (e.g. the 503 path in /api/v1/explain) keep
   working regardless of test ordering.

2. ``_bypass_api_key_for_legacy_tests`` — the X-API-Key gate added in
   PR #275 (issue #239 Part 1) is fail-closed: business endpoints return
   503 when AEGIS_API_KEY_HASHES is unset. Existing tests predate the
   gate and call those endpoints without a key, so this autouse fixture
   installs a dependency override that no-ops the gate for every test
   file *except* test_api_auth.py — those tests exercise the real gate
   and need the dependency to fire.

3. Conditional imports for optional dependencies (torch, pandas) to allow
   tests to run even when these heavy dependencies are not installed.
"""

from __future__ import annotations

from collections.abc import Iterator
import importlib.util
import os

import pytest
from fastapi.testclient import TestClient

from src.api.main import app

RUN_TORCH_TESTS = os.getenv("RUN_TORCH_TESTS", "").lower() == "true"
TORCH_AVAILABLE = RUN_TORCH_TESTS and importlib.util.find_spec("torch") is not None

# Skip torch tests if torch is not available
def pytest_collection_modifyitems(config, items):
    """Skip torch-marked tests if torch is not available."""
    if not TORCH_AVAILABLE:
        skip_torch = pytest.mark.skip(reason="PyTorch tests require RUN_TORCH_TESTS=true")
        for item in items:
            if "torch" in item.keywords or item.parent and "torch" in item.parent.name:
                item.add_marker(skip_torch)


# Test files that predate the X-API-Key gate and still call protected endpoints
# without credentials. Only these receive the bypass. Every other file runs with
# the real security dependencies, so a new test cannot silently opt out of RBAC.
# This list should only shrink. Port a file to a real key instead of adding one.
_LEGACY_BYPASS_FILES = frozenset({
    "test_api.py",
    "test_api_hardening.py",
    "test_blast_radius.py",
    "test_case_management.py",
    "test_concurrency.py",
    "test_entity_resolution.py",
    "test_exception_logging.py",
    "test_memory_leak.py",
    "test_threat_hunting.py",
})


@pytest.fixture
def api_client(monkeypatch):
    """FastAPI client that runs lifespan without opening a real socket."""
    monkeypatch.setenv("AEGIS_ENV", "test")
    with TestClient(app) as client:
        yield client
    from src.api.main import state
    state.voice_analyzer = None
    state.mule_scorer = None
    state.honeypot_manager = None
    state.blockchain_manager = None
    state.aegis_oracle = None
    # Also clear from services container to avoid None being cached
    state.services._services.pop("aegis_oracle", None)


@pytest.fixture(autouse=True)
def _bypass_api_key_for_legacy_tests(
    request: pytest.FixtureRequest,
) -> Iterator[None]:
    """Bypass ``require_api_key`` and ``require_role`` for the legacy test files only.

    Files listed in ``_LEGACY_BYPASS_FILES`` predate the gate and call
    protected endpoints without credentials, so they receive dependency
    overrides that let requests pass straight through. Every other file
    runs with the real dependencies, which keeps 401/403/503 behaviour
    observable and stops a new test from opting out of RBAC by default.

    Two sets of overrides are installed:

    1. ``require_api_key`` — the simple gate dependency (backward-compatible).
    2. Every ``require_role(...)`` closure registered on app routes — identified
       by the ``__qualname__`` of the inner ``dependency`` function produced by
       the ``require_role`` factory.  These are collected once from ``app.routes``
       and each is overridden to return ``Role.SUPER_ADMIN`` so that RBAC-gated
       endpoints are reachable in legacy tests without a real API key.

    All overrides are installed per-test and restored on teardown so that
    parallel test runs and pytest-xdist workers do not see leaked state.
    """
    if request.path.name not in _LEGACY_BYPASS_FILES:
        # Real security dependencies run for every file outside the legacy list.
        yield
        return

    from fastapi.routing import APIRoute
    from src.api.security import require_api_key, Role

    # ------------------------------------------------------------------
    # Collect all require_role() dependency closures registered on routes.
    # Each call to require_role() produces a new closure whose __qualname__
    # is "require_role.<locals>.dependency".  We override each one so that
    # RBAC-protected endpoints are accessible without a real key in tests.
    # ------------------------------------------------------------------
    role_dep_fns: list = []
    for route in app.routes:
        if not isinstance(route, APIRoute):
            continue
        for depends_obj in route.dependencies:
            fn = getattr(depends_obj, "dependency", None)
            if fn is None:
                continue
            qualname = getattr(fn, "__qualname__", "")
            if qualname.startswith("require_role.<locals>.dependency"):
                role_dep_fns.append(fn)

    # Save existing overrides so we can restore them cleanly.
    saved_api_key = app.dependency_overrides.get(require_api_key)
    saved_roles = {fn: app.dependency_overrides.get(fn) for fn in role_dep_fns}

    # Install bypasses.
    app.dependency_overrides[require_api_key] = lambda: None
    for fn in role_dep_fns:
        app.dependency_overrides[fn] = lambda: Role.SUPER_ADMIN

    try:
        yield
    finally:
        # Restore require_api_key override.
        if saved_api_key is None:
            app.dependency_overrides.pop(require_api_key, None)
        else:
            app.dependency_overrides[require_api_key] = saved_api_key
        # Restore require_role overrides.
        for fn, saved in saved_roles.items():
            if saved is None:
                app.dependency_overrides.pop(fn, None)
            else:
                app.dependency_overrides[fn] = saved

@pytest.fixture(autouse=True)
def _reset_global_rate_limiter():
    """Reset rate limits before each test."""
    from src.api.validators import reset_rate_limiter
    reset_rate_limiter()

    # Clear slowapi's storage to prevent 429s across test execution
    from src.api.main import limiter
    storages = (
        getattr(limiter, "_storage", None),
        getattr(getattr(limiter, "limiter", None), "storage", None),
    )
    for storage in storages:
        reset = getattr(storage, "reset", None)
        if callable(reset):
            reset()


@pytest.fixture
def anyio_backend():
    return "asyncio"
