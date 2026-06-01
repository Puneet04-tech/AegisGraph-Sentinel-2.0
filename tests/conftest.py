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

import pytest
from fastapi.testclient import TestClient

from src.api.main import app

# Check if torch is available
try:
    import torch
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False

# Skip torch tests if torch is not available
def pytest_collection_modifyitems(config, items):
    """Skip torch-marked tests if torch is not available."""
    if not TORCH_AVAILABLE:
        skip_torch = pytest.mark.skip(reason="PyTorch not installed")
        for item in items:
            if "torch" in item.keywords or item.parent and "torch" in item.parent.name:
                item.add_marker(skip_torch)


# Files whose tests should exercise the real API key gate. The autouse
# bypass below skips these so the gate is active during those tests.
_AUTH_TEST_FILES = frozenset({"test_api_auth.py"})


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


@pytest.fixture(autouse=True)
def _bypass_api_key_for_legacy_tests(
    request: pytest.FixtureRequest,
) -> Iterator[None]:
    """Bypass ``require_api_key`` for every test file outside the auth suite.

    The auth tests in ``_AUTH_TEST_FILES`` need the real dependency to
    fire to verify 401/403/503 behaviour. All other tests predate the
    gate and would otherwise break with 503 (env var unset) or 401
    (header missing). For those tests we install a dependency override
    that lets the request pass straight through.

    The override is installed per-test and removed on teardown so that
    parallel test runs and pytest-xdist workers don't see leaked state.
    """
    if request.path.name in _AUTH_TEST_FILES:
        # Auth-suite test — let the real gate run.
        yield
        return

    from src.api.security import require_api_key

    saved = app.dependency_overrides.get(require_api_key)
    app.dependency_overrides[require_api_key] = lambda: None
    try:
        yield
    finally:
        if saved is None:
            app.dependency_overrides.pop(require_api_key, None)
        else:
            app.dependency_overrides[require_api_key] = saved

@pytest.fixture(autouse=True)
def _reset_global_rate_limiter():
    """Reset rate limits before each test."""
    from src.api.validators import reset_rate_limiter
    reset_rate_limiter()