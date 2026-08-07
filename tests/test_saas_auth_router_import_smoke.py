"""
Import smoke tests for :mod:`src.saas.routes.auth`.

Regression guard for import-time failures. The router previously referenced
``AuthAttemptLimiter`` (as an eagerly-evaluated return annotation),
``build_attempt_limiter``, and ``build_rate_limit_error_payload`` without
importing any of them, so ``import src.saas.routes.auth`` raised
``NameError: name 'AuthAttemptLimiter' is not defined`` and the SaaS auth
router could not be mounted.
"""

import importlib
import py_compile
from pathlib import Path


def test_auth_router_module_compiles():
    path = Path("src/saas/routes/auth.py")
    assert path.exists()
    py_compile.compile(str(path), doraise=True)


def test_helpers_resolve_from_their_source_modules():
    from src.saas.auth.attempt_limiter import AuthAttemptLimiter, build_attempt_limiter
    from src.exceptions.error_responses import build_rate_limit_error_payload

    assert callable(build_attempt_limiter)
    assert callable(build_rate_limit_error_payload)
    assert AuthAttemptLimiter is not None


def test_auth_router_module_imports():
    module = importlib.import_module("src.saas.routes.auth")
    assert hasattr(module, "router")
    assert hasattr(module, "auth_service")
