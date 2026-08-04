"""
Constructor wiring tests for :class:`src.saas.auth.service.AuthService`.

Regression guard for issue #2862: the constructor previously accepted no
``attempt_limiter``/``revocation_store`` parameters (so the router's
``attempt_limiter=_build_attempt_limiter()`` call raised TypeError) and never
initialized either attribute (so the first login/MFA/refresh operation crashed
with AttributeError).
"""

from src.saas.auth.attempt_limiter import AuthAttemptLimiter, InMemoryAttemptLimiter
from src.saas.auth.revocation import (
    InMemoryTokenRevocationStore,
    TokenRevocationStore,
)
from src.saas.auth.service import AuthService


def _service(**kwargs):
    return AuthService({"jwt_secret": "test-secret-only"}, **kwargs)


def test_default_constructor_initializes_working_dependencies():
    svc = _service()

    assert isinstance(svc.attempt_limiter, AuthAttemptLimiter)
    assert isinstance(svc.attempt_limiter, InMemoryAttemptLimiter)
    assert isinstance(svc.revocation_store, TokenRevocationStore)
    assert isinstance(svc.revocation_store, InMemoryTokenRevocationStore)


def test_constructor_accepts_injected_attempt_limiter():
    limiter = InMemoryAttemptLimiter()
    svc = _service(attempt_limiter=limiter)

    assert svc.attempt_limiter is limiter


def test_constructor_accepts_injected_revocation_store():
    store = InMemoryTokenRevocationStore()
    svc = _service(revocation_store=store)

    assert svc.revocation_store is store


def test_constructor_accepts_both_injected_dependencies():
    limiter = InMemoryAttemptLimiter()
    store = InMemoryTokenRevocationStore()
    svc = _service(attempt_limiter=limiter, revocation_store=store)

    assert svc.attempt_limiter is limiter
    assert svc.revocation_store is store


def test_router_builds_service_with_wired_dependencies(monkeypatch):
    import src.saas.routes.auth as routes
    from src.config.settings import RuntimeSettings

    monkeypatch.setattr(
        "src.config.settings.get_settings",
        lambda: RuntimeSettings(secret_key="router-test-secret"),
    )

    svc = routes._build_auth_service()

    assert svc.jwt_secret == "router-test-secret"
    assert isinstance(svc.attempt_limiter, AuthAttemptLimiter)
    assert isinstance(svc.revocation_store, TokenRevocationStore)
