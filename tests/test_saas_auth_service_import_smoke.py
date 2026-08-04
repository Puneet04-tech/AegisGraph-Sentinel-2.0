"""
Import smoke tests for :mod:`src.saas.auth.service`.

Regression guard for import-time failures. The service module previously
referenced ``TokenRevocationStore`` and ``LockoutState`` in eagerly-evaluated
annotations without importing them (raising ``NameError`` at import time), and
``AuthService.__init__`` still assigned the ``revoked_token_ids`` attribute that
is now a read-only property (raising ``AttributeError``). Either failure made
the module — and with it the whole SaaS auth router — unimportable.
"""

import py_compile
from pathlib import Path


def test_service_module_compiles():
    path = Path("src/saas/auth/service.py")
    assert path.exists()
    py_compile.compile(str(path), doraise=True)


def test_service_module_imports():
    import src.saas.auth.service  # noqa: F401


def test_revoked_token_ids_view_wraps_a_token_revocation_store():
    from src.saas.auth.revocation import InMemoryTokenRevocationStore
    from src.saas.auth.service import _RevokedTokenIdsView

    store = InMemoryTokenRevocationStore()
    store.revoke_token("revoked-jti")

    view = _RevokedTokenIdsView(store)
    assert "revoked-jti" in view
    assert "live-jti" not in view
