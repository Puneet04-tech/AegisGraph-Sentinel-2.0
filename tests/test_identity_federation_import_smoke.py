"""
Import/compile smoke tests for the identity federation package.

Regression guard for import-time breakage. The OAuthProvider refresh-token
grant previously declared duplicate ``client_id``/``client_secret`` parameters,
which raised ``SyntaxError: duplicate argument 'client_id'`` at import time and
made the whole ``src.identity_federation`` package unusable.
"""

import inspect
import py_compile
from pathlib import Path


def test_oauth_provider_module_compiles():
    module_path = Path("src/identity_federation/oauth_provider.py")
    assert module_path.exists()
    py_compile.compile(str(module_path), doraise=True)


def test_identity_federation_package_imports():
    import src.identity_federation  # noqa: F401
    from src.identity_federation.oauth_provider import OAuthProvider

    assert OAuthProvider is not None


def test_refresh_token_grant_signature_has_no_duplicate_params():
    from src.identity_federation.oauth_provider import OAuthProvider

    parameters = list(inspect.signature(OAuthProvider._refresh_token_grant).parameters)
    assert len(parameters) == len(set(parameters)), (
        f"duplicate parameter names in _refresh_token_grant: {parameters}"
    )
    assert {"refresh_token", "client_id", "client_secret", "scope"} <= set(parameters)
