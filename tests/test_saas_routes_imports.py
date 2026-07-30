"""Import and startup coverage for SaaS route packaging."""

from __future__ import annotations

import importlib

import pytest


def test_auth_module_imports():
    module = importlib.import_module("src.saas.routes.auth")
    assert hasattr(module, "get_current_user")
    assert hasattr(module, "auth_service")


def test_saas_routes_package_imports():
    module = importlib.import_module("src.saas.routes")
    assert hasattr(module, "auth_router")
    assert hasattr(module, "organizations_router")
    assert hasattr(module, "users_router")
    assert hasattr(module, "workspaces_router")
    assert hasattr(module, "billing_router")


def test_individual_route_modules_import():
    for module_name in (
        "src.saas.routes.organizations",
        "src.saas.routes.billing",
        "src.saas.routes.users",
        "src.saas.routes.workspaces",
    ):
        module = importlib.import_module(module_name)
        assert module.router is not None


def test_missing_secret_key_raises_descriptive_error(monkeypatch):
    auth_module = importlib.import_module("src.saas.routes.auth")
    from src.config.settings import RuntimeSettings

    monkeypatch.setattr(
        "src.config.settings.get_settings",
        lambda: RuntimeSettings(secret_key=""),
    )

    with pytest.raises(RuntimeError, match="SECRET_KEY is not configured"):
        auth_module._build_auth_service()


def test_auth_service_loads_from_project_configuration():
    auth_module = importlib.import_module("src.saas.routes.auth")
    from src.config.settings import RuntimeSettings
    import src.config.settings as settings_module

    auth_module._AUTH_SERVICE = None
    settings_module.get_settings = lambda: RuntimeSettings(secret_key="project-config-secret")
    service = auth_module._get_auth_service()

    assert service.jwt_secret == "project-config-secret"


def test_application_startup_succeeds():
    from src.api.main import app

    assert app is not None
    assert len(app.routes) > 0


def test_saas_router_registration():
    from src.saas.routes import auth_router, billing_router, organizations_router, users_router, workspaces_router

    assert auth_router.prefix == "/api/v1/auth"
    assert billing_router.prefix == "/api/v1/billing"
    assert organizations_router.prefix == "/api/v1/organizations"
    assert users_router.prefix == "/api/v1/users"
    assert workspaces_router.prefix == "/api/v1/workspaces"
