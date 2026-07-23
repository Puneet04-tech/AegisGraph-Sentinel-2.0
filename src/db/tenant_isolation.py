"""Tenant-aware access helpers for Neo4j."""

from __future__ import annotations

import hashlib
import logging
import os
from dataclasses import dataclass
from functools import lru_cache
from typing import Any, Optional

from fastapi import HTTPException, status

from src.api.middleware.multi_tenancy import _validate_tenant_id

logger = logging.getLogger(__name__)


@dataclass
class TenantScopedNeo4jSession:
    """Lightweight wrapper around a Neo4j session bound to a tenant."""

    session: Any
    tenant_id: str
    database: Optional[str] = None

    def run(self, query: str, **parameters: Any) -> Any:
        scoped_parameters = dict(parameters)
        scoped_parameters.setdefault("tenant_id", self.tenant_id)
        return self.session.run(query, **scoped_parameters)

    def __enter__(self) -> "TenantScopedNeo4jSession":
        if hasattr(self.session, "__enter__"):
            self.session.__enter__()
        return self

    def __exit__(self, exc_type, exc, tb) -> Any:
        if hasattr(self.session, "__exit__"):
            return self.session.__exit__(exc_type, exc, tb)
        return None

    def __getattr__(self, name: str) -> Any:
        return getattr(self.session, name)


def _tenant_database_name(tenant_id: str) -> str:
    normalized = _validate_tenant_id(tenant_id)
    suffix = hashlib.sha1(normalized.encode("utf-8")).hexdigest()[:12]
    return f"tenant_{suffix}"


@lru_cache(maxsize=1)
def _get_graph_provider():
    from src.core.providers.neo4j import Neo4jGraphProvider
    from src.config.settings import get_settings

    settings = get_settings()
    database_settings = getattr(settings, "database", settings)
    return Neo4jGraphProvider(
        uri=getattr(database_settings, "neo4j_uri", None),
        user=getattr(database_settings, "neo4j_user", None),
        password=getattr(database_settings, "neo4j_password", None),
        enabled=bool(getattr(database_settings, "neo4j_enabled", False)),
    )


def _resolve_driver():
    provider = _get_graph_provider()
    driver = getattr(provider, "_driver", None)
    if driver is None or not getattr(provider, "is_active", False):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database isolation failure",
        )
    return driver


def get_tenant_db(tenant_id: str) -> TenantScopedNeo4jSession:
    """Return a tenant-aware Neo4j session or transaction wrapper.

    When the deployment uses dedicated Neo4j databases per tenant, this
    selects the per-tenant database name. Otherwise the same driver is used
    and the tenant identifier is injected into every query as a bound
    parameter so downstream query helpers can apply tenant predicates.
    """

    normalized_tenant = _validate_tenant_id(tenant_id)
    driver = _resolve_driver()
    mode = os.getenv("AEGIS_NEO4J_TENANT_MODE", "shared").strip().lower()

    if mode == "database":
        database_name = _tenant_database_name(normalized_tenant)
        session = driver.session(database=database_name)
    else:
        database_name = os.getenv("AEGIS_NEO4J_SHARED_DATABASE") or None
        session = driver.session(database=database_name)

    return TenantScopedNeo4jSession(session=session, tenant_id=normalized_tenant, database=database_name)

