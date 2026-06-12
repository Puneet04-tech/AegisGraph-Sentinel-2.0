"""
Security Data Fabric Service.

Main service for the AI Security Data Fabric Platform.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid

from .models import (
    AuditEvent,
    DataAsset,
    DataClassification,
    DataDomain,
)
from .store import (
    SecurityDataFabricStore,
    get_fabric_store,
    reset_fabric_store,
)
from .fabric_engine import (
    DataFabricEngine,
    get_fabric_engine,
    reset_fabric_engine,
)
from .schema_registry import (
    SchemaRegistry,
    get_schema_registry,
    reset_schema_registry,
)
from .catalog import (
    CatalogService,
    get_catalog_service,
    reset_catalog_service,
)
from .lineage import (
    LineageEngine,
    get_lineage_engine,
    reset_lineage_engine,
)
from .governance import (
    GovernanceEngine,
    get_governance_engine,
    reset_governance_engine,
)
from .query_engine import (
    QueryEngine,
    get_query_engine,
    reset_query_engine,
)
from .distribution import (
    DistributionEngine,
    get_distribution_engine,
    reset_distribution_engine,
)


class SecurityDataFabricService:
    """Main service for security data fabric."""

    def __init__(self, store: Optional[SecurityDataFabricStore] = None) -> None:
        """Initialize the service."""
        self.store = store or get_fabric_store()
        self.fabric = get_fabric_engine()
        self.registry = get_schema_registry()
        self.catalog = get_catalog_service()
        self.lineage = get_lineage_engine()
        self.governance = get_governance_engine()
        self.query = get_query_engine()
        self.distribution = get_distribution_engine()
        self._audit_log: List[AuditEvent] = []

    async def register(
        self,
        name: str,
        description: str,
        domain: str,
        classification: str = "internal",
        owner: Optional[str] = None,
        tags: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Register a new data asset."""
        result = await self.fabric.register_asset(
            name=name,
            description=description,
            domain=domain,
            classification=classification,
            owner=owner,
            tags=tags,
        )
        
        await self._audit(
            action="register_asset",
            resource_type="asset",
            resource_id=result["asset_id"],
            details={"domain": domain, "classification": classification},
        )
        
        return result

    async def get_catalog(self, domain: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get catalog entries."""
        if domain:
            return self.catalog.get_by_domain(domain)
        entries = list(self.store._catalog.values())
        return [self.catalog._entry_to_dict(e) for e in entries]

    async def get_assets(
        self,
        domain: Optional[str] = None,
        classification: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Get data assets."""
        return self.fabric.get_assets(domain=domain, classification=classification)

    async def query(
        self,
        query_string: str,
        domains: Optional[List[str]] = None,
        limit: int = 100,
    ) -> Dict[str, Any]:
        """Execute a federated query."""
        result = await self.query.execute_query(
            query_string=query_string,
            domains=domains,
            limit=limit,
        )
        
        return {
            "result_id": result.result_id,
            "query_id": result.query_id,
            "data": result.data,
            "row_count": result.row_count,
            "execution_time_ms": result.execution_time_ms,
            "sources_queried": result.sources_queried,
        }

    async def get_lineage(self, asset_id: str, direction: str = "both") -> Dict[str, Any]:
        """Get lineage for an asset."""
        if direction == "upstream":
            return {"asset_id": asset_id, "upstream": self.lineage.get_upstream_lineage(asset_id)}
        elif direction == "downstream":
            return {"asset_id": asset_id, "downstream": self.lineage.get_downstream_lineage(asset_id)}
        else:
            return self.lineage.get_full_lineage_graph(asset_id)

    async def get_governance(self) -> Dict[str, Any]:
        """Get governance status."""
        return self.governance.get_governance_report()

    async def distribute(
        self,
        asset_id: str,
        target_ids: List[str],
    ) -> Dict[str, Any]:
        """Distribute data to targets."""
        result = self.distribution.distribute(asset_id, target_ids)
        
        await self._audit(
            action="distribute",
            resource_type="asset",
            resource_id=asset_id,
            details={"target_count": len(target_ids)},
        )
        
        return result

    async def get_quality(self, asset_id: str) -> Dict[str, Any]:
        """Get quality report for an asset."""
        report = self.store.get_latest_quality_report(asset_id)
        if not report:
            return {"asset_id": asset_id, "status": "no_report"}
        
        return {
            "report_id": report.report_id,
            "asset_id": report.asset_id,
            "overall_score": report.overall_score,
            "completeness": report.completeness_score,
            "accuracy": report.accuracy_score,
            "issues": report.issues,
            "recommendations": report.recommendations,
        }

    async def get_audit(
        self,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Get audit log."""
        return [
            {
                "event_id": e.event_id,
                "timestamp": e.timestamp.isoformat(),
                "user_id": e.user_id,
                "action": e.action,
                "resource_type": e.resource_type,
                "resource_id": e.resource_id,
                "success": e.success,
            }
            for e in self._audit_log[-limit:]
        ]

    async def _audit(
        self,
        action: str,
        resource_type: str,
        resource_id: str,
        details: Dict[str, Any],
    ) -> None:
        """Log an audit entry."""
        entry = AuditEvent(
            event_id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc),
            user_id="system",
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            details=details,
        )
        self._audit_log.append(entry)

    def get_dashboard(self) -> Dict[str, Any]:
        """Get service dashboard."""
        return self.fabric.get_fabric_dashboard()


# Singleton instance
_service: Optional[SecurityDataFabricService] = None


def get_security_data_fabric_service() -> SecurityDataFabricService:
    """Get the global service instance."""
    global _service
    if _service is None:
        _service = SecurityDataFabricService()
    return _service


def reset_security_data_fabric_service() -> None:
    """Reset the global service."""
    global _service
    _service = None
    reset_fabric_store()
    reset_fabric_engine()
    reset_schema_registry()
    reset_catalog_service()
    reset_lineage_engine()
    reset_governance_engine()
    reset_query_engine()
    reset_distribution_engine()