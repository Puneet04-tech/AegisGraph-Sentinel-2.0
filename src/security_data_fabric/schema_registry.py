"""
Schema Registry.

Registry for data schemas with versioning and validation.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid

from .models import DataClassification, DataDomain, DataSchema
from .store import SecurityDataFabricStore, get_fabric_store


class SchemaRegistry:
    """Registry for managing data schemas."""

    def __init__(self, store: Optional[SecurityDataFabricStore] = None) -> None:
        """Initialize the registry."""
        self.store = store or get_fabric_store()

    def register_schema(
        self,
        name: str,
        version: str,
        domain: str,
        fields: List[Dict[str, Any]],
        classification: str = "internal",
    ) -> DataSchema:
        """Register a new schema."""
        schema_id = f"schema-{uuid.uuid4().hex[:12]}"
        
        schema = DataSchema(
            schema_id=schema_id,
            name=name,
            version=version,
            domain=DataDomain(domain),
            fields=fields,
            classification=DataClassification(classification),
        )
        
        self.store.register_schema(schema)
        return schema

    def get_schema(self, schema_id: str) -> Optional[DataSchema]:
        """Get a schema by ID."""
        return self.store.get_schema(schema_id)

    def get_schema_by_name(self, name: str) -> List[DataSchema]:
        """Get all versions of a schema by name."""
        return [s for s in self.store._schemas.values() if s.name == name]

    def get_latest_version(self, name: str) -> Optional[DataSchema]:
        """Get the latest version of a schema."""
        versions = self.get_schema_by_name(name)
        if not versions:
            return None
        
        return max(versions, key=lambda s: s.version)

    def validate_schema(self, schema_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Validate data against a schema."""
        schema = self.store.get_schema(schema_id)
        if not schema:
            return {"valid": False, "errors": ["Schema not found"]}
        
        errors = []
        field_names = {f["name"] for f in schema.fields}
        
        for field_name in data.keys():
            if field_name not in field_names:
                errors.append(f"Unknown field: {field_name}")
        
        required_fields = {f["name"] for f in schema.fields if f.get("required", False)}
        missing = required_fields - set(data.keys())
        if missing:
            errors.append(f"Missing required fields: {', '.join(missing)}")
        
        return {
            "valid": len(errors) == 0,
            "errors": errors,
            "schema_id": schema_id,
        }

    def get_schemas_by_domain(self, domain: DataDomain) -> List[DataSchema]:
        """Get all schemas for a domain."""
        return [s for s in self.store._schemas.values() if s.domain == domain]

    def evolve_schema(
        self,
        schema_id: str,
        new_fields: List[Dict[str, Any]],
    ) -> Optional[DataSchema]:
        """Evolve a schema by adding new fields."""
        schema = self.store.get_schema(schema_id)
        if not schema:
            return None
        
        existing_names = {f["name"] for f in schema.fields}
        for field in new_fields:
            if field["name"] not in existing_names:
                schema.fields.append(field)
        
        schema.updated_at = datetime.now(timezone.utc)
        return schema


# Singleton instance
_registry: Optional[SchemaRegistry] = None


def get_schema_registry() -> SchemaRegistry:
    """Get the global registry instance."""
    global _registry
    if _registry is None:
        _registry = SchemaRegistry()
    return _registry


def reset_schema_registry() -> None:
    """Reset the global registry."""
    global _registry
    _registry = None