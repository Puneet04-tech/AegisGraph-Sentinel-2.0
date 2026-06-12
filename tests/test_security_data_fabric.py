"""
Tests for AI Security Data Fabric Platform.
"""

import asyncio
import pytest

from src.security_data_fabric import (
    DataAsset,
    DataCatalogEntry,
    DataClassification,
    DataDomain,
    DataPolicy,
    DataSchema,
    LineageRecord,
    LineageType,
    SecurityDataFabricStore,
    get_fabric_store,
    reset_fabric_store,
    DataFabricEngine,
    SchemaRegistry,
    CatalogService,
    LineageEngine,
    GovernanceEngine,
    QueryEngine,
    DistributionEngine,
    SecurityDataFabricService,
)


class TestModels:
    """Test data models."""

    def test_data_asset_creation(self):
        """Test data asset creation."""
        asset = DataAsset(
            asset_id="asset-1",
            name="Transaction Data",
            description="Fraud transaction records",
            domain=DataDomain.FRAUD,
        )
        assert asset.asset_id == "asset-1"
        assert asset.domain == DataDomain.FRAUD
        assert asset.classification == DataClassification.INTERNAL

    def test_data_schema_creation(self):
        """Test data schema creation."""
        schema = DataSchema(
            schema_id="schema-1",
            name="Transaction Schema",
            version="1.0",
            domain=DataDomain.FRAUD,
            fields=[{"name": "amount", "type": "float"}],
        )
        assert schema.schema_id == "schema-1"
        assert len(schema.fields) == 1

    def test_lineage_record_creation(self):
        """Test lineage record creation."""
        record = LineageRecord(
            record_id="lin-1",
            source_asset_id="source-1",
            target_asset_id="target-1",
            lineage_type=LineageType.DERIVED_FROM,
        )
        assert record.lineage_type == LineageType.DERIVED_FROM


class TestStore:
    """Test data fabric store."""

    def setup_method(self):
        """Reset store before each test."""
        reset_fabric_store()
        self.store = get_fabric_store()

    def test_register_asset(self):
        """Test registering an asset."""
        asset = DataAsset(
            asset_id="asset-1",
            name="Test Asset",
            description="Test",
            domain=DataDomain.FRAUD,
        )
        self.store.register_asset(asset)
        
        retrieved = self.store.get_asset("asset-1")
        assert retrieved is not None
        assert retrieved.name == "Test Asset"

    def test_get_assets_by_domain(self):
        """Test getting assets by domain."""
        asset = DataAsset(
            asset_id="asset-1",
            name="Fraud Data",
            description="Test",
            domain=DataDomain.FRAUD,
        )
        self.store.register_asset(asset)
        
        assets = self.store.get_assets_by_domain(DataDomain.FRAUD)
        assert len(assets) == 1


class TestFabricEngine:
    """Test data fabric engine."""

    def setup_method(self):
        """Reset store before each test."""
        reset_fabric_store()
        self.engine = DataFabricEngine()

    def test_register_asset(self):
        """Test registering an asset via engine."""
        result = asyncio.run(self.engine.register_asset(
            name="Transaction Data",
            description="Fraud transactions",
            domain="fraud",
        ))
        
        assert "asset_id" in result
        assert result["status"] == "registered"

    def test_get_asset(self):
        """Test getting an asset."""
        asyncio.run(self.engine.register_asset(
            name="Test Asset",
            description="Test",
            domain="fraud",
        ))
        
        assets = self.engine.get_assets()
        assert len(assets) > 0


class TestSchemaRegistry:
    """Test schema registry."""

    def setup_method(self):
        """Reset store before each test."""
        reset_fabric_store()
        self.registry = SchemaRegistry()

    def test_register_schema(self):
        """Test registering a schema."""
        schema = self.registry.register_schema(
            name="Transaction Schema",
            version="1.0",
            domain="fraud",
            fields=[{"name": "id", "type": "string"}],
        )
        
        assert schema.schema_id is not None
        assert schema.name == "Transaction Schema"

    def test_validate_schema(self):
        """Test schema validation."""
        schema = self.registry.register_schema(
            name="Test Schema",
            version="1.0",
            domain="fraud",
            fields=[{"name": "id", "type": "string", "required": True}],
        )
        
        result = self.registry.validate_schema(
            schema.schema_id,
            {"id": "123"},
        )
        
        assert result["valid"] is True


class TestCatalogService:
    """Test catalog service."""

    def setup_method(self):
        """Reset store before each test."""
        reset_fabric_store()
        self.catalog = CatalogService()

    def test_add_entry(self):
        """Test adding a catalog entry."""
        entry = self.catalog.add_entry(
            asset_id="asset-1",
            schema_id="schema-1",
            domain="fraud",
            classification="internal",
            description="Test asset",
        )
        
        assert entry.entry_id is not None

    def test_search(self):
        """Test catalog search."""
        self.catalog.add_entry(
            asset_id="asset-1",
            schema_id="schema-1",
            domain="fraud",
            classification="internal",
            description="Transaction fraud data",
        )
        
        results = self.catalog.search("fraud")
        assert len(results) >= 1


class TestLineageEngine:
    """Test lineage engine."""

    def setup_method(self):
        """Reset store before each test."""
        reset_fabric_store()
        self.lineage = LineageEngine()

    def test_record_lineage(self):
        """Test recording lineage."""
        record = self.lineage.record_lineage(
            source_asset_id="source-1",
            target_asset_id="target-1",
            lineage_type="derived_from",
        )
        
        assert record.record_id is not None

    def test_get_upstream_lineage(self):
        """Test getting upstream lineage."""
        self.lineage.record_lineage(
            source_asset_id="source-1",
            target_asset_id="target-1",
            lineage_type="derived_from",
        )
        
        upstream = self.lineage.get_upstream_lineage("target-1")
        assert len(upstream) >= 1


class TestGovernanceEngine:
    """Test governance engine."""

    def setup_method(self):
        """Reset store before each test."""
        reset_fabric_store()
        self.governance = GovernanceEngine()

    def test_create_policy(self):
        """Test creating a policy."""
        policy = self.governance.create_policy(
            name="Fraud Data Policy",
            description="Policy for fraud data",
            domain="fraud",
            classification="confidential",
            rules=[{"action": "read", "allow": True}],
        )
        
        assert policy.policy_id is not None

    def test_validate_access(self):
        """Test access validation."""
        self.governance.create_policy(
            name="Test Policy",
            description="Test",
            domain="fraud",
            classification="restricted",
            rules=[{"action": "delete", "deny": True}],
        )
        
        result = self.governance.validate_access(
            user_id="user-1",
            asset_domain="fraud",
            asset_classification="restricted",
            action="delete",
        )
        
        assert result["allowed"] is False


class TestQueryEngine:
    """Test query engine."""

    def setup_method(self):
        """Reset store before each test."""
        reset_fabric_store()
        self.engine = QueryEngine()
        
        self.asset = DataAsset(
            asset_id="asset-1",
            name="Transaction Data",
            description="Fraud transaction records",
            domain=DataDomain.FRAUD,
        )
        get_fabric_store().register_asset(self.asset)

    def test_execute_query(self):
        """Test executing a query."""
        result = asyncio.run(self.engine.execute_query("transaction"))
        
        assert result.result_id is not None
        assert result.row_count >= 1


class TestDistributionEngine:
    """Test distribution engine."""

    def setup_method(self):
        """Reset store before each test."""
        reset_fabric_store()
        self.distribution = DistributionEngine()

    def test_register_target(self):
        """Test registering a target."""
        target = self.distribution.register_target(
            target_id="target-1",
            target_type="api",
            endpoint="https://api.example.com",
            capabilities=["push", "pull"],
        )
        
        assert target["target_id"] == "target-1"


class TestSecurityDataFabricService:
    """Test main service."""

    def setup_method(self):
        """Reset store before each test."""
        reset_fabric_store()
        self.service = SecurityDataFabricService()

    def test_register(self):
        """Test registering an asset."""
        result = asyncio.run(self.service.register(
            name="Test Asset",
            description="Test data asset",
            domain="fraud",
        ))
        
        assert "asset_id" in result

    def test_get_assets(self):
        """Test getting assets."""
        asyncio.run(self.service.register(
            name="Test Asset",
            description="Test",
            domain="fraud",
        ))
        
        assets = asyncio.run(self.service.get_assets())
        assert isinstance(assets, list)

    def test_get_dashboard(self):
        """Test getting dashboard."""
        result = self.service.get_dashboard()
        
        assert "total_assets" in result


if __name__ == "__main__":
    pytest.main([__file__, "-v"])