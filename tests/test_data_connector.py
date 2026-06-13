"""Tests for Universal Data Connector"""
import pytest
from src.data_connector.models import DataSource, DataConnector
from src.data_connector.store import get_data_connector_store
from src.data_connector.service import DataConnectorService


class TestDataConnectorModels:
    def test_create_source(self):
        s = DataSource(name="DB1", source_type="postgres")
        assert s.name == "DB1"

    def test_create_connector(self):
        c = DataConnector(name="MySQL Connector", source_types=["mysql"])
        assert c.name == "MySQL Connector"


class TestDataConnectorStore:
    def setup_method(self):
        self.store = get_data_connector_store()

    def test_store_source(self):
        s = DataSource(name="Test", source_type="mongodb")
        self.store.store_source(s)
        assert self.store.get_source(s.source_id) is not None


class TestDataConnectorService:
    def setup_method(self):
        self.service = DataConnectorService()

    def test_add_source(self):
        s = self.service.add_source("DB1", "postgres", {"host": "localhost"})
        assert s.source_id is not None

    def test_create_connector(self):
        c = self.service.create_connector("MySQL Connector", ["mysql"])
        assert c.connector_id is not None

    def test_get_metrics(self):
        self.service.add_source("Test", "mongodb", {})
        m = self.service.get_metrics()
        assert m.active_sources >= 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
