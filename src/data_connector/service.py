"""Universal Data Connector Service"""
from __future__ import annotations
from typing import Any, Dict, List, Optional
from .models import DataSource, DataConnector, ConnectorMetrics
from .store import get_data_connector_store, DataConnectorStore


class DataConnectorService:
    """Core data connector service."""

    def __init__(self, store: Optional[DataConnectorStore] = None):
        self._store = store or get_data_connector_store()

    def add_source(self, name: str, source_type: str, config: Dict[str, Any]) -> DataSource:
        s = DataSource(name=name, source_type=source_type, config=config)
        return self._store.store_source(s)

    def get_source(self, source_id: str) -> Optional[DataSource]:
        return self._store.get_source(source_id)

    def create_connector(self, name: str, source_types: List[str]) -> DataConnector:
        c = DataConnector(name=name, source_types=source_types)
        return self._store.store_connector(c)

    def get_connector(self, connector_id: str) -> Optional[DataConnector]:
        return self._store.get_connector(connector_id)

    def get_metrics(self) -> ConnectorMetrics:
        m = self._store.get_metrics()
        return ConnectorMetrics(**m)


_service: Optional[DataConnectorService] = None


def get_data_connector_service() -> DataConnectorService:
    global _service
    if _service is None:
        _service = DataConnectorService()
    return _service
