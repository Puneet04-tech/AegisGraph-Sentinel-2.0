"""Universal Data Connector Store"""
from __future__ import annotations
from threading import Lock
from typing import Any, Dict, Optional
from .models import DataSource, DataConnector


class DataConnectorStore:
    """Thread-safe storage."""

    def __init__(self):
        self._lock = Lock()
        self._sources: Dict[str, DataSource] = {}
        self._connectors: Dict[str, DataConnector] = {}

    def store_source(self, s: DataSource) -> DataSource:
        with self._lock:
            self._sources[s.source_id] = s
        return s

    def get_source(self, source_id: str) -> Optional[DataSource]:
        return self._sources.get(source_id)

    def store_connector(self, c: DataConnector) -> DataConnector:
        with self._lock:
            self._connectors[c.connector_id] = c
        return c

    def get_connector(self, connector_id: str) -> Optional[DataConnector]:
        return self._connectors.get(connector_id)

    def get_metrics(self) -> Dict[str, Any]:
        return {
            "total_connectors": len(self._connectors),
            "active_sources": len(self._sources),
        }


_store: Optional[DataConnectorStore] = None


def get_data_connector_store() -> DataConnectorStore:
    global _store
    if _store is None:
        _store = DataConnectorStore()
    return _store
