"""
Data Sources Module.

Data source connectors and management.
"""

import random
from typing import Dict, List, Optional, Any, Iterator
from datetime import datetime, timezone
import logging

from .models import (
    DataSource,
    SourceType,
)
from .store import PipelineStore, get_pipeline_store

logger = logging.getLogger(__name__)


class DataSourceConnector:
    """Data Source Connector for managing data sources.
    
    Provides:
        - Source creation
        - Schema discovery
        - Data extraction
        - Incremental loading
    """
    
    def __init__(self, store: Optional[PipelineStore] = None):
        """Initialize the data source connector."""
        self._store = store or get_pipeline_store()
        self._module_id = "data_sources"
    
    def create_source(
        self,
        name: str,
        source_type: SourceType,
        connection_config: Dict[str, Any],
        schema: Dict[str, Any] = None,
        incremental_field: str = None,
    ) -> DataSource:
        """Create a new data source."""
        logger.info(f"Creating data source: {name}")
        
        source = DataSource(
            name=name,
            source_type=source_type,
            connection_config=connection_config,
            schema=schema or {},
            incremental_field=incremental_field,
        )
        
        self._store.store_source(source)
        return source
    
    def get_source(self, source_id: str) -> Optional[DataSource]:
        """Get source by ID."""
        return self._store.get_source(source_id)
    
    def list_sources(
        self,
        source_type: SourceType = None,
    ) -> List[DataSource]:
        """List data sources."""
        sources = self._store.get_all_sources()
        
        if source_type:
            sources = [s for s in sources if s.source_type == source_type]
        
        return sources
    
    def discover_schema(self, source_id: str) -> Dict[str, Any]:
        """Discover schema from data source."""
        source = self._store.get_source(source_id)
        if not source:
            return {"error": "Source not found"}
        
        logger.info(f"Discovering schema for {source.name}")
        
        # Simulate schema discovery based on source type
        if source.source_type == SourceType.DATABASE:
            schema = {
                "tables": [
                    {"name": "transactions", "columns": ["id", "user_id", "amount", "timestamp"]},
                    {"name": "users", "columns": ["id", "name", "email", "created_at"]},
                ]
            }
        elif source.source_type == SourceType.API:
            schema = {
                "endpoints": [
                    {"path": "/alerts", "method": "GET", "fields": ["id", "severity", "message"]},
                    {"path": "/cases", "method": "GET", "fields": ["id", "status", "assigned_to"]},
                ]
            }
        else:
            schema = {"fields": ["field1", "field2", "field3"]}
        
        return schema
    
    def extract_data(
        self,
        source_id: str,
        query: str = None,
        limit: int = 1000,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """Extract data from source."""
        source = self._store.get_source(source_id)
        if not source:
            return []
        
        logger.info(f"Extracting data from {source.name}")
        
        # Simulate data extraction
        records = []
        for i in range(min(limit, 100)):
            record = {
                "id": offset + i,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "data": f"record_{i}",
            }
            records.append(record)
        
        return records
    
    def extract_incremental(
        self,
        source_id: str,
        since: datetime,
    ) -> List[Dict[str, Any]]:
        """Extract incremental data since last sync."""
        source = self._store.get_source(source_id)
        if not source:
            return []
        
        if not source.incremental_field:
            return self.extract_data(source_id)
        
        logger.info(f"Extracting incremental data from {source.name} since {since}")
        
        # Simulate incremental extraction
        return self.extract_data(source_id, limit=50)
    
    def test_connection(self, source_id: str) -> Dict[str, Any]:
        """Test connection to data source."""
        source = self._store.get_source(source_id)
        if not source:
            return {"success": False, "error": "Source not found"}
        
        logger.info(f"Testing connection to {source.name}")
        
        # Simulate connection test
        success = random.random() > 0.1  # 90% success rate
        
        return {
            "success": success,
            "latency_ms": random.uniform(10, 100) if success else 0,
            "message": "Connected successfully" if success else "Connection failed",
        }


# Global singleton
_data_source_connector: Optional[DataSourceConnector] = None


def get_data_source_connector(store: Optional[PipelineStore] = None) -> DataSourceConnector:
    """Get or create the singleton DataSourceConnector instance."""
    global _data_source_connector
    
    if _data_source_connector is None:
        _data_source_connector = DataSourceConnector(store=store)
    return _data_source_connector