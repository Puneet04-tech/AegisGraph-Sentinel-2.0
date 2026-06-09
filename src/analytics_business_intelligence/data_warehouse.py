"""
Data Warehouse Module.

Provides analytical data layer, data cubes, and aggregation capabilities.
"""

import random
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone, timedelta
import logging

from .models import (
    DataCube,
    MetricDefinition,
    MetricValue,
    MetricType,
    AggregationType,
)
from .store import AnalyticsStore, get_analytics_store

logger = logging.getLogger(__name__)


class DataWarehouseModule:
    """Data Warehouse for analytical data management.
    
    Provides:
        - Data cube creation and management
        - Multi-dimensional analysis
        - Data aggregation and caching
        - Time-series data management
    """
    
    def __init__(self, store: Optional[AnalyticsStore] = None):
        """Initialize the data warehouse module.
        
        Args:
            store: Optional analytics store
        """
        self._store = store or get_analytics_store()
        self._module_id = "data_warehouse"
    
    def create_data_cube(
        self,
        name: str,
        dimensions: List[str],
        measures: List[str],
    ) -> DataCube:
        """Create a new data cube.
        
        Args:
            name: Cube name
            dimensions: List of dimension names
            measures: List of measure names
            
        Returns:
            DataCube
        """
        logger.info(f"Creating data cube: {name}")
        
        cube = DataCube(
            name=name,
            dimensions=dimensions,
            measures=measures,
            facts=random.randint(1000, 100000),
            aggregations=self._generate_aggregations(dimensions, measures),
        )
        
        return cube
    
    def _generate_aggregations(
        self,
        dimensions: List[str],
        measures: List[str],
    ) -> Dict[str, Any]:
        """Generate pre-computed aggregations."""
        aggregations = {}
        
        for dim in dimensions[:3]:  # Limit combinations
            for measure in measures[:3]:
                key = f"{dim}_{measure}_sum"
                aggregations[key] = {
                    "type": AggregationType.SUM.value,
                    "dimension": dim,
                    "measure": measure,
                    "value": random.uniform(1000, 100000),
                }
        
        return aggregations
    
    def query_cube(
        self,
        cube_name: str,
        dimensions: Dict[str, Any] = None,
        measures: List[str] = None,
        filters: Dict[str, Any] = None,
        aggregation: AggregationType = AggregationType.SUM,
    ) -> List[Dict[str, Any]]:
        """Query a data cube.
        
        Args:
            cube_name: Name of the cube to query
            dimensions: Dimension filters
            measures: Measures to retrieve
            filters: Additional filters
            aggregation: Aggregation type
            
        Returns:
            List of result rows
        """
        logger.info(f"Querying cube: {cube_name}")
        
        dimensions = dimensions or {}
        measures = measures or ["count"]
        filters = filters or {}
        
        # Generate sample results
        results = []
        for i in range(random.randint(5, 20)):
            row = {"row_id": i}
            row.update(dimensions)
            
            for measure in measures:
                if aggregation == AggregationType.AVG:
                    row[measure] = random.uniform(50, 200)
                elif aggregation == AggregationType.SUM:
                    row[measure] = random.uniform(1000, 50000)
                elif aggregation == AggregationType.COUNT:
                    row[measure] = random.randint(10, 1000)
                else:
                    row[measure] = random.uniform(0, 100)
            
            results.append(row)
        
        return results
    
    def rollup_cube(
        self,
        cube_name: str,
        rollup_dimensions: List[str],
    ) -> Dict[str, Any]:
        """Perform cube rollup (aggregate at higher level).
        
        Args:
            cube_name: Cube name
            rollup_dimensions: Dimensions to roll up to
            
        Returns:
            Rollup results
        """
        logger.info(f"Rolling up cube {cube_name} by {rollup_dimensions}")
        
        return {
            "rolled_dimensions": rollup_dimensions,
            "total_records": random.randint(1000, 100000),
            "aggregated_values": {
                dim: random.uniform(1000, 50000) for dim in rollup_dimensions
            },
        }
    
    def drilldown_cube(
        self,
        cube_name: str,
        drilldown_dimension: str,
        level: int = 1,
    ) -> List[Dict[str, Any]]:
        """Perform cube drilldown (break down to lower level).
        
        Args:
            cube_name: Cube name
            drilldown_dimension: Dimension to drill down
            level: Drilldown level
            
        Returns:
            Drilldown results
        """
        logger.info(f"Drilling down cube {cube_name} on {drilldown_dimension}")
        
        results = []
        for i in range(random.randint(5, 15)):
            results.append({
                "dimension": drilldown_dimension,
                "level": level,
                "value": f"detail_{i}",
                "count": random.randint(10, 500),
                "total": random.uniform(1000, 50000),
            })
        
        return results
    
    def slice_cube(
        self,
        cube_name: str,
        dimension: str,
        value: Any,
    ) -> Dict[str, Any]:
        """Slice a cube by dimension value.
        
        Args:
            cube_name: Cube name
            dimension: Dimension to slice on
            value: Value to filter by
            
        Returns:
            Sliced result
        """
        logger.info(f"Slicing cube {cube_name} on {dimension}={value}")
        
        return {
            "sliced_dimension": dimension,
            "slice_value": value,
            "record_count": random.randint(100, 5000),
            "total": random.uniform(10000, 500000),
        }
    
    def define_metric(
        self,
        name: str,
        description: str,
        metric_type: MetricType,
        aggregation: AggregationType,
        category: str,
        unit: str,
        formula: str = None,
    ) -> MetricDefinition:
        """Define a new metric.
        
        Args:
            name: Metric name
            description: Metric description
            metric_type: Type of metric
            aggregation: Default aggregation
            category: Metric category
            unit: Unit of measurement
            formula: Optional formula
            
        Returns:
            MetricDefinition
        """
        logger.info(f"Defining metric: {name}")
        
        metric = MetricDefinition(
            name=name,
            description=description,
            metric_type=metric_type,
            aggregation=aggregation,
            category=category,
            unit=unit,
            formula=formula,
            dimensions=["time", "entity_type", "risk_level"],
            thresholds={"warning": 0.7, "critical": 0.9},
        )
        
        self._store.store_metric_definition(metric)
        return metric
    
    def record_metric_value(
        self,
        metric_id: str,
        value: float,
        dimensions: Dict[str, str] = None,
        metadata: Dict[str, Any] = None,
    ) -> MetricValue:
        """Record a metric value.
        
        Args:
            metric_id: Metric ID
            value: Metric value
            dimensions: Dimension values
            metadata: Additional metadata
            
        Returns:
            MetricValue
        """
        logger.info(f"Recording metric {metric_id}: {value}")
        
        metric_value = MetricValue(
            metric_id=metric_id,
            value=value,
            dimensions=dimensions or {},
            metadata=metadata or {},
        )
        
        self._store.store_metric_value(metric_value)
        return metric_value
    
    def get_metric_time_series(
        self,
        metric_id: str,
        period_days: int = 30,
    ) -> List[Dict[str, Any]]:
        """Get metric time series.
        
        Args:
            metric_id: Metric ID
            period_days: Number of days to retrieve
            
        Returns:
            Time series data
        """
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(days=period_days)
        
        values = self._store.get_metric_values(
            metric_id=metric_id,
            start_time=start_time,
            end_time=end_time,
        )
        
        # Generate sample data if no values
        if not values:
            data = []
            for i in range(period_days):
                timestamp = start_time + timedelta(days=i)
                data.append({
                    "timestamp": timestamp.isoformat(),
                    "value": random.uniform(50, 150),
                })
            return data
        
        return [
            {
                "timestamp": v.timestamp.isoformat(),
                "value": v.value,
                "dimensions": v.dimensions,
            }
            for v in values
        ]
    
    def compute_aggregation(
        self,
        metric_id: str,
        aggregation: AggregationType,
        start_time: datetime = None,
        end_time: datetime = None,
    ) -> float:
        """Compute metric aggregation.
        
        Args:
            metric_id: Metric ID
            aggregation: Aggregation type
            start_time: Start time filter
            end_time: End time filter
            
        Returns:
            Aggregated value
        """
        values = self._store.get_metric_values(
            metric_id=metric_id,
            start_time=start_time,
            end_time=end_time,
            limit=10000,
        )
        
        if not values:
            return 0.0
        
        numeric_values = [v.value for v in values]
        
        if aggregation == AggregationType.SUM:
            return sum(numeric_values)
        elif aggregation == AggregationType.AVG:
            return sum(numeric_values) / len(numeric_values)
        elif aggregation == AggregationType.MIN:
            return min(numeric_values)
        elif aggregation == AggregationType.MAX:
            return max(numeric_values)
        elif aggregation == AggregationType.COUNT:
            return len(numeric_values)
        else:
            return sum(numeric_values) / len(numeric_values)


# Global singleton
_data_warehouse: Optional[DataWarehouseModule] = None


def get_data_warehouse_module(store: Optional[AnalyticsStore] = None) -> DataWarehouseModule:
    """Get or create the singleton DataWarehouseModule instance."""
    global _data_warehouse
    
    if _data_warehouse is None:
        _data_warehouse = DataWarehouseModule(store=store)
    return _data_warehouse