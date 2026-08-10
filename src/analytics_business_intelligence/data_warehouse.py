"""
Data Warehouse Module.

Provides analytical data layer, data cubes, and aggregation capabilities.
"""

from collections import defaultdict
from statistics import median
from typing import Dict, List, Optional, Any, Tuple
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

    #: Metric values scanned when answering a cube query.
    MAX_SCAN = 10000

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

        # facts used to be random.randint(1000, 100000) -- a cube over an
        # empty warehouse still claimed tens of thousands of rows. It is now
        # the number of recorded values the cube's measures actually cover.
        facts = self._fact_values(measures)

        cube = DataCube(
            name=name,
            dimensions=dimensions,
            measures=measures,
            facts=len(facts),
            aggregations=self._generate_aggregations(dimensions, measures, facts),
        )

        # The cube was previously returned and discarded, so every operation
        # below that takes a cube_name had nothing to resolve it against.
        self._store.store_cube(cube)
        return cube
    
    def _generate_aggregations(
        self,
        dimensions: List[str],
        measures: List[str],
        facts: List[MetricValue],
    ) -> Dict[str, Any]:
        """Pre-compute aggregations from the recorded facts.

        Each value used to be a random.uniform draw, so two cubes over the
        same warehouse disagreed about the same sum.
        """
        aggregations = {}

        for dim in dimensions[:3]:  # Limit combinations
            for measure in measures[:3]:
                relevant = [
                    fact.value for fact in facts
                    if fact.metric_id == measure and dim in fact.dimensions
                ]
                key = f"{dim}_{measure}_sum"
                aggregations[key] = {
                    "type": AggregationType.SUM.value,
                    "dimension": dim,
                    "measure": measure,
                    "value": round(sum(relevant), 4),
                    "fact_count": len(relevant),
                }

        return aggregations

    def _fact_values(self, measures: List[str]) -> List[MetricValue]:
        """Recorded values belonging to any of the cube's measures."""
        facts: List[MetricValue] = []
        for measure in measures:
            facts.extend(
                self._store.get_metric_values(measure, limit=self.MAX_SCAN)
            )
        return facts

    def _cube_facts(self, cube_name: str) -> Tuple[Optional[DataCube], List[MetricValue]]:
        """Resolve a cube by name and load the facts behind it."""
        cube = self._store.get_cube_by_name(cube_name)
        if cube is None:
            logger.warning("Cube '%s' does not exist", cube_name)
            return None, []
        return cube, self._fact_values(cube.measures)

    @staticmethod
    def _matches(fact: MetricValue, filters: Dict[str, Any]) -> bool:
        """Whether a fact satisfies every dimension filter."""
        return all(
            str(fact.dimensions.get(key)) == str(value)
            for key, value in filters.items()
        )

    @staticmethod
    def _aggregate(values: List[float], aggregation: AggregationType) -> float:
        """Apply an aggregation to a list of values."""
        if aggregation == AggregationType.COUNT:
            return len(values)
        if not values:
            return 0.0
        if aggregation == AggregationType.AVG:
            return round(sum(values) / len(values), 4)
        if aggregation == AggregationType.MIN:
            return min(values)
        if aggregation == AggregationType.MAX:
            return max(values)
        if aggregation == AggregationType.MEDIAN:
            return median(values)
        return round(sum(values), 4)
    
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
        
        # The query used to return between 5 and 20 rows of random numbers.
        # cube_name was never resolved, the filters were echoed back into
        # every row unexamined, and the aggregation type only chose which
        # random range to draw from.
        cube, facts = self._cube_facts(cube_name)
        if cube is None:
            return []

        selected_measures = measures or cube.measures
        all_filters = {**(dimensions or {}), **(filters or {})}

        # Group by the cube dimensions that were not pinned by a filter.
        group_by = [dim for dim in cube.dimensions if dim not in all_filters]

        grouped: Dict[tuple, Dict[str, List[float]]] = defaultdict(
            lambda: defaultdict(list)
        )
        for fact in facts:
            if fact.metric_id not in selected_measures:
                continue
            if not self._matches(fact, all_filters):
                continue
            key = tuple(str(fact.dimensions.get(dim)) for dim in group_by)
            grouped[key][fact.metric_id].append(fact.value)

        results = []
        for row_id, (key, measure_values) in enumerate(sorted(grouped.items())):
            row: Dict[str, Any] = {"row_id": row_id}
            row.update(all_filters)
            row.update(dict(zip(group_by, key)))

            for measure in selected_measures:
                row[measure] = self._aggregate(
                    measure_values.get(measure, []), aggregation,
                )

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
        
        cube, facts = self._cube_facts(cube_name)
        if cube is None:
            return {
                "rolled_dimensions": rollup_dimensions,
                "total_records": 0,
                "aggregated_values": {},
                "cube_found": False,
            }

        # Total per dimension, over the facts that actually carry it.
        aggregated_values = {
            dim: round(
                sum(f.value for f in facts if dim in f.dimensions), 4,
            )
            for dim in rollup_dimensions
        }

        return {
            "rolled_dimensions": rollup_dimensions,
            "total_records": len(facts),
            "aggregated_values": aggregated_values,
            "cube_found": True,
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
        
        # Values were literally named "detail_0", "detail_1", ... with random
        # counts attached; the drilldown dimension was never read.
        cube, facts = self._cube_facts(cube_name)
        if cube is None:
            return []

        grouped: Dict[str, List[float]] = defaultdict(list)
        for fact in facts:
            value = fact.dimensions.get(drilldown_dimension)
            if value is None:
                continue
            grouped[str(value)].append(fact.value)

        return [
            {
                "dimension": drilldown_dimension,
                "level": level,
                "value": value,
                "count": len(values),
                "total": round(sum(values), 4),
            }
            for value, values in sorted(grouped.items())
        ]
    
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
        
        cube, facts = self._cube_facts(cube_name)
        if cube is None:
            return {
                "sliced_dimension": dimension,
                "slice_value": value,
                "record_count": 0,
                "total": 0.0,
                "cube_found": False,
            }

        matching = [f for f in facts if self._matches(f, {dimension: value})]

        return {
            "sliced_dimension": dimension,
            "slice_value": value,
            "record_count": len(matching),
            "total": round(sum(f.value for f in matching), 4),
            "cube_found": True,
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
        
        # A metric with nothing recorded used to be filled in with a full
        # period of random points, so an unreported metric was indistinguishable
        # from a healthy one.
        if not values:
            logger.warning(
                "No values recorded for metric '%s' in the last %d day(s)",
                metric_id, period_days,
            )
            return []
        
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