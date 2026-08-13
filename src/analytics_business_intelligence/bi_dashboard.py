"""
Business Intelligence Dashboard Module.

Provides BI dashboards, charts, and visualization capabilities.
"""

from collections import Counter
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timedelta, timezone
import logging

from .models import (
    BIChart,
    BIDashboard,
)
from .store import AnalyticsStore, get_analytics_store

logger = logging.getLogger(__name__)


class BIDashboardModule:
    """Business Intelligence Dashboard module.
    
    Provides:
        - Dashboard creation and management
        - Chart configuration
        - Real-time data visualization
        - Dashboard sharing
    """

    #: Days covered by each supported time range string.
    TIME_RANGE_DAYS = {"7d": 7, "30d": 30, "90d": 90, "12m": 365}

    #: Window used when a caller passes an unrecognised time range.
    DEFAULT_RANGE_DAYS = 30

    #: Maximum observations plotted on a series.
    MAX_POINTS = 1000

    #: Maximum slices shown on a share-of-total chart.
    MAX_SLICES = 10

    def __init__(self, store: Optional[AnalyticsStore] = None):
        """Initialize the BI dashboard module.
        
        Args:
            store: Optional analytics store
        """
        self._store = store or get_analytics_store()
        self._module_id = "bi_dashboard"
    
    def create_chart(
        self,
        name: str,
        chart_type: str,
        data_source: str,
        x_axis: str,
        y_axis: str,
        series: List[str] = None,
        filters: Dict[str, Any] = None,
    ) -> BIChart:
        """Create a BI chart.
        
        Args:
            name: Chart name
            chart_type: Type (bar, line, pie, etc.)
            data_source: Data source identifier
            x_axis: X-axis field
            y_axis: Y-axis field
            series: Series fields for multi-series charts
            filters: Chart filters
            
        Returns:
            BIChart
        """
        logger.info(f"Creating chart: {name}")
        
        chart = BIChart(
            name=name,
            chart_type=chart_type,
            data_source=data_source,
            x_axis=x_axis,
            y_axis=y_axis,
            series=series or [],
            filters=filters or {},
            visualization_options=self._get_default_options(chart_type),
        )
        
        self._store.store_chart(chart)
        return chart
    
    def _get_default_options(self, chart_type: str) -> Dict[str, Any]:
        """Get default visualization options for chart type."""
        options = {
            "colors": ["#1f77b4", "#ff7f0e", "#2ca02c", "#d62728"],
            "show_legend": True,
            "show_grid": True,
        }
        
        if chart_type == "line":
            options["line_width"] = 2
            options["show_points"] = True
        elif chart_type == "bar":
            options["bar_width"] = 0.8
            options["horizontal"] = False
        elif chart_type == "pie":
            options["show_labels"] = True
            options["donut"] = False
        
        return options
    
    def create_dashboard(
        self,
        name: str,
        description: str,
        chart_ids: List[str] = None,
        kpi_ids: List[str] = None,
        layout: Dict[str, Any] = None,
        refresh_interval: int = 300,
        created_by: str = None,
        is_shared: bool = False,
    ) -> BIDashboard:
        """Create a BI dashboard.
        
        Args:
            name: Dashboard name
            description: Dashboard description
            chart_ids: Chart IDs to include
            kpi_ids: KPI IDs to include
            layout: Dashboard layout configuration
            refresh_interval: Auto-refresh interval in seconds
            created_by: Creator username
            is_shared: Whether dashboard is shared
            
        Returns:
            BIDashboard
        """
        logger.info(f"Creating dashboard: {name}")
        
        # Get charts
        charts = []
        if chart_ids:
            for chart_id in chart_ids:
                chart = self._store.get_chart(chart_id)
                if chart:
                    charts.append(chart)
        
        dashboard = BIDashboard(
            name=name,
            description=description,
            charts=charts,
            kpis=kpi_ids or [],
            layout=layout or self._generate_default_layout(len(charts)),
            refresh_interval=refresh_interval,
            created_by=created_by,
            is_shared=is_shared,
        )
        
        self._store.store_dashboard(dashboard)
        return dashboard
    
    def _generate_default_layout(self, chart_count: int) -> Dict[str, Any]:
        """Generate default dashboard layout."""
        return {
            "type": "grid",
            "columns": 2,
            "rows": (chart_count + 1) // 2,
            "widget_size": {
                "width": 6,
                "height": 4,
            },
        }
    
    def get_chart_data(
        self,
        chart_id: str,
        time_range: str = "30d",
    ) -> Dict[str, Any]:
        """Get chart data for visualization.
        
        Args:
            chart_id: Chart ID
            time_range: Time range for data
            
        Returns:
            Chart data for visualization
        """
        chart = self._store.get_chart(chart_id)
        if not chart:
            return {"error": "Chart not found"}
        
        # Every chart used to be filled with random numbers, and the label
        # list was a fixed string list of a different length again -- a "7d"
        # line chart got 30 random points against 7 weekday labels, so no
        # point on any chart lined up with the axis beneath it.
        start, end = self._window(time_range)

        if chart.chart_type == "pie":
            labels, values = self._share_by_dimension(chart, start, end)
            data = values
        elif chart.chart_type in ("line", "bar"):
            labels, data = self._time_series(chart, start, end)
        else:
            labels, values = self._share_by_dimension(chart, start, end)
            data = [
                {"label": label, "value": value}
                for label, value in zip(labels, values)
            ]

        return {
            "chart_id": chart_id,
            "chart_type": chart.chart_type,
            "x_axis": chart.x_axis,
            "y_axis": chart.y_axis,
            "data": data,
            "labels": labels,
            "period_start": start.isoformat(),
            "period_end": end.isoformat(),
            "insufficient_data": not labels,
        }
    
    def _window(self, time_range: str) -> Tuple[datetime, datetime]:
        """Resolve a time range string to a concrete window."""
        end = datetime.now(timezone.utc)
        days = self.TIME_RANGE_DAYS.get(time_range, self.DEFAULT_RANGE_DAYS)
        return end - timedelta(days=days), end

    def _time_series(
        self,
        chart: BIChart,
        start: datetime,
        end: datetime,
    ) -> Tuple[List[str], List[List[float]]]:
        """Recorded values per series, with labels that match them.

        Each entry in ``chart.series`` names a metric; a chart with no series
        list falls back to its ``data_source``. Labels are the observation
        timestamps of the first series, so labels and points always have the
        same length.
        """
        metric_ids = chart.series or [chart.data_source]

        observations = [
            self._observations(metric_id, start, end)
            for metric_id in metric_ids
        ]
        observations = [series for series in observations if series]

        if not observations:
            logger.warning(
                "No recorded values for chart '%s' between %s and %s",
                chart.name, start, end,
            )
            return [], []

        labels = [timestamp.isoformat() for timestamp, _ in observations[0]]
        data = [[value for _, value in series] for series in observations]
        return labels, data

    def _share_by_dimension(
        self,
        chart: BIChart,
        start: datetime,
        end: datetime,
    ) -> Tuple[List[str], List[float]]:
        """Percentage share per value of the chart's x-axis dimension.

        Shares are computed from the recorded values' dimensions and sum to
        100. Previously five random values were normalised to 100%, which
        looked like a real breakdown of nothing.
        """
        values = self._store.get_metric_values(
            chart.data_source, start_time=start, end_time=end,
        )

        totals: Counter = Counter()
        for value in values:
            key = value.dimensions.get(chart.x_axis)
            if key is None:
                continue
            totals[key] += value.value

        grand_total = sum(totals.values())
        if not grand_total:
            logger.warning(
                "No values carrying dimension '%s' for chart '%s'",
                chart.x_axis, chart.name,
            )
            return [], []

        ranked = totals.most_common(self.MAX_SLICES)
        return (
            [label for label, _ in ranked],
            [round(100 * total / grand_total, 2) for _, total in ranked],
        )

    def _observations(
        self,
        metric_id: str,
        start: datetime,
        end: datetime,
    ) -> List[Tuple[datetime, float]]:
        """Recorded values for a metric in the window, oldest first."""
        values = self._store.get_metric_values(
            metric_id, start_time=start, end_time=end, limit=self.MAX_POINTS,
        )
        return [(v.timestamp, v.value) for v in reversed(values)]

    
    def get_dashboard_data(
        self,
        dashboard_id: str,
        time_range: str = "30d",
    ) -> Dict[str, Any]:
        """Get complete dashboard data for rendering.
        
        Args:
            dashboard_id: Dashboard ID
            time_range: Time range for all charts
            
        Returns:
            Dashboard data
        """
        dashboard = self._store.get_dashboard(dashboard_id)
        if not dashboard:
            return {"error": "Dashboard not found"}
        
        # Get data for each chart
        chart_data = []
        for chart in dashboard.charts:
            data = self.get_chart_data(chart.chart_id, time_range)
            chart_data.append({
                "chart_id": chart.chart_id,
                "name": chart.name,
                "type": chart.chart_type,
                "data": data,
            })
        
        # Get KPI data
        kpi_data = []
        for kpi_id in dashboard.kpis:
            kpi = self._store.get_kpi(kpi_id)
            if kpi:
                kpi_data.append({
                    "kpi_id": kpi.kpi_id,
                    "name": kpi.name,
                    # `or` also replaced a genuine recorded value of 0.0.
                    "current_value": kpi.current_value,
                    "target_value": kpi.target_value,
                    "status": kpi.status,
                    "change_percent": kpi.change_percent,
                })
        
        return {
            "dashboard_id": dashboard.dashboard_id,
            "name": dashboard.name,
            "description": dashboard.description,
            "charts": chart_data,
            "kpis": kpi_data,
            "layout": dashboard.layout,
            "refresh_interval": dashboard.refresh_interval,
            "last_updated": datetime.now(timezone.utc).isoformat(),
        }
    
    def share_dashboard(
        self,
        dashboard_id: str,
        recipients: List[str],
    ) -> bool:
        """Share a dashboard with recipients.
        
        Args:
            dashboard_id: Dashboard ID
            recipients: List of recipient usernames/emails
            
        Returns:
            True if successful
        """
        dashboard = self._store.get_dashboard(dashboard_id)
        if not dashboard:
            return False
        
        dashboard.is_shared = True
        return True
    
    def duplicate_dashboard(
        self,
        dashboard_id: str,
        new_name: str,
        created_by: str,
    ) -> BIDashboard:
        """Duplicate an existing dashboard.
        
        Args:
            dashboard_id: Dashboard to duplicate
            new_name: Name for new dashboard
            created_by: Creator username
            
        Returns:
            New BIDashboard
        """
        original = self._store.get_dashboard(dashboard_id)
        if not original:
            raise ValueError("Dashboard not found")
        
        new_dashboard = BIDashboard(
            name=new_name,
            description=original.description,
            charts=original.charts,
            kpis=original.kpis,
            layout=original.layout.copy(),
            refresh_interval=original.refresh_interval,
            created_by=created_by,
            is_shared=False,
        )
        
        self._store.store_dashboard(new_dashboard)
        return new_dashboard
    
    def get_default_dashboards(self) -> List[Dict[str, Any]]:
        """Get default pre-built dashboards."""
        return [
            {
                "id": "fraud_overview",
                "name": "Fraud Overview",
                "description": "Executive fraud metrics dashboard",
                "charts": ["fraud_trend", "risk_distribution", "detection_rate"],
                "kpis": ["fraud_detection_rate", "false_positive_rate"],
            },
            {
                "id": "operational_metrics",
                "name": "Operational Metrics",
                "description": "Operations performance dashboard",
                "charts": ["investigation_volume", "resolution_time", "analyst_workload"],
                "kpis": ["resolution_time", "cases_closed"],
            },
            {
                "id": "risk_analysis",
                "name": "Risk Analysis",
                "description": "Enterprise risk analysis dashboard",
                "charts": ["risk_trend", "risk_by_segment", "risk_heatmap"],
                "kpis": ["overall_risk_score", "high_risk_entities"],
            },
        ]


# Global singleton
_bi_dashboard: Optional[BIDashboardModule] = None


def get_bi_dashboard_module(store: Optional[AnalyticsStore] = None) -> BIDashboardModule:
    """Get or create the singleton BIDashboardModule instance."""
    global _bi_dashboard
    
    if _bi_dashboard is None:
        _bi_dashboard = BIDashboardModule(store=store)
    return _bi_dashboard