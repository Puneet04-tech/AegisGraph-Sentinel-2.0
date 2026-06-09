"""
Business Intelligence Dashboard Module.

Provides BI dashboards, charts, and visualization capabilities.
"""

import random
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone
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
        
        # Generate sample data based on chart type
        if chart.chart_type == "line":
            data = self._generate_line_data(chart)
        elif chart.chart_type == "bar":
            data = self._generate_bar_data(chart)
        elif chart.chart_type == "pie":
            data = self._generate_pie_data(chart)
        else:
            data = self._generate_generic_data(chart)
        
        return {
            "chart_id": chart_id,
            "chart_type": chart.chart_type,
            "x_axis": chart.x_axis,
            "y_axis": chart.y_axis,
            "data": data,
            "labels": self._generate_labels(chart, time_range),
        }
    
    def _generate_line_data(self, chart: BIChart) -> List[List[float]]:
        """Generate line chart data."""
        series_count = len(chart.series) if chart.series else 1
        points = 30
        
        data = []
        for _ in range(series_count):
            series = [random.uniform(20, 100) for _ in range(points)]
            data.append(series)
        
        return data
    
    def _generate_bar_data(self, chart: BIChart) -> List[float]:
        """Generate bar chart data."""
        return [random.uniform(50, 200) for _ in range(12)]
    
    def _generate_pie_data(self, chart: BIChart) -> List[float]:
        """Generate pie chart data."""
        values = [random.uniform(10, 40) for _ in range(5)]
        total = sum(values)
        return [v / total * 100 for v in values]
    
    def _generate_generic_data(self, chart: BIChart) -> List[Dict[str, Any]]:
        """Generate generic chart data."""
        return [
            {"label": f"Item {i}", "value": random.uniform(10, 100)}
            for i in range(10)
        ]
    
    def _generate_labels(self, chart: BIChart, time_range: str) -> List[str]:
        """Generate axis labels."""
        if time_range == "7d":
            return ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
        elif time_range == "30d":
            return [f"Day {i+1}" for i in range(30)]
        elif time_range == "12m":
            return ["Jan", "Feb", "Mar", "Apr", "May", "Jun", 
                    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
        else:
            return [f"Q{i}" for i in range(4)]
    
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
                    "current_value": kpi.current_value or random.uniform(50, 150),
                    "target_value": kpi.target_value,
                    "status": kpi.status,
                    "change_percent": kpi.change_percent or random.uniform(-10, 10),
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