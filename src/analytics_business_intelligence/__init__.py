"""
Advanced Analytics & Business Intelligence Platform.

A production-grade analytics module for business intelligence, KPI tracking,
trend analysis, and automated reporting.

Modules:
    - Data Warehouse: Analytical data layer and data cubes
    - BI Dashboard: Business intelligence dashboards and visualizations
    - Advanced Analytics: Trend, correlation, segmentation, cohort analysis
    - KPI Engine: KPI tracking and threshold monitoring
    - Report Automation: Scheduled and on-demand reporting
"""

from .models import (
    MetricType,
    AggregationType,
    ReportSchedule,
    DataCube,
    MetricDefinition,
    MetricValue,
    KPI,
    TrendAnalysis,
    CorrelationResult,
    SegmentAnalysis,
    CohortAnalysis,
    BIChart,
    BIDashboard,
    AutomatedReport,
    DataAggregation,
    Insight,
)
from .store import AnalyticsStore, get_analytics_store
from .data_warehouse import DataWarehouseModule, get_data_warehouse_module
from .bi_dashboard import BIDashboardModule, get_bi_dashboard_module
from .advanced_analytics import AdvancedAnalyticsModule, get_advanced_analytics_module
from .kpi_engine import KPIEngineModule, get_kpi_engine_module
from .report_automation import ReportAutomationModule, get_report_automation_module

__all__ = [
    # Enums
    "MetricType",
    "AggregationType",
    "ReportSchedule",
    # Models
    "DataCube",
    "MetricDefinition",
    "MetricValue",
    "KPI",
    "TrendAnalysis",
    "CorrelationResult",
    "SegmentAnalysis",
    "CohortAnalysis",
    "BIChart",
    "BIDashboard",
    "AutomatedReport",
    "DataAggregation",
    "Insight",
    # Store
    "AnalyticsStore",
    "get_analytics_store",
    # Modules
    "DataWarehouseModule",
    "get_data_warehouse_module",
    "BIDashboardModule",
    "get_bi_dashboard_module",
    "AdvancedAnalyticsModule",
    "get_advanced_analytics_module",
    "KPIEngineModule",
    "get_kpi_engine_module",
    "ReportAutomationModule",
    "get_report_automation_module",
]