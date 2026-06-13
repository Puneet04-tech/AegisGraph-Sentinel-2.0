"""
Analytics Business Intelligence Storage Engine.

Thread-safe storage for analytics data, dashboards, KPIs, and reports.
"""

from collections import OrderedDict
from threading import Lock
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone
import logging

from .models import (
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

logger = logging.getLogger(__name__)


class AnalyticsStore:
    """Thread-safe storage for analytics and BI data.
    
    Provides:
        - O(1) lookup by ID
        - LRU cache for bounded memory
        - Thread-safe operations
        - Report management
    """
    
    def __init__(self, max_size: int = 5000):
        """Initialize the analytics store.
        
        Args:
            max_size: Maximum records per category
        """
        self._max_size = max_size
        self._lock = Lock()
        
        # Metric definitions
        self._metric_definitions: Dict[str, MetricDefinition] = {}
        
        # Metric values (time-series)
        self._metric_values: OrderedDict[str, MetricValue] = OrderedDict()
        
        # KPIs
        self._kpis: Dict[str, KPI] = {}
        
        # Trend analyses
        self._trends: Dict[str, TrendAnalysis] = {}
        
        # Correlations
        self._correlations: Dict[str, CorrelationResult] = {}
        
        # Segment analyses
        self._segments: Dict[str, SegmentAnalysis] = {}
        
        # Cohort analyses
        self._cohorts: Dict[str, CohortAnalysis] = {}
        
        # Charts
        self._charts: Dict[str, BIChart] = {}
        
        # Dashboards
        self._dashboards: Dict[str, BIDashboard] = {}
        
        # Automated reports
        self._reports: OrderedDict[str, AutomatedReport] = OrderedDict()
        
        # Data aggregations
        self._aggregations: Dict[str, DataAggregation] = {}
        
        # Insights
        self._insights: OrderedDict[str, Insight] = OrderedDict()
        
        # Initialize default KPIs
        self._initialize_default_kpis()
    
    def _initialize_default_kpis(self):
        """Initialize default KPIs."""
        default_kpis = [
            KPI(
                name="Fraud Detection Rate",
                description="Percentage of fraud detected",
                metric_id="fraud_detection_rate",
                target_value=95.0,
                warning_threshold=90.0,
                critical_threshold=85.0,
                current_value=92.5,
                status="ON_TARGET",
                category="Fraud",
            ),
            KPI(
                name="False Positive Rate",
                description="Percentage of false alerts",
                metric_id="false_positive_rate",
                target_value=5.0,
                warning_threshold=8.0,
                critical_threshold=10.0,
                current_value=7.0,
                status="WARNING",
                category="Quality",
            ),
            KPI(
                name="Investigation Resolution Time",
                description="Average hours to resolve",
                metric_id="resolution_time",
                target_value=24.0,
                warning_threshold=36.0,
                critical_threshold=48.0,
                current_value=28.0,
                status="ON_TARGET",
                category="Efficiency",
            ),
        ]
        
        for kpi in default_kpis:
            self._kpis[kpi.kpi_id] = kpi
    
    # Metric Definition Methods
    def store_metric_definition(self, metric: MetricDefinition) -> MetricDefinition:
        """Store a metric definition."""
        with self._lock:
            self._metric_definitions[metric.metric_id] = metric
        return metric
    
    def get_metric_definition(self, metric_id: str) -> Optional[MetricDefinition]:
        """Get metric definition by ID."""
        return self._metric_definitions.get(metric_id)
    
    def get_all_metric_definitions(self) -> List[MetricDefinition]:
        """Get all metric definitions."""
        return list(self._metric_definitions.values())
    
    # Metric Value Methods
    def store_metric_value(self, value: MetricValue) -> MetricValue:
        """Store a metric value."""
        with self._lock:
            self._metric_values[value.value_id] = value
            self._metric_values.move_to_end(value.value_id)
            
            while len(self._metric_values) > self._max_size:
                self._metric_values.popitem(last=False)
        
        return value
    
    def get_metric_value(self, value_id: str) -> Optional[MetricValue]:
        """Get metric value by ID."""
        return self._metric_values.get(value_id)
    
    def get_metric_values(
        self,
        metric_id: str,
        start_time: datetime = None,
        end_time: datetime = None,
        limit: int = 1000,
    ) -> List[MetricValue]:
        """Get metric values with optional time filter."""
        values = [v for v in self._metric_values.values() if v.metric_id == metric_id]
        
        if start_time:
            values = [v for v in values if v.timestamp >= start_time]
        if end_time:
            values = [v for v in values if v.timestamp <= end_time]
        
        return sorted(values, key=lambda v: v.timestamp, reverse=True)[:limit]
    
    # KPI Methods
    def store_kpi(self, kpi: KPI) -> KPI:
        """Store a KPI."""
        with self._lock:
            self._kpis[kpi.kpi_id] = kpi
        return kpi
    
    def get_kpi(self, kpi_id: str) -> Optional[KPI]:
        """Get KPI by ID."""
        return self._kpis.get(kpi_id)
    
    def get_all_kpis(self) -> List[KPI]:
        """Get all KPIs."""
        return list(self._kpis.values())
    
    def get_kpis_by_status(self, status: str) -> List[KPI]:
        """Get KPIs by status."""
        return [k for k in self._kpis.values() if k.status == status]
    
    def get_kpis_by_category(self, category: str) -> List[KPI]:
        """Get KPIs by category."""
        return [k for k in self._kpis.values() if k.category == category]
    
    # Trend Analysis Methods
    def store_trend(self, trend: TrendAnalysis) -> TrendAnalysis:
        """Store trend analysis."""
        with self._lock:
            self._trends[trend.analysis_id] = trend
        return trend
    
    def get_trend(self, analysis_id: str) -> Optional[TrendAnalysis]:
        """Get trend by ID."""
        return self._trends.get(analysis_id)
    
    def get_recent_trends(self, limit: int = 50) -> List[TrendAnalysis]:
        """Get recent trends."""
        trends = list(self._trends.values())
        return sorted(trends, key=lambda t: t.created_at, reverse=True)[:limit]
    
    # Correlation Methods
    def store_correlation(self, correlation: CorrelationResult) -> CorrelationResult:
        """Store correlation result."""
        with self._lock:
            self._correlations[correlation.correlation_id] = correlation
        return correlation
    
    def get_correlation(self, correlation_id: str) -> Optional[CorrelationResult]:
        """Get correlation by ID."""
        return self._correlations.get(correlation_id)
    
    # Segment Analysis Methods
    def store_segment(self, segment: SegmentAnalysis) -> SegmentAnalysis:
        """Store segment analysis."""
        with self._lock:
            self._segments[segment.segment_id] = segment
        return segment
    
    def get_segment(self, segment_id: str) -> Optional[SegmentAnalysis]:
        """Get segment by ID."""
        return self._segments.get(segment_id)
    
    def get_all_segments(self) -> List[SegmentAnalysis]:
        """Get all segments."""
        return list(self._segments.values())
    
    # Cohort Analysis Methods
    def store_cohort(self, cohort: CohortAnalysis) -> CohortAnalysis:
        """Store cohort analysis."""
        with self._lock:
            self._cohorts[cohort.cohort_id] = cohort
        return cohort
    
    def get_cohort(self, cohort_id: str) -> Optional[CohortAnalysis]:
        """Get cohort by ID."""
        return self._cohorts.get(cohort_id)
    
    def get_all_cohorts(self) -> List[CohortAnalysis]:
        """Get all cohorts."""
        return list(self._cohorts.values())
    
    # Chart Methods
    def store_chart(self, chart: BIChart) -> BIChart:
        """Store BI chart."""
        with self._lock:
            self._charts[chart.chart_id] = chart
        return chart
    
    def get_chart(self, chart_id: str) -> Optional[BIChart]:
        """Get chart by ID."""
        return self._charts.get(chart_id)
    
    def get_all_charts(self) -> List[BIChart]:
        """Get all charts."""
        return list(self._charts.values())
    
    # Dashboard Methods
    def store_dashboard(self, dashboard: BIDashboard) -> BIDashboard:
        """Store BI dashboard."""
        with self._lock:
            self._dashboards[dashboard.dashboard_id] = dashboard
        return dashboard
    
    def get_dashboard(self, dashboard_id: str) -> Optional[BIDashboard]:
        """Get dashboard by ID."""
        return self._dashboards.get(dashboard_id)
    
    def get_all_dashboards(self) -> List[BIDashboard]:
        """Get all dashboards."""
        return list(self._dashboards.values())
    
    def get_shared_dashboards(self) -> List[BIDashboard]:
        """Get shared dashboards."""
        return [d for d in self._dashboards.values() if d.is_shared]
    
    # Automated Report Methods
    def store_report(self, report: AutomatedReport) -> AutomatedReport:
        """Store automated report."""
        with self._lock:
            self._reports[report.report_id] = report
            self._reports.move_to_end(report.report_id)
            
            while len(self._reports) > self._max_size:
                self._reports.popitem(last=False)
        
        return report
    
    def get_report(self, report_id: str) -> Optional[AutomatedReport]:
        """Get report by ID."""
        return self._reports.get(report_id)
    
    def get_enabled_reports(self) -> List[AutomatedReport]:
        """Get enabled automated reports."""
        return [r for r in self._reports.values() if r.enabled]
    
    def get_recent_reports(self, limit: int = 50) -> List[AutomatedReport]:
        """Get recent reports."""
        reports = list(self._reports.values())
        return sorted(reports, key=lambda r: r.created_at, reverse=True)[:limit]
    
    # Insight Methods
    def store_insight(self, insight: Insight) -> Insight:
        """Store business insight."""
        with self._lock:
            self._insights[insight.insight_id] = insight
            self._insights.move_to_end(insight.insight_id)
            
            while len(self._insights) > self._max_size:
                self._insights.popitem(last=False)
        
        return insight
    
    def get_insight(self, insight_id: str) -> Optional[Insight]:
        """Get insight by ID."""
        return self._insights.get(insight_id)
    
    def get_recent_insights(self, limit: int = 50) -> List[Insight]:
        """Get recent insights."""
        insights = list(self._insights.values())
        return sorted(insights, key=lambda i: i.generated_at, reverse=True)[:limit]
    
    def get_unacknowledged_insights(self) -> List[Insight]:
        """Get unacknowledged insights."""
        return [i for i in self._insights.values() if not i.acknowledged]
    
    # Statistics
    def get_stats(self) -> Dict[str, Any]:
        """Get store statistics."""
        return {
            "metric_definitions_stored": len(self._metric_definitions),
            "metric_values_stored": len(self._metric_values),
            "kpis_stored": len(self._kpis),
            "trends_stored": len(self._trends),
            "correlations_stored": len(self._correlations),
            "segments_stored": len(self._segments),
            "cohorts_stored": len(self._cohorts),
            "charts_stored": len(self._charts),
            "dashboards_stored": len(self._dashboards),
            "reports_stored": len(self._reports),
            "insights_stored": len(self._insights),
            "unacknowledged_insights": len(self.get_unacknowledged_insights()),
        }


# Global singleton
_analytics_store: Optional[AnalyticsStore] = None


def get_analytics_store() -> AnalyticsStore:
    """Get or create the singleton analytics store instance."""
    global _analytics_store
    
    if _analytics_store is None:
        _analytics_store = AnalyticsStore()
    return _analytics_store