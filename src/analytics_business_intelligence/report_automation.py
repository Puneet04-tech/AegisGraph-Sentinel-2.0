"""
Report Automation Module.

Provides automated report generation, scheduling, and delivery.
"""

import json
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone, timedelta
import logging

from .models import AutomatedReport, ReportSchedule
from .store import AnalyticsStore, get_analytics_store

logger = logging.getLogger(__name__)


class ReportAutomationModule:
    """Report Automation for scheduled and on-demand reporting.
    
    Provides:
        - Automated report scheduling
        - Report generation
        - Report delivery
        - Report history tracking
    """
    
    def __init__(self, store: Optional[AnalyticsStore] = None):
        """Initialize the report automation module.
        
        Args:
            store: Optional analytics store
        """
        self._store = store or get_analytics_store()
        self._module_id = "report_automation"
    
    def create_scheduled_report(
        self,
        name: str,
        description: str,
        schedule: ReportSchedule,
        report_type: str,
        content_config: Dict[str, Any],
        recipients: List[str],
        report_format: str = "PDF",
    ) -> AutomatedReport:
        """Create an automated scheduled report.
        
        Args:
            name: Report name
            description: Report description
            schedule: Report schedule
            report_type: Type of report
            content_config: Report content configuration
            recipients: List of recipients
            report_format: Output format
            
        Returns:
            AutomatedReport
        """
        logger.info(f"Creating scheduled report: {name}")
        
        next_run = self._calculate_next_run(schedule)
        
        report = AutomatedReport(
            name=name,
            description=description,
            schedule=schedule,
            report_type=report_type,
            content_config=content_config,
            recipients=recipients,
            format=report_format,
            enabled=True,
            last_run=None,
            next_run=next_run,
        )
        
        self._store.store_report(report)
        return report
    
    def _calculate_next_run(self, schedule: ReportSchedule) -> datetime:
        """Calculate next run time based on schedule."""
        now = datetime.now(timezone.utc)
        
        if schedule == ReportSchedule.DAILY:
            return now + timedelta(days=1)
        elif schedule == ReportSchedule.WEEKLY:
            return now + timedelta(weeks=1)
        elif schedule == ReportSchedule.MONTHLY:
            return now + timedelta(days=30)
        elif schedule == ReportSchedule.QUARTERLY:
            return now + timedelta(days=90)
        else:
            return now + timedelta(days=1)
    
    def generate_report(
        self,
        report_type: str,
        content_config: Dict[str, Any],
        format: str = "PDF",
    ) -> Dict[str, Any]:
        """Generate a report on-demand.
        
        Args:
            report_type: Type of report to generate
            content_config: Report content configuration
            format: Output format
            
        Returns:
            Generated report data
        """
        logger.info(f"Generating {report_type} report")
        
        # Generate based on type
        if report_type == "executive_summary":
            content = self._generate_executive_summary(content_config)
        elif report_type == "operational_metrics":
            content = self._generate_operational_metrics(content_config)
        elif report_type == "fraud_analysis":
            content = self._generate_fraud_analysis(content_config)
        elif report_type == "compliance_report":
            content = self._generate_compliance_report(content_config)
        else:
            content = self._generate_generic_report(content_config)
        
        # Derive page count and size from the actual generated content rather
        # than inventing random values. ~3000 bytes of serialized content per page.
        content_bytes = json.dumps(content, indent=2).encode("utf-8")
        page_count = max(1, min(20, round(len(content_bytes) / 3000)))
        
        return {
            "report_id": f"report_{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}",
            "report_type": report_type,
            "format": format,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "content": content,
            "page_count": page_count,
            "size_bytes": len(content_bytes),
        }
    
    # ------------------------------------------------------------------
    # Live data sources
    # ------------------------------------------------------------------

    def _live_insights(self, limit: int = 10) -> List[Any]:
        """Return recently generated insights from the analytics store."""
        try:
            return self._store.get_recent_insights(limit)
        except Exception:
            return []

    def _live_case_stats(self) -> Dict[str, Any]:
        """Return case management statistics from the live case store."""
        try:
            from src.case_management.store import get_case_store
            return get_case_store().get_dashboard_stats()
        except Exception:
            return {}

    def _live_fraud_metrics(self) -> Dict[str, Any]:
        """Return fraud metrics from the live financial crime store."""
        try:
            from src.financial_crime_command.store import get_financial_crime_store
            return get_financial_crime_store().get_dashboard_metrics()
        except Exception:
            return {}

    def _live_compliance_overview(self) -> Dict[str, Any]:
        """Return compliance status from the live governance store."""
        try:
            from src.executive_governance.compliance_analytics import get_compliance_analytics_module
            return get_compliance_analytics_module().get_compliance_overview()
        except Exception:
            return {}

    def _live_kpis(self) -> List[Dict[str, Any]]:
        """Return a snapshot of tracked KPIs with their live values."""
        kpis = []
        for kpi in self._store.get_all_kpis():
            unit = ""
            try:
                definition = self._store.get_metric_definition(kpi.metric_id)
                if definition:
                    unit = definition.unit
            except Exception:
                pass
            kpis.append({
                "name": kpi.name,
                "category": kpi.category,
                "unit": unit,
                "current_value": kpi.current_value,
                "target_value": kpi.target_value,
                "change_percent": kpi.change_percent,
                "status": kpi.status,
            })
        return kpis

    def _format_kpi_value(self, value: Any, unit: str) -> str:
        """Format a KPI value with its unit for report display."""
        if value is None:
            return "No data"
        if isinstance(value, float):
            value_str = f"{value:.2f}"
        else:
            value_str = str(value)
        if unit:
            return f"{value_str} {unit}"
        return value_str

    def _generate_executive_summary(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Generate executive summary report from live analytics data."""
        kpis = self._live_kpis()
        case_stats = self._live_case_stats()
        insights = self._live_insights(limit=10)

        highlights = []
        for kpi in kpis:
            if kpi["current_value"] is None:
                continue
            highlights.append({
                "metric": kpi["name"],
                "value": self._format_kpi_value(kpi["current_value"], kpi["unit"]),
            })

        if case_stats.get("total_cases") is not None:
            highlights.append({"metric": "Investigations Completed", "value": str(case_stats["total_cases"])})
        if case_stats.get("open_cases") is not None:
            highlights.append({"metric": "Open Investigations", "value": str(case_stats["open_cases"])})

        key_insights = [
            {"title": insight.title, "description": insight.description, "severity": insight.severity}
            for insight in insights
        ]

        recommendations = []
        for insight in insights:
            recommendations.extend(insight.recommendations)
        recommendations = recommendations[:5]

        return {
            "title": "Executive Summary Report",
            "period": config.get("period", "Monthly"),
            "highlights": highlights,
            "key_insights": key_insights,
            "recommendations": recommendations,
        }
    
    def _generate_operational_metrics(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Generate operational metrics report from live data."""
        stats = self._store.get_stats()
        case_stats = self._live_case_stats()
        fraud = self._live_fraud_metrics()
        kpis = self._live_kpis()

        metrics = {
            "total_cases": case_stats.get("total_cases", 0),
            "open_cases": case_stats.get("open_cases", 0),
            "in_progress_cases": case_stats.get("in_progress_cases", 0),
            "escalated_cases": case_stats.get("escalated_cases", 0),
            "metric_definitions": stats.get("metric_definitions_stored", 0),
            "metric_values_recorded": stats.get("metric_values_stored", 0),
            "kpis_tracked": stats.get("kpis_stored", 0),
            "insights_generated": stats.get("insights_stored", 0),
            "recent_alerts": fraud.get("recent_alerts", 0),
            "pending_investigations": fraud.get("pending_investigations", 0),
        }

        performance = [
            {
                "metric": kpi["name"],
                "current_value": kpi["current_value"],
                "target_value": kpi["target_value"],
                "status": kpi["status"],
            }
            for kpi in kpis
            if kpi["current_value"] is not None
        ]

        return {
            "title": "Operational Metrics Report",
            "period": config.get("period", "Weekly"),
            "metrics": metrics,
            "performance": performance,
        }
    
    def _generate_fraud_analysis(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Generate fraud analysis report from live data."""
        fraud = self._live_fraud_metrics()
        cases_by_type = fraud.get("cases_by_type", {})

        top_fraud_types = [
            {"type": crime_type, "count": count}
            for crime_type, count in sorted(
                cases_by_type.items(), key=lambda item: item[1], reverse=True
            )
            if count > 0
        ]

        fraud_trends = []
        try:
            trends = self._store.get_recent_trends(limit=5)
            fraud_trends = [
                {
                    "metric": trend.metric_name,
                    "direction": trend.direction,
                    "slope": round(trend.slope, 4) if trend.slope is not None else None,
                    "volatility": round(trend.volatility, 4) if trend.volatility is not None else None,
                    "period_start": trend.period_start.isoformat(),
                    "period_end": trend.period_end.isoformat(),
                }
                for trend in trends
            ]
        except Exception:
            pass

        return {
            "title": "Fraud Analysis Report",
            "period": config.get("period", "Monthly"),
            "fraud_summary": {
                "total_fraud_cases": fraud.get("total_cases", 0),
                "open_cases": fraud.get("open_cases", 0),
                "closed_cases": fraud.get("closed_cases", 0),
                "escalated_cases": fraud.get("escalated_cases", 0),
                "high_priority_cases": fraud.get("high_priority_cases", 0),
            },
            "top_fraud_types": top_fraud_types,
            "fraud_trends": fraud_trends,
        }
    
    def _generate_compliance_report(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Generate compliance report from live governance data."""
        overview = self._live_compliance_overview()

        if overview:
            compliance_score = overview.get("overall_compliance")
            frameworks = [
                {
                    "name": entry.get("name"),
                    "status": entry.get("status"),
                    "compliance": entry.get("compliance"),
                }
                for entry in overview.get("framework_summary", [])
            ]
            frameworks_tracked = overview.get("frameworks_tracked", 0)
            compliant_frameworks = overview.get("compliant_frameworks", 0)
            open_findings = overview.get("open_findings", 0)
            critical_findings = overview.get("critical_findings", 0)
        else:
            compliance_score = None
            frameworks = []
            frameworks_tracked = 0
            compliant_frameworks = 0
            open_findings = 0
            critical_findings = 0

        return {
            "title": "Compliance Report",
            "period": config.get("period", "Quarterly"),
            "compliance_score": compliance_score,
            "frameworks_tracked": frameworks_tracked,
            "compliant_frameworks": compliant_frameworks,
            "frameworks": frameworks,
            "open_findings": open_findings,
            "critical_findings": critical_findings,
        }
    
    def _generate_generic_report(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Generate generic report from live analytics data."""
        stats = self._store.get_stats()
        return {
            "title": config.get("title", "Analytics Report"),
            "period": config.get("period", "Monthly"),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "summary": "Report generated from live analytics data.",
            "data_points": stats.get("metric_values_stored", 0),
        }
    
    def run_scheduled_reports(self) -> List[Dict[str, Any]]:
        """Run all due scheduled reports.
        
        Returns:
            List of report execution results
        """
        logger.info("Running scheduled reports")
        
        results = []
        now = datetime.now(timezone.utc)
        
        for report in self._store.get_enabled_reports():
            if report.next_run and report.next_run <= now:
                # Generate and deliver report
                result = self.generate_report(
                    report_type=report.report_type,
                    content_config=report.content_config,
                    format=report.format,
                )
                
                # Update report
                report.last_run = now
                report.next_run = self._calculate_next_run(report.schedule)
                self._store.store_report(report)
                
                results.append({
                    "report_id": report.report_id,
                    "name": report.name,
                    "status": "SUCCESS",
                    "recipients": len(report.recipients),
                    "generated_at": result["generated_at"],
                })
        
        return results
    
    def get_report_schedule(self) -> Dict[str, Any]:
        """Get report schedule overview."""
        reports = self._store.get_all_dashboards()  # Using dashboards as placeholder
        
        enabled = self._store.get_enabled_reports()
        
        schedule_summary = {}
        for schedule in ReportSchedule:
            count = sum(1 for r in enabled if r.schedule == schedule)
            schedule_summary[schedule.value] = count
        
        return {
            "total_scheduled": len(enabled),
            "by_schedule": schedule_summary,
            "next_run": min(
                (r.next_run for r in enabled if r.next_run),
                default=datetime.now(timezone.utc),
            ).isoformat() if enabled else None,
        }
    
    def pause_report(self, report_id: str) -> bool:
        """Pause a scheduled report.
        
        Args:
            report_id: Report ID
            
        Returns:
            True if successful
        """
        report = self._store.get_report(report_id)
        if report:
            report.enabled = False
            self._store.store_report(report)
            return True
        return False
    
    def resume_report(self, report_id: str) -> bool:
        """Resume a paused scheduled report.
        
        Args:
            report_id: Report ID
            
        Returns:
            True if successful
        """
        report = self._store.get_report(report_id)
        if report:
            report.enabled = True
            report.next_run = self._calculate_next_run(report.schedule)
            self._store.store_report(report)
            return True
        return False
    
    def get_report_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get report generation history."""
        reports = self._store.get_recent_reports(limit)
        
        return [
            {
                "report_id": r.report_id,
                "name": r.name,
                "schedule": r.schedule.value,
                "last_run": r.last_run.isoformat() if r.last_run else None,
                "next_run": r.next_run.isoformat() if r.next_run else None,
                "enabled": r.enabled,
            }
            for r in reports
        ]


# Global singleton
_report_automation: Optional[ReportAutomationModule] = None


def get_report_automation_module(store: Optional[AnalyticsStore] = None) -> ReportAutomationModule:
    """Get or create the singleton ReportAutomationModule instance."""
    global _report_automation
    
    if _report_automation is None:
        _report_automation = ReportAutomationModule(store=store)
    return _report_automation