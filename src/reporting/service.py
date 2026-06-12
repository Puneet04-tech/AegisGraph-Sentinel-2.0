"""Reporting Service"""
from typing import Any, Dict, List, Optional
from uuid import uuid4
from datetime import datetime
from .models import Report, ReportTemplate, ReportType, ReportStatus

class ReportingService:
    """Enterprise Reporting Service"""
    
    def __init__(self) -> None:
        self.reports: Dict[str, Report] = {}
        self.templates: Dict[str, ReportTemplate] = {}
        self._init_default_templates()
    
    def _init_default_templates(self) -> None:
        """Initialize default templates"""
        templates = [
            ReportTemplate(
                template_id="tmpl-001",
                name="Executive Summary",
                report_type=ReportType.EXECUTIVE,
                description="Executive security summary",
                content_template="# Executive Summary\n\n## Overview\n\n## Key Findings"
            ),
            ReportTemplate(
                template_id="tmpl-002",
                name="Compliance Report",
                report_type=ReportType.COMPLIANCE,
                description="Regulatory compliance report",
                content_template="# Compliance Report\n\n## Requirements\n\n## Status"
            )
        ]
        for t in templates:
            self.templates[t.template_id] = t
    
    def create_report(
        self,
        name: str,
        report_type: str,
        description: str,
        parameters: Optional[Dict[str, Any]] = None,
        created_by: str = "system"
    ) -> Dict[str, Any]:
        """Create a new report"""
        report = Report(
            report_id=str(uuid4())[:8],
            name=name,
            report_type=ReportType(report_type),
            description=description,
            parameters=parameters or {},
            status=ReportStatus.DRAFT,
            created_by=created_by
        )
        self.reports[report.report_id] = report
        return report.to_dict()
    
    def generate_report(self, report_id: str) -> Optional[Dict[str, Any]]:
        """Generate a report"""
        report = self.reports.get(report_id)
        if not report:
            return None
        
        report.status = ReportStatus.GENERATED
        report.generated_at = datetime.utcnow()
        return report.to_dict()
    
    def get_report(self, report_id: str) -> Optional[Dict[str, Any]]:
        """Get a report"""
        report = self.reports.get(report_id)
        return report.to_dict() if report else None
    
    def get_all_reports(self) -> List[Dict[str, Any]]:
        """Get all reports"""
        return [r.to_dict() for r in self.reports.values()]
    
    def get_templates(self) -> List[Dict[str, Any]]:
        """Get all templates"""
        return [t.to_dict() for t in self.templates.values()]
    
    def export_report(self, report_id: str, format: str = "PDF") -> Dict[str, Any]:
        """Export a report"""
        report = self.reports.get(report_id)
        if not report:
            raise ValueError(f"Report {report_id} not found")
        
        return {
            "report_id": report_id,
            "format": format,
            "exported_at": datetime.utcnow().isoformat(),
            "status": "EXPORTED"
        }
    
    def get_dashboard(self) -> Dict[str, Any]:
        """Get reporting dashboard"""
        type_counts: Dict[str, int] = {}
        status_counts: Dict[str, int] = {}
        
        for report in self.reports.values():
            type_counts[report.report_type.value] = type_counts.get(report.report_type.value, 0) + 1
            status_counts[report.status.value] = status_counts.get(report.status.value, 0) + 1
        
        return {
            "total_reports": len(self.reports),
            "total_templates": len(self.templates),
            "reports_by_type": type_counts,
            "reports_by_status": status_counts
        }


_reporting_service: Optional[ReportingService] = None

def get_reporting_service() -> ReportingService:
    """Get the global service instance"""
    global _reporting_service
    if _reporting_service is None:
        _reporting_service = ReportingService()
    return _reporting_service