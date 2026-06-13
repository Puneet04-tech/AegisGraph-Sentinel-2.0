"""
Compliance Engine.

Manages compliance reporting and assessments.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid

from .models import ComplianceReport
from .store import QuantumSecurityStore, get_quantum_store


class ComplianceEngine:
    """Engine for compliance management."""

    def __init__(self, store: Optional[QuantumSecurityStore] = None) -> None:
        """Initialize the engine."""
        self.store = store or get_quantum_store()

    def generate_report(
        self,
        framework: str,
    ) -> ComplianceReport:
        """Generate a compliance report."""
        report_id = f"comp-{uuid.uuid4().hex[:12]}"
        
        assets = list(self.store._assets.values())
        vulnerable = [a for a in assets if not a.quantum_resistant]
        
        findings = []
        if vulnerable:
            findings.append(f"{len(vulnerable)} quantum-vulnerable assets detected")
        
        certificates = list(self.store._certificates.values())
        expiring = self.store.get_expiring_certificates(30)
        if expiring:
            findings.append(f"{len(expiring)} certificates expiring within 30 days")
        
        high_risk = self.store.get_high_risk_assessments()
        if high_risk:
            findings.append(f"{len(high_risk)} high/critical risk assets")
        
        report = ComplianceReport(
            report_id=report_id,
            framework=framework,
            compliant=len(findings) == 0,
            total_assets=len(assets),
            compliant_assets=len(assets) - len(vulnerable),
            non_compliant_assets=[a.asset_id for a in vulnerable],
            findings=findings,
        )
        
        self.store.store_compliance_report(report)
        
        return report

    def get_report(self, report_id: str) -> Optional[Dict[str, Any]]:
        """Get a compliance report."""
        from .models import ComplianceReport
        for report in self.store._compliance_reports.values():
            if report.report_id == report_id:
                return {
                    "report_id": report.report_id,
                    "framework": report.framework,
                    "compliant": report.compliant,
                    "total_assets": report.total_assets,
                    "compliant_assets": report.compliant_assets,
                    "non_compliant_assets": report.non_compliant_assets,
                    "findings": report.findings,
                    "generated_at": report.generated_at.isoformat(),
                }
        return None

    def get_latest_report(self, framework: str) -> Optional[Dict[str, Any]]:
        """Get latest report for a framework."""
        report = self.store.get_latest_compliance_report(framework)
        if not report:
            return None
        
        return {
            "report_id": report.report_id,
            "framework": report.framework,
            "compliant": report.compliant,
            "findings": report.findings,
            "generated_at": report.generated_at.isoformat(),
        }


# Singleton instance
_engine: Optional[ComplianceEngine] = None


def get_compliance_engine() -> ComplianceEngine:
    """Get the global engine instance."""
    global _engine
    if _engine is None:
        _engine = ComplianceEngine()
    return _engine


def reset_compliance_engine() -> None:
    """Reset the global engine."""
    global _engine
    _engine = None