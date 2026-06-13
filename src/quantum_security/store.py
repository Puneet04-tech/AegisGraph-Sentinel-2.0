"""
Quantum Security Store.

Storage layer for quantum security components.
"""

from __future__ import annotations

import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .models import (
    AuditEvent,
    Certificate,
    ComplianceReport,
    CryptoAlgorithm,
    CryptoAsset,
    CryptoType,
    GovernancePolicy,
    KeyLifecycleRecord,
    MigrationPlan,
    MigrationStatus,
    QuantumRiskAssessment,
    RiskLevel,
)


class QuantumSecurityStore:
    """Store for quantum security."""

    def __init__(self) -> None:
        """Initialize the store."""
        self._assets: Dict[str, CryptoAsset] = {}
        self._certificates: Dict[str, Certificate] = {}
        self._assessments: Dict[str, QuantumRiskAssessment] = {}
        self._lifecycle_records: Dict[str, List[KeyLifecycleRecord]] = {}
        self._policies: Dict[str, GovernancePolicy] = {}
        self._compliance_reports: Dict[str, ComplianceReport] = {}
        self._migration_plans: Dict[str, MigrationPlan] = {}
        self._audit_log: List[AuditEvent] = []
        self._lock = threading.RLock()

    def register_asset(self, asset: CryptoAsset) -> None:
        """Register a crypto asset."""
        with self._lock:
            self._assets[asset.asset_id] = asset

    def get_asset(self, asset_id: str) -> Optional[CryptoAsset]:
        """Get an asset by ID."""
        return self._assets.get(asset_id)

    def get_assets_by_algorithm(self, algorithm: CryptoAlgorithm) -> List[CryptoAsset]:
        """Get assets by algorithm."""
        return [a for a in self._assets.values() if a.algorithm == algorithm]

    def get_assets_by_system(self, system: str) -> List[CryptoAsset]:
        """Get assets by system."""
        return [a for a in self._assets.values() if a.system == system]

    def get_vulnerable_assets(self) -> List[CryptoAsset]:
        """Get quantum-vulnerable assets."""
        return [a for a in self._assets.values() if not a.quantum_resistant]

    def add_certificate(self, cert: Certificate) -> None:
        """Add a certificate."""
        with self._lock:
            self._certificates[cert.cert_id] = cert

    def get_certificate(self, cert_id: str) -> Optional[Certificate]:
        """Get a certificate."""
        return self._certificates.get(cert_id)

    def get_expiring_certificates(self, days: int = 30) -> List[Certificate]:
        """Get certificates expiring within days."""
        now = datetime.now(timezone.utc)
        threshold = datetime.fromtimestamp(
            now.timestamp() + days * 86400,
            tz=timezone.utc,
        )
        return [
            c for c in self._certificates.values()
            if c.valid_until <= threshold
        ]

    def store_assessment(self, assessment: QuantumRiskAssessment) -> None:
        """Store a risk assessment."""
        with self._lock:
            self._assessments[assessment.asset_id] = assessment

    def get_assessment(self, asset_id: str) -> Optional[QuantumRiskAssessment]:
        """Get assessment for an asset."""
        return self._assessments.get(asset_id)

    def get_high_risk_assessments(self) -> List[QuantumRiskAssessment]:
        """Get high-risk assessments."""
        return [
            a for a in self._assessments.values()
            if a.risk_level in [RiskLevel.CRITICAL, RiskLevel.HIGH]
        ]

    def add_lifecycle_record(self, record: KeyLifecycleRecord) -> None:
        """Add a lifecycle record."""
        with self._lock:
            if record.key_id not in self._lifecycle_records:
                self._lifecycle_records[record.key_id] = []
            self._lifecycle_records[record.key_id].append(record)

    def get_lifecycle_records(self, key_id: str) -> List[KeyLifecycleRecord]:
        """Get lifecycle records for a key."""
        return self._lifecycle_records.get(key_id, [])

    def add_policy(self, policy: GovernancePolicy) -> None:
        """Add a governance policy."""
        with self._lock:
            self._policies[policy.policy_id] = policy

    def get_policy(self, policy_id: str) -> Optional[GovernancePolicy]:
        """Get a policy."""
        return self._policies.get(policy_id)

    def get_enforced_policies(self) -> List[GovernancePolicy]:
        """Get enforced policies."""
        return [p for p in self._policies.values() if p.enforced]

    def store_compliance_report(self, report: ComplianceReport) -> None:
        """Store a compliance report."""
        with self._lock:
            self._compliance_reports[report.report_id] = report

    def get_latest_compliance_report(
        self,
        framework: str,
    ) -> Optional[ComplianceReport]:
        """Get latest compliance report for a framework."""
        reports = [
            r for r in self._compliance_reports.values()
            if r.framework == framework
        ]
        if not reports:
            return None
        return max(reports, key=lambda r: r.generated_at)

    def create_migration_plan(self, plan: MigrationPlan) -> None:
        """Create a migration plan."""
        with self._lock:
            self._migration_plans[plan.plan_id] = plan

    def get_migration_plan(self, plan_id: str) -> Optional[MigrationPlan]:
        """Get a migration plan."""
        return self._migration_plans.get(plan_id)

    def update_migration_progress(self, plan_id: str, progress: float) -> bool:
        """Update migration progress."""
        plan = self._migration_plans.get(plan_id)
        if not plan:
            return False
        plan.progress = progress
        if progress >= 1.0:
            plan.status = MigrationStatus.COMPLETED
        return True

    def log_audit(
        self,
        user_id: str,
        action: str,
        resource_type: str,
        resource_id: str,
        details: Optional[Dict[str, Any]] = None,
        success: bool = True,
    ) -> None:
        """Log an audit event."""
        event = AuditEvent(
            event_id=f"audit-{len(self._audit_log) + 1}",
            timestamp=datetime.now(timezone.utc),
            user_id=user_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            details=details or {},
            success=success,
        )
        with self._lock:
            self._audit_log.append(event)

    def get_audit_log(self, limit: int = 100) -> List[AuditEvent]:
        """Get audit log."""
        return self._audit_log[-limit:]

    def get_dashboard_metrics(self) -> Dict[str, Any]:
        """Get dashboard metrics."""
        assets = list(self._assets.values())
        vulnerable = len([a for a in assets if not a.quantum_resistant])
        
        return {
            "total_assets": len(assets),
            "vulnerable_assets": vulnerable,
            "quantum_resistant_assets": len(assets) - vulnerable,
            "total_certificates": len(self._certificates),
            "expiring_certificates": len(self.get_expiring_certificates()),
            "high_risk_assets": len(self.get_high_risk_assessments()),
            "active_migrations": len([
                p for p in self._migration_plans.values()
                if p.status == MigrationStatus.IN_PROGRESS
            ]),
            "compliant_policies": len(self.get_enforced_policies()),
        }

    def clear(self) -> None:
        """Clear all data."""
        with self._lock:
            self._assets.clear()
            self._certificates.clear()
            self._assessments.clear()
            self._lifecycle_records.clear()
            self._policies.clear()
            self._compliance_reports.clear()
            self._migration_plans.clear()
            self._audit_log.clear()


# Singleton instance
_store: Optional[QuantumSecurityStore] = None
_store_lock = threading.Lock()


def get_quantum_store() -> QuantumSecurityStore:
    """Get the global store instance."""
    global _store
    if _store is None:
        with _store_lock:
            if _store is None:
                _store = QuantumSecurityStore()
    return _store


def reset_quantum_store() -> None:
    """Reset the global store."""
    global _store
    with _store_lock:
        if _store is not None:
            _store.clear()
        _store = None