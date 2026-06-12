"""
Audit Service for Global Intelligence operations.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
import uuid

from .models import (
    AuditRecord,
    FederationPartner,
    InvestigationStatus,
    ThreatLevel,
)
from .store import GlobalIntelligenceStore, get_global_intelligence_store


@dataclass
class AuditQuery:
    """Query for audit records."""
    query_id: str
    start_date: Optional[datetime]
    end_date: Optional[datetime]
    operations: List[str]
    partner_ids: List[str]
    user_ids: List[str]
    success_only: bool
    limit: int = 100


@dataclass
class AuditSummary:
    """Summary of audit activity."""
    total_operations: int
    operations_by_type: Dict[str, int]
    operations_by_partner: Dict[str, int]
    success_rate: float
    failed_operations: List[Dict[str, Any]]
    period_start: datetime
    period_end: datetime


class GlobalIntelligenceAudit:
    """
    Comprehensive audit logging for global intelligence operations.

    Handles:
    - Operation audit logging
    - Access pattern analysis
    - Compliance reporting
    - Security event tracking
    """

    def __init__(self, store: Optional[GlobalIntelligenceStore] = None):
        self._store = store or get_global_intelligence_store()

    def log_operation(
        self,
        operation: str,
        user_id: str,
        partner_id: Optional[str] = None,
        entity_ids: Optional[List[str]] = None,
        success: bool = True,
        error_message: Optional[str] = None,
        ip_address: str = "unknown",
        user_agent: str = "unknown",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AuditRecord:
        """Log an audit record."""
        record = AuditRecord(
            record_id=str(uuid.uuid4()),
            operation=operation,
            user_id=user_id,
            partner_id=partner_id,
            entity_ids=entity_ids or [],
            timestamp=datetime.now(timezone.utc),
            ip_address=ip_address,
            user_agent=user_agent,
            success=success,
            error_message=error_message,
            metadata=metadata or {},
        )

        self._store.store_audit_record(record)
        return record

    def query_audit(
        self,
        query: AuditQuery,
    ) -> List[AuditRecord]:
        """Query audit records with filters."""
        records = self._store.get_audit_records(
            partner_id=query.partner_ids[0] if query.partner_ids else None,
            user_id=query.user_ids[0] if query.user_ids else None,
            operation=query.operations[0] if query.operations else None,
            limit=query.limit,
        )

        filtered = []
        for record in records:
            # Date range filter
            if query.start_date and record.timestamp < query.start_date:
                continue
            if query.end_date and record.timestamp > query.end_date:
                continue

            # Success filter
            if query.success_only and not record.success:
                continue

            filtered.append(record)

        return filtered

    def get_summary(
        self,
        period_days: int = 7,
    ) -> AuditSummary:
        """Get audit summary for a period."""
        end_date = datetime.now(timezone.utc)
        start_date = end_date - timedelta(days=period_days)

        records = self._store.get_audit_records(limit=10000)

        # Filter to period
        period_records = [
            r for r in records
            if start_date <= r.timestamp <= end_date
        ]

        # Count by operation type
        operations_by_type: Dict[str, int] = {}
        operations_by_partner: Dict[str, int] = {}
        failed_operations: List[Dict[str, Any]] = []
        success_count = 0

        for record in period_records:
            operations_by_type[record.operation] = operations_by_type.get(record.operation, 0) + 1

            if record.partner_id:
                operations_by_partner[record.partner_id] = (
                    operations_by_partner.get(record.partner_id, 0) + 1
                )

            if record.success:
                success_count += 1
            else:
                failed_operations.append({
                    "operation": record.operation,
                    "user_id": record.user_id,
                    "error": record.error_message,
                    "timestamp": record.timestamp.isoformat(),
                })

        total = len(period_records)
        success_rate = success_count / total if total > 0 else 0

        return AuditSummary(
            total_operations=total,
            operations_by_type=operations_by_type,
            operations_by_partner=operations_by_partner,
            success_rate=success_rate,
            failed_operations=failed_operations[:50],
            period_start=start_date,
            period_end=end_date,
        )

    def get_partner_activity(
        self,
        partner_id: str,
        days: int = 30,
    ) -> Dict[str, Any]:
        """Get activity summary for a partner."""
        end_date = datetime.now(timezone.utc)
        start_date = end_date - timedelta(days=days)

        records = self._store.get_audit_records(
            partner_id=partner_id,
            limit=1000,
        )

        # Filter to period
        period_records = [
            r for r in records
            if start_date <= r.timestamp <= end_date
        ]

        operations = {}
        total_entities_accessed = set()

        for record in period_records:
            operations[record.operation] = operations.get(record.operation, 0) + 1
            total_entities_accessed.update(record.entity_ids)

        return {
            "partner_id": partner_id,
            "total_operations": len(period_records),
            "operations_by_type": operations,
            "unique_entities_accessed": len(total_entities_accessed),
            "period_days": days,
            "avg_operations_per_day": len(period_records) / days if days > 0 else 0,
        }

    def detect_anomalies(
        self,
        threshold_multiplier: float = 2.0,
    ) -> List[Dict[str, Any]]:
        """Detect anomalous access patterns."""
        # Get records for analysis
        records = self._store.get_audit_records(limit=5000)

        # Calculate baseline statistics
        operations_by_user: Dict[str, int] = {}
        operations_by_hour: Dict[int, int] = defaultdict(int)

        for record in records:
            operations_by_user[record.user_id] = operations_by_user.get(record.user_id, 0) + 1
            operations_by_hour[record.timestamp.hour] += 1

        if not operations_by_user:
            return []

        # Find anomalies
        avg_ops = sum(operations_by_user.values()) / len(operations_by_user)
        threshold = avg_ops * threshold_multiplier

        anomalies = []

        for user_id, count in operations_by_user.items():
            if count > threshold:
                anomalies.append({
                    "type": "high_activity",
                    "user_id": user_id,
                    "operation_count": count,
                    "threshold": threshold,
                    "severity": "medium" if count < threshold * 2 else "high",
                })

        # Check for off-hours activity
        unusual_hour_count = sum(
            count for hour, count in operations_by_hour.items()
            if hour < 6 or hour > 22
        )

        if unusual_hour_count > len(records) * 0.2:
            anomalies.append({
                "type": "unusual_hours",
                "description": f"{unusual_hour_count} operations during off-hours",
                "severity": "low",
            })

        return anomalies

    def generate_compliance_report(
        self,
        start_date: datetime,
        end_date: datetime,
    ) -> Dict[str, Any]:
        """Generate compliance report for a period."""
        records = self._store.get_audit_records(limit=10000)

        # Filter to period
        period_records = [
            r for r in records
            if start_date <= r.timestamp <= end_date
        ]

        # Group by operation type
        operations = {}
        partners = set()
        users = set()
        failed = 0

        for record in period_records:
            operations[record.operation] = operations.get(record.operation, 0) + 1
            if record.partner_id:
                partners.add(record.partner_id)
            users.add(record.user_id)
            if not record.success:
                failed += 1

        return {
            "report_period": {
                "start": start_date.isoformat(),
                "end": end_date.isoformat(),
            },
            "total_operations": len(period_records),
            "unique_users": len(users),
            "unique_partners": len(partners),
            "operations_by_type": operations,
            "failed_operations": failed,
            "failure_rate": failed / len(period_records) if period_records else 0,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }


# Global audit instance
_audit: Optional[GlobalIntelligenceAudit] = None


def get_audit_service() -> GlobalIntelligenceAudit:
    """Get the global audit service instance."""
    global _audit
    if _audit is None:
        _audit = GlobalIntelligenceAudit()
    return _audit


def reset_audit_service() -> None:
    """Reset the audit service (for testing)."""
    global _audit
    _audit = None