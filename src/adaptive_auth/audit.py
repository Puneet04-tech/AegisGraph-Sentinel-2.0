"""
Audit Service for Adaptive Authentication & Continuous Authorization.

Provides comprehensive audit logging for authentication events,
authorization decisions, and security incidents.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Set
import json

from .models import (
    AuditEvent,
    AuthenticationSession,
    RiskLevel,
    TrustLevel,
)
from .store import AdaptiveAuthStore, get_adaptive_auth_store


@dataclass
class AuditQuery:
    """Query parameters for audit log search."""
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    event_type: Optional[str] = None
    severity: Optional[str] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    resource: Optional[str] = None
    action: Optional[str] = None
    outcome: Optional[str] = None
    limit: int = 100
    offset: int = 0


@dataclass
class AuditSummary:
    """Summary of audit events."""
    total_events: int
    events_by_type: Dict[str, int]
    events_by_severity: Dict[str, int]
    events_by_outcome: Dict[str, int]
    recent_events: List[Dict[str, Any]]
    time_range: Dict[str, str]


class AuditService:
    """
    Audit service for authentication and authorization events.
    
    Maintains a comprehensive audit trail of all security-relevant events
    including authentication attempts, policy decisions, and trust changes.
    """
    
    def __init__(self, store: AdaptiveAuthStore):
        self.store = store
        self._audit_log: List[AuditEvent] = []
        self._events_by_user: Dict[str, Set[str]] = {}
        self._events_by_session: Dict[str, Set[str]] = {}
        self._max_events = 100000
    
    def log_event(
        self,
        event_type: str,
        severity: str,
        user_id: str,
        resource: str,
        action: str,
        outcome: str,
        session_id: Optional[str] = None,
        risk_score: Optional[float] = None,
        trust_level: Optional[str] = None,
        ip_address: str = "",
        user_agent: str = "",
        correlation_id: str = "",
        **metadata,
    ) -> AuditEvent:
        """Log an audit event."""
        event = AuditEvent.create(
            event_type=event_type,
            severity=severity,
            user_id=user_id,
            session_id=session_id,
            resource=resource,
            action=action,
            outcome=outcome,
            risk_score=risk_score,
            trust_level=trust_level,
            ip_address=ip_address,
            user_agent=user_agent,
            correlation_id=correlation_id,
            metadata=metadata,
        )
        
        self._audit_log.append(event)
        
        # Index by user
        if user_id not in self._events_by_user:
            self._events_by_user[user_id] = set()
        self._events_by_user[user_id].add(event.event_id)

        # Index by session
        if session_id:
            if session_id not in self._events_by_session:
                self._events_by_session[session_id] = set()
            self._events_by_session[session_id].add(event.event_id)
        
        # Cleanup old events if needed
        self._cleanup_old_events()
        
        return event
    
    def _cleanup_old_events(self) -> None:
        """Remove old events if log exceeds max size."""
        if len(self._audit_log) > self._max_events:
            # Remove oldest 10%
            remove_count = self._max_events // 10
            removed = self._audit_log[:remove_count]
            self._audit_log = self._audit_log[remove_count:]
            
            # Clean up indexes
            for event in removed:
                user_ids = self._events_by_user.get(event.user_id)
                if user_ids is not None:
                    user_ids.discard(event.event_id)
                    if not user_ids:
                        del self._events_by_user[event.user_id]

                if event.session_id:
                    session_ids = self._events_by_session.get(event.session_id)
                    if session_ids is not None:
                        session_ids.discard(event.event_id)
                        if not session_ids:
                            del self._events_by_session[event.session_id]
    
    def log_authentication_attempt(
        self,
        session: AuthenticationSession,
        risk_score: float,
        outcome: str,
        challenges_issued: Optional[List[str]] = None,
    ) -> AuditEvent:
        """Log an authentication attempt."""
        return self.log_event(
            event_type="authentication_attempt",
            severity="info" if outcome == "success" else "warning",
            user_id=session.user_id,
            session_id=session.session_id,
            resource="authentication",
            action="login",
            outcome=outcome,
            risk_score=risk_score,
            trust_level=session.trust.trust_level.value,
            ip_address=session.ip_address,
            user_agent=session.user_agent,
            challenges_issued=challenges_issued or [],
        )
    
    def log_risk_evaluation(
        self,
        session: AuthenticationSession,
        risk_score: float,
        risk_level: RiskLevel,
        signals: List[Dict[str, Any]],
    ) -> AuditEvent:
        """Log a risk evaluation."""
        return self.log_event(
            event_type="risk_evaluation",
            severity="info",
            user_id=session.user_id,
            session_id=session.session_id,
            resource="risk_engine",
            action="evaluate",
            outcome="completed",
            risk_score=risk_score,
            trust_level=session.trust.trust_level.value,
            ip_address=session.ip_address,
            signals=signals,
            risk_level=risk_level.value,
        )
    
    def log_trust_change(
        self,
        session: AuthenticationSession,
        previous_level: TrustLevel,
        new_level: TrustLevel,
        reason: str,
    ) -> AuditEvent:
        """Log a trust level change."""
        severity = "info"
        if new_level.value in ("none", "low"):
            severity = "warning"
        elif previous_level.value == "full" and new_level.value in ("low", "none"):
            severity = "critical"
        
        return self.log_event(
            event_type="trust_change",
            severity=severity,
            user_id=session.user_id,
            session_id=session.session_id,
            resource="session",
            action="trust_update",
            outcome="completed",
            trust_level=new_level.value,
            previous_trust_level=previous_level.value,
            reason=reason,
        )
    
    def log_policy_decision(
        self,
        session: AuthenticationSession,
        resource: str,
        action: str,
        decision: str,
        policy_id: str,
        denied_reason: Optional[str] = None,
    ) -> AuditEvent:
        """Log a policy evaluation decision."""
        severity = "info" if decision == "allow" else "warning"
        
        return self.log_event(
            event_type="policy_decision",
            severity=severity,
            user_id=session.user_id,
            session_id=session.session_id,
            resource=resource,
            action=action,
            outcome=decision,
            policy_id=policy_id,
            denied_reason=denied_reason,
        )
    
    def log_stepup_challenge(
        self,
        session: AuthenticationSession,
        challenge_id: str,
        challenge_type: str,
        outcome: str,
        attempts: int = 0,
    ) -> AuditEvent:
        """Log a step-up challenge event."""
        severity = "info" if outcome == "completed" else "warning"
        
        return self.log_event(
            event_type="stepup_challenge",
            severity=severity,
            user_id=session.user_id,
            session_id=session.session_id,
            resource="stepup_auth",
            action=challenge_type,
            outcome=outcome,
            challenge_id=challenge_id,
            attempts=attempts,
        )
    
    def log_session_termination(
        self,
        session: AuthenticationSession,
        reason: str,
    ) -> AuditEvent:
        """Log a session termination."""
        return self.log_event(
            event_type="session_termination",
            severity="warning",
            user_id=session.user_id,
            session_id=session.session_id,
            resource="session",
            action="terminate",
            outcome="completed",
            termination_reason=reason,
        )
    
    def log_anomaly_detected(
        self,
        session: AuthenticationSession,
        anomaly_type: str,
        severity: str,
        description: str,
    ) -> AuditEvent:
        """Log an anomaly detection event."""
        return self.log_event(
            event_type="anomaly_detected",
            severity=severity,
            user_id=session.user_id,
            session_id=session.session_id,
            resource="behavior_monitor",
            action="anomaly_detection",
            outcome="detected",
            anomaly_type=anomaly_type,
            description=description,
        )
    
    def query_events(
        self,
        query: AuditQuery,
    ) -> List[AuditEvent]:
        """Query audit events with filters."""
        events = self._audit_log
        
        # Apply filters
        if query.user_id:
            event_ids = self._events_by_user.get(query.user_id, set())
            events = [e for e in events if e.event_id in event_ids]

        if query.session_id:
            event_ids = self._events_by_session.get(query.session_id, set())
            events = [e for e in events if e.event_id in event_ids]
        
        if query.event_type:
            events = [e for e in events if e.event_type == query.event_type]
        
        if query.severity:
            events = [e for e in events if e.severity == query.severity]
        
        if query.outcome:
            events = [e for e in events if e.outcome == query.outcome]
        
        if query.start_time:
            events = [e for e in events if e.timestamp >= query.start_time]
        
        if query.end_time:
            events = [e for e in events if e.timestamp <= query.end_time]
        
        if query.resource:
            events = [e for e in events if query.resource in e.resource]
        
        # _audit_log is append-only in chronological order; reverse is O(N)
        events = list(reversed(events))
        
        # Apply pagination
        return events[query.offset:query.offset + query.limit]
    
    def get_user_audit_trail(
        self,
        user_id: str,
        limit: int = 100,
    ) -> List[AuditEvent]:
        """Get audit trail for a specific user."""
        query = AuditQuery(user_id=user_id, limit=limit)
        return self.query_events(query)
    
    def get_session_audit_trail(
        self,
        session_id: str,
        limit: int = 100,
    ) -> List[AuditEvent]:
        """Get audit trail for a specific session."""
        query = AuditQuery(session_id=session_id, limit=limit)
        return self.query_events(query)
    
    def get_summary(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> AuditSummary:
        """Get a summary of audit events."""
        if not start_time:
            start_time = datetime.now(timezone.utc) - timedelta(hours=24)
        if not end_time:
            end_time = datetime.now(timezone.utc)
        
        # Filter by time range
        events = [
            e for e in self._audit_log
            if start_time <= e.timestamp <= end_time
        ]
        
        # Count by type
        events_by_type: Dict[str, int] = {}
        for e in events:
            events_by_type[e.event_type] = events_by_type.get(e.event_type, 0) + 1
        
        # Count by severity
        events_by_severity: Dict[str, int] = {}
        for e in events:
            events_by_severity[e.severity] = events_by_severity.get(e.severity, 0) + 1
        
        # Count by outcome
        events_by_outcome: Dict[str, int] = {}
        for e in events:
            events_by_outcome[e.outcome] = events_by_outcome.get(e.outcome, 0) + 1
        
        # Recent events
        recent = sorted(events, key=lambda e: e.timestamp, reverse=True)[:10]
        recent_events = [
            {
                "event_id": e.event_id,
                "event_type": e.event_type,
                "severity": e.severity,
                "user_id": e.user_id,
                "outcome": e.outcome,
                "timestamp": e.timestamp.isoformat(),
            }
            for e in recent
        ]
        
        return AuditSummary(
            total_events=len(events),
            events_by_type=events_by_type,
            events_by_severity=events_by_severity,
            events_by_outcome=events_by_outcome,
            recent_events=recent_events,
            time_range={
                "start": start_time.isoformat(),
                "end": end_time.isoformat(),
            },
        )
    
    def export_events(
        self,
        query: AuditQuery,
        format: str = "json",
    ) -> str:
        """Export audit events in specified format."""
        events = self.query_events(query)
        
        if format == "json":
            return json.dumps([
                {
                    "event_id": e.event_id,
                    "timestamp": e.timestamp.isoformat(),
                    "event_type": e.event_type,
                    "severity": e.severity,
                    "user_id": e.user_id,
                    "session_id": e.session_id,
                    "resource": e.resource,
                    "action": e.action,
                    "outcome": e.outcome,
                    "risk_score": e.risk_score,
                    "trust_level": e.trust_level,
                    "metadata": e.metadata,
                }
                for e in events
            ], indent=2, default=str)
        
        elif format == "csv":
            lines = ["event_id,timestamp,event_type,severity,user_id,session_id,resource,action,outcome,risk_score,trust_level"]
            for e in events:
                lines.append(f'{e.event_id},{e.timestamp.isoformat()},{e.event_type},{e.severity},{e.user_id},{e.session_id or ""},{e.resource},{e.action},{e.outcome},{e.risk_score or ""},{e.trust_level or ""}')
            return "\n".join(lines)
        
        return ""
    
    def get_compliance_report(
        self,
        start_time: datetime,
        end_time: datetime,
    ) -> Dict[str, Any]:
        """Generate a compliance report for audit period."""
        summary = self.get_summary(start_time, end_time)

        # Calculate additional compliance metrics
        total_auths = summary.events_by_type.get("authentication_attempt", 0)
        failed_auths = summary.events_by_outcome.get("failed", 0)
        return {
            "report_period": summary.time_range,
            "total_events": summary.total_events,
            "authentication_metrics": {
                "total_attempts": total_auths,
                "failed_attempts": failed_auths,
                "failure_rate": failed_auths / total_auths if total_auths > 0 else 0,
            },
            "security_metrics": {
                "anomalies_detected": summary.events_by_type.get("anomaly_detected", 0),
                "stepup_challenges": summary.events_by_type.get("stepup_challenge", 0),
                "trust_changes": summary.events_by_type.get("trust_change", 0),
                "session_terminations": summary.events_by_type.get("session_termination", 0),
                "suspicious_events": sum(
                    count for event_type, count in summary.events_by_type.items()
                    if "anomaly" in event_type or "risk" in event_type
                ),
            },
            "severity_breakdown": summary.events_by_severity,
            "outcome_breakdown": summary.events_by_outcome,
            "recommendations": self._generate_recommendations(summary),
        }
    
    def _generate_recommendations(
        self,
        summary: AuditSummary,
    ) -> List[str]:
        """Generate recommendations based on audit summary."""
        recommendations = []
        
        # High failure rate
        total_auths = summary.events_by_type.get("authentication_attempt", 0)
        failed_auths = summary.events_by_outcome.get("failed", 0)
        if total_auths > 0 and failed_auths / total_auths > 0.1:
            recommendations.append(
                "High authentication failure rate detected. Consider reviewing account lockout policies."
            )
        
        # Many anomalies
        anomalies = summary.events_by_type.get("anomaly_detected", 0)
        if anomalies > 10:
            recommendations.append(
                f"Multiple anomalies detected ({anomalies}). Review behavior monitoring thresholds."
            )
        
        # Session terminations
        terminations = summary.events_by_type.get("session_termination", 0)
        if terminations > 5:
            recommendations.append(
                f"Multiple session terminations ({terminations}). Investigate potential security incidents."
            )
        
        # Critical events
        critical = summary.events_by_severity.get("critical", 0)
        if critical > 0:
            recommendations.append(
                f"Critical security events detected ({critical}). Immediate investigation required."
            )
        
        if not recommendations:
            recommendations.append("No significant security concerns detected.")
        
        return recommendations
    
    def get_stats(self) -> Dict[str, Any]:
        """Get audit service statistics."""
        return {
            "total_events": len(self._audit_log),
            "total_users": len(self._events_by_user),
            "total_sessions": len(self._events_by_session),
            "max_capacity": self._max_events,
            "utilization_percent": (len(self._audit_log) / self._max_events) * 100,
            "events_by_type": {
                et: len([e for e in self._audit_log if e.event_type == et])
                for et in set(e.event_type for e in self._audit_log)
            },
        }


# Global audit service instance
_audit_service: Optional[AuditService] = None


def get_audit_service() -> AuditService:
    """Get the global audit service instance."""
    global _audit_service
    if _audit_service is None:
        store = get_adaptive_auth_store()
        _audit_service = AuditService(store)
    return _audit_service


def reset_audit_service() -> None:
    """Reset the audit service (for testing)."""
    global _audit_service
    _audit_service = None