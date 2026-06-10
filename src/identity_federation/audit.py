"""
Identity Federation Audit Logger

Provides comprehensive audit logging for identity events.
"""

import uuid
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Optional

from .models import AuditEvent
from .store import IdentityFederationStore


class AuditLogger:
    """
    Provides comprehensive audit logging for identity federation events.
    
    Logs all authentication, authorization, and provisioning events.
    """
    
    def __init__(self, store: IdentityFederationStore, retention_days: int = 90):
        self._store = store
        self._retention_days = retention_days
        
        # In-memory audit log (in production, use persistent storage)
        self._audit_log: dict[str, AuditEvent] = {}
        
        # Event counters
        self._counters: dict[str, int] = defaultdict(int)
    
    def log(
        self,
        action: str,
        resource_type: str,
        user_id: Optional[str] = None,
        username: Optional[str] = None,
        resource_id: Optional[str] = None,
        success: bool = True,
        error_message: Optional[str] = None,
        provider_id: Optional[str] = None,
        session_id: Optional[str] = None,
        authentication_method: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        metadata: Optional[dict] = None,
    ) -> AuditEvent:
        """
        Log an audit event.
        
        Args:
            action: Action performed (e.g., "login", "logout", "token_refresh")
            resource_type: Type of resource (e.g., "session", "user", "provider")
            user_id: User ID
            username: Username
            resource_id: Resource ID
            success: Whether action was successful
            error_message: Error message if failed
            provider_id: Identity Provider ID
            session_id: Session ID
            authentication_method: Auth method used
            ip_address: Client IP address
            user_agent: Client user agent
            metadata: Additional metadata
        
        Returns:
            Created AuditEvent
        """
        event = AuditEvent(
            id=str(uuid.uuid4()),
            timestamp=datetime.utcnow(),
            user_id=user_id,
            username=username,
            ip_address=ip_address,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            success=success,
            error_message=error_message,
            provider_id=provider_id,
            session_id=session_id,
            authentication_method=authentication_method,
            user_agent=user_agent,
            metadata=metadata or {},
        )
        
        self._audit_log[event.id] = event
        self._counters[action] += 1
        
        # Cleanup old events periodically
        if len(self._audit_log) > 10000:
            self._cleanup_old_events()
        
        return event
    
    def log_authentication(
        self,
        success: bool,
        provider_id: str,
        user_id: Optional[str] = None,
        username: Optional[str] = None,
        authentication_method: str = "unknown",
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        error_message: Optional[str] = None,
    ) -> AuditEvent:
        """Log an authentication event."""
        return self.log(
            action="authentication",
            resource_type="identity",
            user_id=user_id,
            username=username,
            success=success,
            error_message=error_message,
            provider_id=provider_id,
            authentication_method=authentication_method,
            ip_address=ip_address,
            user_agent=user_agent,
            metadata={"result": "success" if success else "failure"},
        )
    
    def log_authorization(
        self,
        success: bool,
        user_id: str,
        resource_type: str,
        resource_id: str,
        action: str,
        ip_address: Optional[str] = None,
        error_message: Optional[str] = None,
    ) -> AuditEvent:
        """Log an authorization event."""
        return self.log(
            action=f"authorization_{action}",
            resource_type=resource_type,
            user_id=user_id,
            resource_id=resource_id,
            success=success,
            error_message=error_message,
            ip_address=ip_address,
        )
    
    def log_session(
        self,
        action: str,
        session_id: str,
        user_id: Optional[str] = None,
        provider_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        success: bool = True,
        error_message: Optional[str] = None,
    ) -> AuditEvent:
        """Log a session event."""
        return self.log(
            action=f"session_{action}",
            resource_type="session",
            user_id=user_id,
            resource_id=session_id,
            success=success,
            error_message=error_message,
            provider_id=provider_id,
            session_id=session_id,
            ip_address=ip_address,
        )
    
    def log_provider_event(
        self,
        action: str,
        provider_id: str,
        user_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        success: bool = True,
        error_message: Optional[str] = None,
        metadata: Optional[dict] = None,
    ) -> AuditEvent:
        """Log an identity provider event."""
        return self.log(
            action=f"provider_{action}",
            resource_type="provider",
            user_id=user_id,
            resource_id=provider_id,
            success=success,
            error_message=error_message,
            provider_id=provider_id,
            ip_address=ip_address,
            metadata=metadata,
        )
    
    def log_provisioning(
        self,
        action: str,
        user_id: str,
        provider_id: str,
        success: bool = True,
        error_message: Optional[str] = None,
        metadata: Optional[dict] = None,
    ) -> AuditEvent:
        """Log a provisioning event."""
        return self.log(
            action=f"provisioning_{action}",
            resource_type="user",
            user_id=user_id,
            resource_id=user_id,
            success=success,
            error_message=error_message,
            provider_id=provider_id,
            metadata=metadata,
        )
    
    def log_token_event(
        self,
        action: str,
        user_id: Optional[str] = None,
        client_id: Optional[str] = None,
        success: bool = True,
        error_message: Optional[str] = None,
        ip_address: Optional[str] = None,
        metadata: Optional[dict] = None,
    ) -> AuditEvent:
        """Log a token event."""
        return self.log(
            action=f"token_{action}",
            resource_type="token",
            user_id=user_id,
            resource_id=client_id,
            success=success,
            error_message=error_message,
            ip_address=ip_address,
            metadata=metadata,
        )
    
    def query(
        self,
        user_id: Optional[str] = None,
        provider_id: Optional[str] = None,
        action: Optional[str] = None,
        resource_type: Optional[str] = None,
        success: Optional[bool] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[AuditEvent]:
        """
        Query audit events.
        
        Args:
            user_id: Filter by user ID
            provider_id: Filter by provider ID
            action: Filter by action
            resource_type: Filter by resource type
            success: Filter by success status
            start_time: Start of time range
            end_time: End of time range
            limit: Maximum number of events to return
            offset: Offset for pagination
        
        Returns:
            List of matching AuditEvents
        """
        results = []
        
        for event in self._audit_log.values():
            # Apply filters
            if user_id and event.user_id != user_id:
                continue
            if provider_id and event.provider_id != provider_id:
                continue
            if action and event.action != action:
                continue
            if resource_type and event.resource_type != resource_type:
                continue
            if success is not None and event.success != success:
                continue
            if start_time and event.timestamp < start_time:
                continue
            if end_time and event.timestamp > end_time:
                continue
            
            results.append(event)
        
        # Sort by timestamp descending
        results.sort(key=lambda e: e.timestamp, reverse=True)
        
        # Apply pagination
        return results[offset:offset + limit]
    
    def get_user_activity(
        self,
        user_id: str,
        days: int = 30,
    ) -> dict:
        """
        Get activity summary for a user.
        
        Args:
            user_id: User ID
            days: Number of days to look back
        
        Returns:
            Activity summary
        """
        start_time = datetime.utcnow() - timedelta(days=days)
        
        events = self.query(
            user_id=user_id,
            start_time=start_time,
            limit=1000,
        )
        
        summary = {
            "total_events": len(events),
            "successful_events": sum(1 for e in events if e.success),
            "failed_events": sum(1 for e in events if not e.success),
            "actions": defaultdict(int),
            "providers": defaultdict(int),
            "last_activity": None,
        }
        
        for event in events:
            summary["actions"][event.action] += 1
            if event.provider_id:
                summary["providers"][event.provider_id] += 1
        
        if events:
            summary["last_activity"] = events[0].timestamp.isoformat()
        
        return summary
    
    def get_security_summary(
        self,
        days: int = 7,
    ) -> dict:
        """
        Get security event summary.
        
        Args:
            days: Number of days to look back
        
        Returns:
            Security summary
        """
        start_time = datetime.utcnow() - timedelta(days=days)
        
        # Query security-relevant events
        auth_events = self.query(
            action="authentication",
            start_time=start_time,
            limit=10000,
        )
        
        failed_auth = [e for e in auth_events if not e.success]
        
        # Count failed attempts by IP
        failed_by_ip = defaultdict(int)
        for event in failed_auth:
            if event.ip_address:
                failed_by_ip[event.ip_address] += 1
        
        return {
            "period_days": days,
            "total_authentications": len(auth_events),
            "successful_authentications": sum(1 for e in auth_events if e.success),
            "failed_authentications": len(failed_by_ip),
            "unique_users": len(set(e.user_id for e in auth_events if e.user_id)),
            "suspicious_ips": [
                {"ip": ip, "failed_attempts": count}
                for ip, count in failed_by_ip.items()
                if count >= 5
            ],
            "providers_used": list(set(e.provider_id for e in auth_events if e.provider_id)),
        }
    
    def get_stats(self) -> dict:
        """Get audit logger statistics."""
        return {
            "total_events": len(self._audit_log),
            "counters": dict(self._counters),
            "retention_days": self._retention_days,
        }
    
    def _cleanup_old_events(self) -> int:
        """Remove events older than retention period."""
        cutoff = datetime.utcnow() - timedelta(days=self._retention_days)
        
        to_remove = [
            event_id
            for event_id, event in self._audit_log.items()
            if event.timestamp < cutoff
        ]
        
        for event_id in to_remove:
            del self._audit_log[event_id]
        
        return len(to_remove)
    
    def export_events(
        self,
        start_time: datetime,
        end_time: datetime,
        format: str = "json",
    ) -> list[dict]:
        """
        Export audit events for a time period.
        
        Args:
            start_time: Start of time range
            end_time: End of time range
            format: Output format (json, csv)
        
        Returns:
            List of event dictionaries
        """
        events = self.query(
            start_time=start_time,
            end_time=end_time,
            limit=100000,
        )
        
        if format == "json":
            return [
                {
                    "id": e.id,
                    "timestamp": e.timestamp.isoformat(),
                    "action": e.action,
                    "resource_type": e.resource_type,
                    "resource_id": e.resource_id,
                    "user_id": e.user_id,
                    "username": e.username,
                    "provider_id": e.provider_id,
                    "success": e.success,
                    "error_message": e.error_message,
                    "ip_address": e.ip_address,
                    "metadata": e.metadata,
                }
                for e in events
            ]
        
        return []