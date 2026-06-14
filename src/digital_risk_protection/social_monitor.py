"""
Social Media Monitoring Engine.

Monitors social media for brand abuse and threats.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid

from .models import RiskLevel, SocialMediaAbuse, ThreatStatus
from .store import DRPStore, get_drp_store


class SocialMediaMonitor:
    """Engine for social media monitoring."""

    def __init__(self, store: Optional[DRPStore] = None) -> None:
        """Initialize the engine."""
        self.store = store or get_drp_store()
        self._monitored_accounts: Dict[str, List[str]] = {}

    def register_account(self, platform: str, account_handle: str) -> None:
        """Register an account for monitoring."""
        if platform not in self._monitored_accounts:
            self._monitored_accounts[platform] = []
        if account_handle not in self._monitored_accounts[platform]:
            self._monitored_accounts[platform].append(account_handle)

    def report_abuse(
        self,
        platform: str,
        account_handle: str,
        content: str,
        abuse_type: str,
    ) -> SocialMediaAbuse:
        """Report social media abuse."""
        abuse = SocialMediaAbuse(
            abuse_id=f"sm-{uuid.uuid4().hex[:12]}",
            platform=platform,
            account_handle=account_handle,
            content=content,
            type=abuse_type,
            status=ThreatStatus.NEW,
            sentiment_score=self._analyze_sentiment(content),
        )
        
        self.store.add_social_abuse(abuse)
        
        self.store.log_audit(
            user_id="system",
            action="social_abuse_detected",
            resource_type="social_media_abuse",
            resource_id=abuse.abuse_id,
            details={"platform": platform, "type": abuse_type},
        )
        
        return abuse

    def _analyze_sentiment(self, content: str) -> float:
        """Analyze sentiment of content."""
        negative_words = [
            "scam", "fake", "fraud", "stolen", "hacked", "breach",
            "warning", "alert", "danger", "threat", "phishing",
        ]
        
        content_lower = content.lower()
        negative_count = sum(1 for word in negative_words if word in content_lower)
        
        return min(0.99, negative_count * 0.2)

    def get_abuse_reports(
        self,
        platform: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Get abuse reports."""
        reports = self.store.get_social_abuse(platform)
        
        return [
            {
                "abuse_id": r.abuse_id,
                "platform": r.platform,
                "account_handle": r.account_handle,
                "content": r.content[:100] + "..." if len(r.content) > 100 else r.content,
                "type": r.type,
                "status": r.status.value,
                "sentiment_score": r.sentiment_score,
                "created_at": r.created_at.isoformat(),
            }
            for r in reports
        ]


# Singleton instance
_engine: Optional[SocialMediaMonitor] = None


def get_social_media_monitor() -> SocialMediaMonitor:
    """Get the global engine instance."""
    global _engine
    if _engine is None:
        _engine = SocialMediaMonitor()
    return _engine


def reset_social_media_monitor() -> None:
    """Reset the global engine."""
    global _engine
    _engine = None