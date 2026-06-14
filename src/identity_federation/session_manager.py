"""
Session Manager

Manages federation sessions with secure session handling.
"""

import secrets
from datetime import datetime, timedelta
from typing import Optional

from .models import (
    FederationSession,
    SessionState,
    TokenType,
)
from .store import IdentityFederationStore


class SessionManager:
    """
    Manages federation sessions with secure session handling.
    
    Provides session lifecycle management, validation, and revocation.
    """
    
    def __init__(
        self,
        store: IdentityFederationStore,
        default_ttl: int = 3600,
        max_concurrent_sessions: int = 10,
    ):
        self._store = store
        self._default_ttl = default_ttl
        self._max_concurrent = max_concurrent_sessions
    
    def create_session(
        self,
        user_id: str,
        provider_id: str,
        access_token: Optional[str] = None,
        refresh_token: Optional[str] = None,
        id_token: Optional[str] = None,
        session_index: Optional[str] = None,
        relay_state: Optional[str] = None,
        nonce: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        ttl: Optional[int] = None,
    ) -> FederationSession:
        """
        Create a new federation session.
        
        Args:
            user_id: User ID
            provider_id: Identity Provider ID
            access_token: OAuth2/OIDC access token
            refresh_token: Refresh token
            id_token: OIDC ID token
            session_index: SAML session index
            relay_state: SAML relay state
            nonce: OIDC nonce
            ip_address: Client IP address
            user_agent: Client user agent
            ttl: Session TTL in seconds
        
        Returns:
            Created FederationSession
        """
        session_id = self._generate_session_id()
        expires_at = datetime.utcnow() + timedelta(seconds=ttl or self._default_ttl)
        
        # Determine token type
        token_type = TokenType.ACCESS_TOKEN
        if id_token:
            token_type = TokenType.ID_TOKEN
        elif refresh_token:
            token_type = TokenType.REFRESH_TOKEN
        
        session = FederationSession(
            id=session_id,
            user_id=user_id,
            provider_id=provider_id,
            access_token=access_token,
            refresh_token=refresh_token,
            id_token=id_token,
            token_type=token_type,
            state=SessionState.ACTIVE,
            session_index=session_index,
            relay_state=relay_state,
            nonce=nonce,
            expires_at=expires_at,
            ip_address=ip_address,
            user_agent=user_agent,
        )
        
        self._store.create_session(session)
        
        # Enforce max concurrent sessions
        self._enforce_max_sessions(user_id)
        
        return session
    
    def _generate_session_id(self) -> str:
        """Generate secure session ID."""
        return f"fs_{secrets.token_hex(24)}"
    
    def _enforce_max_sessions(self, user_id: str) -> None:
        """Enforce maximum concurrent sessions per user."""
        sessions = self._store.get_session_by_user(user_id)
        if len(sessions) > self._max_concurrent:
            # Revoke oldest sessions
            sessions_sorted = sorted(sessions, key=lambda s: s.last_activity)
            for session in sessions_sorted[:len(sessions) - self._max_concurrent]:
                self._store.revoke_session(session.id)
    
    def get_session(self, session_id: str) -> Optional[FederationSession]:
        """Get session by ID."""
        return self._store.get_session(session_id)
    
    def get_user_sessions(self, user_id: str) -> list[FederationSession]:
        """Get all active sessions for a user."""
        return self._store.get_session_by_user(user_id)
    
    def validate_session(self, session_id: str) -> tuple[bool, Optional[FederationSession], Optional[str]]:
        """
        Validate a session.
        
        Args:
            session_id: Session ID
        
        Returns:
            Tuple of (is_valid, session, error_message)
        """
        session = self._store.get_session(session_id)
        
        if not session:
            return False, None, "Session not found"
        
        if session.state != SessionState.ACTIVE:
            return False, session, f"Session is {session.state.value}"
        
        if session.is_expired:
            self._store.revoke_session(session_id)
            return False, session, "Session expired"
        
        return True, session, None
    
    def refresh_session(self, session_id: str, ttl: Optional[int] = None) -> bool:
        """
        Refresh a session, extending its expiration.
        
        Args:
            session_id: Session ID
            ttl: New TTL in seconds
        
        Returns:
            True if successful
        """
        session = self._store.get_session(session_id)
        if not session or session.state != SessionState.ACTIVE:
            return False
        
        session.expires_at = datetime.utcnow() + timedelta(seconds=ttl or self._default_ttl)
        session.last_activity = datetime.utcnow()
        self._store.update_session(session)
        
        return True
    
    def revoke_session(self, session_id: str) -> bool:
        """Revoke a session."""
        return self._store.revoke_session(session_id)
    
    def revoke_user_sessions(self, user_id: str, provider_id: Optional[str] = None) -> int:
        """
        Revoke all sessions for a user.
        
        Args:
            user_id: User ID
            provider_id: Optional provider ID to filter by
        
        Returns:
            Number of sessions revoked
        """
        sessions = self._store.get_session_by_user(user_id)
        count = 0
        
        for session in sessions:
            if provider_id is None or session.provider_id == provider_id:
                if self._store.revoke_session(session.id):
                    count += 1
        
        return count
    
    def revoke_expired_sessions(self) -> int:
        """Revoke all expired sessions."""
        return self._store.cleanup_sessions()
    
    def update_session_activity(self, session_id: str) -> bool:
        """Update session last activity timestamp."""
        session = self._store.get_session(session_id)
        if not session or session.state != SessionState.ACTIVE:
            return False
        
        session.last_activity = datetime.utcnow()
        self._store.update_session(session)
        
        return True
    
    def get_session_stats(self, user_id: str) -> dict:
        """Get session statistics for a user."""
        sessions = self._store.get_session_by_user(user_id)
        
        return {
            "total_sessions": len(sessions),
            "active_sessions": sum(1 for s in sessions if s.state == SessionState.ACTIVE),
            "expired_sessions": sum(1 for s in sessions if s.is_expired),
            "sessions_by_provider": self._count_by_provider(sessions),
            "oldest_session": min((s.created_at for s in sessions), default=None),
            "newest_session": max((s.created_at for s in sessions), default=None),
        }
    
    def _count_by_provider(self, sessions: list[FederationSession]) -> dict:
        """Count sessions by provider."""
        counts = {}
        for session in sessions:
            counts[session.provider_id] = counts.get(session.provider_id, 0) + 1
        return counts
    
    def create_anonymous_session(
        self,
        provider_id: str,
        request_id: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> FederationSession:
        """
        Create an anonymous session for pending authentication.
        
        Args:
            provider_id: Identity Provider ID
            request_id: Authentication request ID
            ip_address: Client IP address
            user_agent: Client user agent
        
        Returns:
            Created anonymous FederationSession
        """
        session_id = self._generate_session_id()
        expires_at = datetime.utcnow() + timedelta(minutes=10)  # Short TTL for pending auth
        
        session = FederationSession(
            id=session_id,
            user_id=f"pending_{request_id}",
            provider_id=provider_id,
            state=SessionState.ACTIVE,
            expires_at=expires_at,
            ip_address=ip_address,
            user_agent=user_agent,
            metadata={"pending_auth": True, "request_id": request_id},
        )
        
        self._store.create_session(session)
        return session
    
    def convert_anonymous_to_user_session(
        self,
        anonymous_session_id: str,
        user_id: str,
    ) -> Optional[FederationSession]:
        """
        Convert an anonymous session to a user session.
        
        Args:
            anonymous_session_id: Anonymous session ID
            user_id: Actual user ID
        
        Returns:
            Updated session or None
        """
        session = self._store.get_session(anonymous_session_id)
        if not session:
            return None
        
        # Update user ID and metadata
        session.user_id = user_id
        session.metadata.pop("pending_auth", None)
        session.metadata.pop("request_id", None)
        session.expires_at = datetime.utcnow() + timedelta(seconds=self._default_ttl)
        
        self._store.update_session(session)
        return session