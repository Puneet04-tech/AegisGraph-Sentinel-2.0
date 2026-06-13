"""
Identity Federation Data Store

Thread-safe in-memory store with O(1) lookups using dictionaries.
"""

import threading
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Optional
from .models import (
    IdentityProvider,
    FederatedUser,
    FederationSession,
    RoleMapping,
    IdentityMapping,
    SessionState,
)


class IdentityFederationStore:
    """
    Thread-safe in-memory store for identity federation data.
    
    Uses dictionary-based O(1) lookups for optimal performance.
    Supports session caching and federation metadata caching.
    """
    
    def __init__(self, session_ttl: int = 3600, cache_size: int = 10000):
        """
        Initialize the store.
        
        Args:
            session_ttl: Session time-to-live in seconds (default: 1 hour)
            cache_size: Maximum number of sessions to cache
        """
        self._lock = threading.RLock()
        
        # Identity Providers - O(1) lookup by ID
        self._providers: dict[str, IdentityProvider] = {}
        
        # Federated Users - O(1) lookup by ID and composite keys
        self._users: dict[str, FederatedUser] = {}
        self._users_by_email: dict[str, FederatedUser] = {}
        self._users_by_provider: dict[str, dict[str, FederatedUser]] = defaultdict(dict)
        
        # Federation Sessions - O(1) lookup with LRU-style management
        self._sessions: dict[str, FederationSession] = {}
        self._sessions_by_user: dict[str, list[str]] = defaultdict(list)
        self._session_ttl = session_ttl
        
        # Role Mappings
        self._role_mappings: dict[str, RoleMapping] = {}
        self._role_mappings_by_provider: dict[str, list[RoleMapping]] = defaultdict(list)
        
        # Identity Mappings
        self._identity_mappings: dict[str, IdentityMapping] = {}
        self._identity_mappings_by_provider: dict[str, list[IdentityMapping]] = defaultdict(list)
        
        # Cache for federation metadata
        self._metadata_cache: dict[str, tuple[datetime, dict]] = {}
        self._metadata_cache_ttl = 300  # 5 minutes
        
        # Statistics
        self._stats = {
            "sessions_created": 0,
            "sessions_expired": 0,
            "sessions_revoked": 0,
            "authentications": 0,
            "cache_hits": 0,
            "cache_misses": 0,
        }
    
    # ==================== Identity Providers ====================
    
    def register_provider(self, provider: IdentityProvider) -> None:
        """Register an identity provider."""
        with self._lock:
            self._providers[provider.id] = provider
    
    def get_provider(self, provider_id: str) -> Optional[IdentityProvider]:
        """Get identity provider by ID - O(1) lookup."""
        return self._providers.get(provider_id)
    
    def list_providers(self, enabled_only: bool = False) -> list[IdentityProvider]:
        """List all registered identity providers."""
        with self._lock:
            providers = list(self._providers.values())
            if enabled_only:
                providers = [p for p in providers if p.enabled]
            return providers
    
    def update_provider(self, provider: IdentityProvider) -> None:
        """Update an identity provider."""
        with self._lock:
            provider.updated_at = datetime.utcnow()
            self._providers[provider.id] = provider
    
    def delete_provider(self, provider_id: str) -> bool:
        """Delete an identity provider."""
        with self._lock:
            if provider_id in self._providers:
                del self._providers[provider_id]
                return True
            return False
    
    # ==================== Federated Users ====================
    
    def register_user(self, user: FederatedUser) -> None:
        """Register a federated user."""
        with self._lock:
            self._users[user.id] = user
            self._users_by_email[user.email] = user
            self._users_by_provider[user.provider_id][user.provider_user_id] = user
    
    def get_user(self, user_id: str) -> Optional[FederatedUser]:
        """Get federated user by ID - O(1) lookup."""
        return self._users.get(user_id)
    
    def get_user_by_email(self, email: str) -> Optional[FederatedUser]:
        """Get federated user by email - O(1) lookup."""
        return self._users_by_email.get(email.lower())
    
    def get_user_by_provider(
        self, provider_id: str, provider_user_id: str
    ) -> Optional[FederatedUser]:
        """Get federated user by provider - O(1) lookup."""
        return self._users_by_provider.get(provider_id, {}).get(provider_user_id)
    
    def list_users_by_provider(self, provider_id: str) -> list[FederatedUser]:
        """List all users for a specific provider."""
        with self._lock:
            return list(self._users_by_provider.get(provider_id, {}).values())
    
    def update_user(self, user: FederatedUser) -> None:
        """Update a federated user."""
        with self._lock:
            user.updated_at = datetime.utcnow()
            self._users[user.id] = user
            self._users_by_email[user.email] = user
    
    def delete_user(self, user_id: str) -> bool:
        """Delete a federated user."""
        with self._lock:
            user = self._users.get(user_id)
            if user:
                del self._users[user_id]
                self._users_by_email.pop(user.email, None)
                self._users_by_provider.get(user.provider_id, {}).pop(
                    user.provider_user_id, None
                )
                return True
            return False
    
    # ==================== Federation Sessions ====================
    
    def create_session(self, session: FederationSession) -> None:
        """Create a new federation session."""
        with self._lock:
            self._sessions[session.id] = session
            self._sessions_by_user[session.user_id].append(session.id)
            self._stats["sessions_created"] += 1
            self._stats["authentications"] += 1
            self._cleanup_expired_sessions()
    
    def get_session(self, session_id: str) -> Optional[FederationSession]:
        """Get session by ID - O(1) lookup."""
        with self._lock:
            session = self._sessions.get(session_id)
            if session and not session.is_expired:
                return session
            elif session and session.is_expired:
                self._expire_session(session)
            return None
    
    def get_session_by_user(self, user_id: str) -> list[FederationSession]:
        """Get all active sessions for a user."""
        with self._lock:
            session_ids = self._sessions_by_user.get(user_id, [])
            sessions = []
            for sid in session_ids:
                session = self._sessions.get(sid)
                if session:
                    if session.is_expired:
                        self._expire_session(session)
                    elif session.state == SessionState.ACTIVE:
                        sessions.append(session)
            return sessions
    
    def update_session(self, session: FederationSession) -> None:
        """Update a session."""
        with self._lock:
            session.last_activity = datetime.utcnow()
            self._sessions[session.id] = session
    
    def revoke_session(self, session_id: str) -> bool:
        """Revoke a session."""
        with self._lock:
            session = self._sessions.get(session_id)
            if session:
                session.state = SessionState.REVOKED
                self._stats["sessions_revoked"] += 1
                return True
            return False
    
    def revoke_user_sessions(self, user_id: str) -> int:
        """Revoke all sessions for a user."""
        with self._lock:
            count = 0
            session_ids = self._sessions_by_user.get(user_id, [])
            for sid in session_ids:
                session = self._sessions.get(sid)
                if session and session.state == SessionState.ACTIVE:
                    session.state = SessionState.REVOKED
                    count += 1
                    self._stats["sessions_revoked"] += 1
            return count
    
    def _expire_session(self, session: FederationSession) -> None:
        """Mark a session as expired."""
        session.state = SessionState.EXPIRED
        self._stats["sessions_expired"] += 1
    
    def _cleanup_expired_sessions(self) -> None:
        """Clean up expired sessions."""
        expired = [
            (sid, s) for sid, s in self._sessions.items()
            if s.is_expired and s.state == SessionState.ACTIVE
        ]
        for sid, session in expired:
            self._expire_session(session)
    
    def cleanup_sessions(self) -> int:
        """Manually trigger session cleanup."""
        with self._lock:
            before = len(self._sessions)
            self._cleanup_expired_sessions()
            return before - len(self._sessions)
    
    # ==================== Role Mappings ====================
    
    def add_role_mapping(self, mapping: RoleMapping) -> None:
        """Add a role mapping."""
        with self._lock:
            self._role_mappings[mapping.id] = mapping
            self._role_mappings_by_provider[mapping.provider_id].append(mapping)
    
    def get_role_mapping(self, mapping_id: str) -> Optional[RoleMapping]:
        """Get role mapping by ID - O(1) lookup."""
        return self._role_mappings.get(mapping_id)
    
    def list_role_mappings(
        self, provider_id: Optional[str] = None, enabled_only: bool = False
    ) -> list[RoleMapping]:
        """List role mappings."""
        with self._lock:
            if provider_id:
                mappings = self._role_mappings_by_provider.get(provider_id, [])
            else:
                mappings = list(self._role_mappings.values())
            
            if enabled_only:
                mappings = [m for m in mappings if m.enabled]
            
            return sorted(mappings, key=lambda m: m.priority, reverse=True)
    
    def delete_role_mapping(self, mapping_id: str) -> bool:
        """Delete a role mapping."""
        with self._lock:
            mapping = self._role_mappings.get(mapping_id)
            if mapping:
                del self._role_mappings[mapping_id]
                provider_mappings = self._role_mappings_by_provider.get(
                    mapping.provider_id, []
                )
                self._role_mappings_by_provider[mapping.provider_id] = [
                    m for m in provider_mappings if m.id != mapping_id
                ]
                return True
            return False
    
    # ==================== Identity Mappings ====================
    
    def add_identity_mapping(self, mapping: IdentityMapping) -> None:
        """Add an identity mapping."""
        with self._lock:
            self._identity_mappings[mapping.id] = mapping
            self._identity_mappings_by_provider[mapping.provider_id].append(mapping)
    
    def get_identity_mapping(self, mapping_id: str) -> Optional[IdentityMapping]:
        """Get identity mapping by ID - O(1) lookup."""
        return self._identity_mappings.get(mapping_id)
    
    def list_identity_mappings(
        self, provider_id: Optional[str] = None, enabled_only: bool = False
    ) -> list[IdentityMapping]:
        """List identity mappings."""
        with self._lock:
            if provider_id:
                mappings = self._identity_mappings_by_provider.get(provider_id, [])
            else:
                mappings = list(self._identity_mappings.values())
            
            if enabled_only:
                mappings = [m for m in mappings if m.enabled]
            
            return mappings
    
    def delete_identity_mapping(self, mapping_id: str) -> bool:
        """Delete an identity mapping."""
        with self._lock:
            mapping = self._identity_mappings.get(mapping_id)
            if mapping:
                del self._identity_mappings[mapping_id]
                provider_mappings = self._identity_mappings_by_provider.get(
                    mapping.provider_id, []
                )
                self._identity_mappings_by_provider[mapping.provider_id] = [
                    m for m in provider_mappings if m.id != mapping_id
                ]
                return True
            return False
    
    # ==================== Metadata Cache ====================
    
    def cache_metadata(self, key: str, metadata: dict) -> None:
        """Cache federation metadata."""
        with self._lock:
            self._metadata_cache[key] = (datetime.utcnow(), metadata)
    
    def get_cached_metadata(self, key: str) -> Optional[dict]:
        """Get cached metadata if not expired."""
        with self._lock:
            if key in self._metadata_cache:
                timestamp, metadata = self._metadata_cache[key]
                if datetime.utcnow() - timestamp < timedelta(seconds=self._metadata_cache_ttl):
                    self._stats["cache_hits"] += 1
                    return metadata
                else:
                    del self._metadata_cache[key]
            self._stats["cache_misses"] += 1
            return None
    
    def invalidate_metadata_cache(self, key: Optional[str] = None) -> None:
        """Invalidate metadata cache."""
        with self._lock:
            if key:
                self._metadata_cache.pop(key, None)
            else:
                self._metadata_cache.clear()
    
    # ==================== Statistics ====================
    
    def get_stats(self) -> dict:
        """Get store statistics."""
        with self._lock:
            return {
                **self._stats,
                "providers_count": len(self._providers),
                "users_count": len(self._users),
                "sessions_active": sum(
                    1 for s in self._sessions.values()
                    if s.state == SessionState.ACTIVE and not s.is_expired
                ),
                "sessions_total": len(self._sessions),
                "role_mappings_count": len(self._role_mappings),
                "identity_mappings_count": len(self._identity_mappings),
            }
    
    def reset_stats(self) -> None:
        """Reset statistics."""
        with self._lock:
            self._stats = {
                "sessions_created": 0,
                "sessions_expired": 0,
                "sessions_revoked": 0,
                "authentications": 0,
                "cache_hits": 0,
                "cache_misses": 0,
            }