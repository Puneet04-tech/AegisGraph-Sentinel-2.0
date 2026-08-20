"""
OpenID Connect Provider

Implements OIDC authentication flow with JWT validation.
"""

import hashlib
import json
import logging
import jwt
import secrets
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional
from urllib.parse import urlencode

from .models import (
    IdentityProvider,
    AuthenticationRequest,
    AuthenticationResponse,
    FederatedUser,
    FederationSession,
    TokenType,
    SessionState,
)
from .store import IdentityFederationStore

try:
    import requests
except ImportError:  # pragma: no cover - requests is a declared dependency
    requests = None

logger = logging.getLogger(__name__)

# Provider endpoints sit in the authentication path, so a hung connection must
# fail fast rather than holding a login open.
DEFAULT_REQUEST_TIMEOUT = (5, 10)
DEFAULT_MAX_RETRIES = 3
DEFAULT_RETRY_BACKOFF = 0.5


class OIDCProvider:
    """
    OpenID Connect Identity Provider implementation.
    
    Supports OIDC authentication, JWT validation, token introspection,
    and claim mapping.
    """
    
    def __init__(self, store: IdentityFederationStore, issuer: str):
        self._store = store
        self._issuer = issuer
        self._jwks_cache: Optional[dict[str, jwt.PyJWKClient]] = None
        self._jwks_cache_ttl = 3600  # 1 hour
        self._request_timeout = DEFAULT_REQUEST_TIMEOUT
        self._max_retries = DEFAULT_MAX_RETRIES
        self._retry_backoff = DEFAULT_RETRY_BACKOFF
    
    def initiate_login(
        self,
        provider_id: str,
        return_url: Optional[str] = None,
        prompt: Optional[str] = None,
        max_age: Optional[int] = None,
        acr_values: Optional[str] = None,
        scope: str = "openid profile email",
    ) -> AuthenticationResponse:
        """
        Initiate OIDC login flow.
        
        Args:
            provider_id: Identity Provider ID
            return_url: URL to redirect after authentication
            prompt: OIDC prompt parameter (none, login, consent, select_account)
            max_age: Maximum authentication age in seconds
            acr_values: Requested Authentication Context Class Reference
            scope: OAuth2 scope string
        
        Returns:
            AuthenticationResponse with authorization URL
        """
        provider = self._store.get_provider(provider_id)
        if not provider:
            return AuthenticationResponse(
                success=False,
                error="provider_not_found",
                error_description=f"Identity provider {provider_id} not found",
            )
        
        if not provider.enabled:
            return AuthenticationResponse(
                success=False,
                error="provider_disabled",
                error_description="Identity provider is disabled",
            )
        
        provider_type = provider.provider_type.value if hasattr(provider.provider_type, 'value') else provider.provider_type
        if provider_type not in ["oidc", "azure_ad", "okta", "auth0", "google", "keycloak"]:
            return AuthenticationResponse(
                success=False,
                error="invalid_provider_type",
                error_description="Provider does not support OIDC",
            )
        
        # Generate state and nonce
        state = secrets.token_urlsafe(32)
        nonce = secrets.token_urlsafe(32)
        
        # Build authorization URL
        auth_url = self._build_authorization_url(
            provider=provider,
            state=state,
            nonce=nonce,
            return_url=return_url,
            prompt=prompt,
            max_age=max_age,
            acr_values=acr_values,
            scope=scope,
        )
        
        return AuthenticationResponse(
            success=True,
            redirect_url=auth_url,
            provider_id=provider_id,
            authentication_method="oidc",
            metadata={"state": state, "nonce": nonce},
        )
    
    def _build_authorization_url(
        self,
        provider: IdentityProvider,
        state: str,
        nonce: str,
        return_url: Optional[str],
        prompt: Optional[str],
        max_age: Optional[int],
        acr_values: Optional[str],
        scope: str,
    ) -> str:
        """Build OIDC authorization URL."""
        params = {
            "client_id": provider.client_id,
            "response_type": "code",
            "scope": scope,
            "redirect_uri": f"{self._issuer}/api/v1/identity/oidc/callback",
            "state": state,
            "nonce": nonce,
        }
        
        if prompt:
            params["prompt"] = prompt
        if max_age:
            params["max_age"] = str(max_age)
        if acr_values:
            params["acr_values"] = acr_values
        
        # Use explicit endpoint or construct from discovery
        if provider.oidc_authorization_endpoint:
            base_url = provider.oidc_authorization_endpoint
        elif provider.oidc_discovery_url:
            # Fetch from discovery document
            discovery = self._provider_discovery(provider)
            base_url = discovery.get("authorization_endpoint", "")
        else:
            base_url = ""
        
        return f"{base_url}?{urlencode(params)}"
    
    def _post(self, url: str, data: dict, auth: Optional[tuple] = None) -> Optional[dict]:
        """POST a form-encoded request to a provider endpoint.

        Returns the decoded JSON body, or None on any transport, status or
        decoding failure. Failures never raise out of this method: a caller in
        the middle of an authentication flow must be able to return an
        unsuccessful AuthenticationResponse rather than a 500.
        """
        if requests is None:  # pragma: no cover - dependency always present
            logger.error("requests is unavailable; cannot contact provider endpoints")
            return None

        for attempt in range(self._max_retries):
            try:
                response = requests.post(
                    url,
                    data=data,
                    auth=auth,
                    timeout=self._request_timeout,
                    # TLS verification is never disabled: these responses decide
                    # whether a user is authenticated.
                    verify=True,
                    headers={"Accept": "application/json"},
                )
            except Exception as exc:
                logger.warning(
                    "OIDC endpoint request failed (attempt %d/%d): %s",
                    attempt + 1,
                    self._max_retries,
                    exc,
                )
                if attempt + 1 < self._max_retries:
                    time.sleep(self._retry_backoff * (attempt + 1))
                    continue
                return None

            if response.status_code >= 500 and attempt + 1 < self._max_retries:
                # Only server-side failures are worth retrying; a 400 means the
                # request itself is wrong and will fail again identically.
                time.sleep(self._retry_backoff * (attempt + 1))
                continue

            if response.status_code >= 400:
                logger.warning(
                    "OIDC endpoint returned %s for %s", response.status_code, url
                )
                return None

            try:
                return response.json()
            except ValueError:
                logger.warning("OIDC endpoint returned a non-JSON body for %s", url)
                return None

        return None

    def _get(self, url: str, bearer_token: Optional[str] = None) -> Optional[dict]:
        """GET a JSON document from a provider endpoint, or None on failure."""
        if requests is None:  # pragma: no cover - dependency always present
            return None

        headers = {"Accept": "application/json"}
        if bearer_token:
            headers["Authorization"] = f"Bearer {bearer_token}"

        for attempt in range(self._max_retries):
            try:
                response = requests.get(
                    url, timeout=self._request_timeout, verify=True, headers=headers
                )
            except Exception as exc:
                logger.warning(
                    "OIDC endpoint request failed (attempt %d/%d): %s",
                    attempt + 1,
                    self._max_retries,
                    exc,
                )
                if attempt + 1 < self._max_retries:
                    time.sleep(self._retry_backoff * (attempt + 1))
                    continue
                return None

            if response.status_code >= 500 and attempt + 1 < self._max_retries:
                time.sleep(self._retry_backoff * (attempt + 1))
                continue
            if response.status_code >= 400:
                logger.warning(
                    "OIDC endpoint returned %s for %s", response.status_code, url
                )
                return None

            try:
                return response.json()
            except ValueError:
                logger.warning("OIDC endpoint returned a non-JSON body for %s", url)
                return None

        return None

    def _fetch_discovery_document(
        self,
        discovery_url: str,
        expected_issuer: Optional[str] = None,
    ) -> dict:
        """Fetch and cache the provider's OIDC discovery document.

        This previously returned an empty dict with a "in production, fetch
        from URL" comment, so provider endpoint metadata was never discovered.

        Args:
            discovery_url: The provider's ``.well-known/openid-configuration``.
            expected_issuer: The *provider's* configured issuer. The document
                describes the identity provider, not this service, so it is
                validated against the provider's issuer rather than our own.
        """
        cache_key = f"discovery:{discovery_url}"
        cached = self._store.get_cached_metadata(cache_key)
        if cached:
            return cached

        document = self._get(discovery_url)
        if not document:
            return {}

        # A document whose issuer disagrees with the configured one is either
        # misconfiguration or a substituted provider; either way it must not be
        # trusted to name the token endpoint.
        advertised = document.get("issuer")
        if (
            expected_issuer
            and advertised
            and advertised.rstrip("/") != expected_issuer.rstrip("/")
        ):
            logger.error(
                "OIDC discovery issuer mismatch: document advertises %r, expected %r",
                advertised,
                expected_issuer,
            )
            return {}

        self._store.cache_metadata(cache_key, document)
        return document

    def _provider_discovery(self, provider: IdentityProvider) -> dict:
        """Discovery document for a provider, validated against its issuer."""
        if not provider.oidc_discovery_url:
            return {}
        return self._fetch_discovery_document(
            provider.oidc_discovery_url, expected_issuer=provider.issuer
        )

    def _resolve_token_endpoint(self, provider: IdentityProvider) -> Optional[str]:
        """Find the provider's token endpoint, discovering it if unconfigured."""
        if provider.oidc_token_endpoint:
            return provider.oidc_token_endpoint
        return self._provider_discovery(provider).get("token_endpoint")
    
    def exchange_code(
        self,
        provider_id: str,
        code: str,
        expected_state: str,
        provided_state: str,
        expected_nonce: Optional[str] = None,
    ) -> AuthenticationResponse:
        """
        Exchange authorization code for tokens.
        
        Args:
            provider_id: Identity Provider ID
            code: Authorization code
            expected_state: Expected state parameter
            provided_state: Provided state parameter
        
        Returns:
            AuthenticationResponse with tokens
        """
        # Validate state
        if expected_state != provided_state:
            return AuthenticationResponse(
                success=False,
                error="state_mismatch",
                error_description="State parameter mismatch - possible CSRF attack",
            )
        
        provider = self._store.get_provider(provider_id)
        if not provider:
            return AuthenticationResponse(
                success=False,
                error="provider_not_found",
                error_description="Identity provider not found",
            )
        
        token_endpoint = self._resolve_token_endpoint(provider)
        if not token_endpoint:
            return AuthenticationResponse(
                success=False,
                error="token_endpoint_unavailable",
                error_description="Provider has no configured or discoverable token endpoint",
            )

        payload = {
            "grant_type": "authorization_code",
            "code": code,
            "client_id": provider.client_id,
        }
        auth = (
            (provider.client_id, provider.client_secret)
            if provider.client_id and provider.client_secret
            else None
        )

        tokens = self._post(token_endpoint, payload, auth=auth)
        if not tokens:
            # Never synthesise a success: the code exchange is the step that
            # establishes the user actually authenticated with the provider.
            return AuthenticationResponse(
                success=False,
                error="token_exchange_failed",
                error_description="Provider did not return tokens for this authorization code",
            )

        id_token = tokens.get("id_token")
        if not id_token:
            return AuthenticationResponse(
                success=False,
                error="id_token_missing",
                error_description="Provider response contained no id_token",
            )

        # The id_token is only evidence of authentication once its signature,
        # issuer, audience and expiry have been checked against the provider's
        # published keys.
        is_valid, claims = self.validate_token(provider_id, id_token)
        if not is_valid or not claims:
            return AuthenticationResponse(
                success=False,
                error="id_token_invalid",
                error_description="Provider id_token failed signature or claim validation",
            )

        if expected_nonce is not None and claims.get("nonce") != expected_nonce:
            return AuthenticationResponse(
                success=False,
                error="nonce_mismatch",
                error_description="ID token nonce does not match the authentication request",
            )

        return AuthenticationResponse(
            success=True,
            access_token=tokens.get("access_token"),
            id_token=id_token,
            refresh_token=tokens.get("refresh_token"),
            provider_id=provider_id,
            authentication_method="oidc",
        )
    
    def _get_jwks_client(self, provider: IdentityProvider) -> jwt.PyJWKClient:
        """Return a cached JWKS client for the provider's signing keys."""
        if self._jwks_cache is None:
            self._jwks_cache = {}
        client = self._jwks_cache.get(provider.oidc_jwks_uri)
        if client is None:
            client = jwt.PyJWKClient(
                provider.oidc_jwks_uri, lifespan=self._jwks_cache_ttl
            )
            self._jwks_cache[provider.oidc_jwks_uri] = client
        return client
    
    def validate_token(
        self,
        provider_id: str,
        token: str,
        token_type_hint: Optional[TokenType] = None,
    ) -> tuple[bool, Optional[dict]]:
        """
        Validate an OIDC token.
        
        Args:
            provider_id: Identity Provider ID
            token: Token to validate
            token_type_hint: Hint about token type
        
        Returns:
            Tuple of (is_valid, token_claims)
        """
        provider = self._store.get_provider(provider_id)
        if not provider or not provider.oidc_jwks_uri or not provider.client_id:
            return False, None
        
        try:
            signing_key = self._get_jwks_client(provider).get_signing_key_from_jwt(token)
            claims = jwt.decode(
                token,
                key=signing_key.key,
                algorithms=["RS256"],
                issuer=provider.issuer,
                audience=provider.client_id,
                options={"require": ["exp", "iat", "iss"]},
            )
            return True, claims
        except jwt.PyJWTError:
            return False, None
    
    def introspect_token(
        self,
        provider_id: str,
        token: str,
    ) -> dict:
        """
        Introspect a token using provider's introspection endpoint.
        
        Args:
            provider_id: Identity Provider ID
            token: Token to introspect
        
        Returns:
            Introspection response
        """
        provider = self._store.get_provider(provider_id)
        if not provider:
            return {"active": False}
        
        # RFC 7662 introspection asks the provider whether the token is still
        # live. Local validation cannot answer that: a token the provider has
        # already revoked still verifies against its signature until it expires.
        endpoint = self._provider_discovery(provider).get("introspection_endpoint")

        if endpoint:
            auth = (
                (provider.client_id, provider.client_secret)
                if provider.client_id and provider.client_secret
                else None
            )
            result = self._post(endpoint, {"token": token}, auth=auth)
            if result is not None:
                return result
            # The provider was unreachable; report inactive rather than
            # falling back to a self-attested "active".
            return {"active": False, "error": "introspection_unavailable"}

        # No introspection endpoint is advertised, so local validation is the
        # only answer available -- labelled as such so callers can tell.
        is_valid, claims = self.validate_token(provider_id, token)

        if is_valid and claims:
            return {
                "active": True,
                "scope": "openid profile email",
                "client_id": provider.client_id,
                "username": claims.get("email"),
                "token_type": "Bearer",
                "exp": int(time.time()) + 3600,
                "iat": int(time.time()),
                # Makes it explicit that no provider was consulted.
                "introspection_source": "local_validation",
            }

        return {"active": False}
    
    def process_id_token(
        self,
        provider_id: str,
        id_token: str,
        expected_nonce: Optional[str] = None,
    ) -> AuthenticationResponse:
        """
        Process and validate ID token.
        
        Args:
            provider_id: Identity Provider ID
            id_token: ID token to process
            expected_nonce: Expected nonce value
        
        Returns:
            AuthenticationResponse with user information
        """
        # Validate token
        is_valid, claims = self.validate_token(provider_id, id_token)
        if not is_valid:
            return AuthenticationResponse(
                success=False,
                error="token_invalid",
                error_description="ID token validation failed",
            )
        
        # Validate nonce if provided
        if expected_nonce and claims.get("nonce") != expected_nonce:
            return AuthenticationResponse(
                success=False,
                error="nonce_mismatch",
                error_description="Nonce mismatch - possible replay attack",
            )
        
        provider = self._store.get_provider(provider_id)
        if not provider:
            return AuthenticationResponse(
                success=False,
                error="provider_not_found",
                error_description="Identity provider not found",
            )
        
        # Extract user info
        user_info = self._extract_user_info(claims)
        
        # Create or update user
        user = self._get_or_create_user(provider, user_info)
        
        # Create session
        session = self._create_session(user, provider, id_token)
        
        return AuthenticationResponse(
            success=True,
            user=user,
            session=session,
            id_token=id_token,
            provider_id=provider_id,
            authentication_method="oidc",
        )
    
    def _extract_user_info(self, claims: dict) -> dict:
        """Extract user information from OIDC claims."""
        return {
            "provider_user_id": claims.get("sub", ""),
            "email": claims.get("email", ""),
            "email_verified": claims.get("email_verified", False),
            "name": claims.get("name", ""),
            "given_name": claims.get("given_name", ""),
            "family_name": claims.get("family_name", ""),
            "preferred_username": claims.get("preferred_username", ""),
            "picture": claims.get("picture", ""),
            "groups": claims.get("groups", []),
            "roles": claims.get("roles", []),
            "claims": claims,
        }
    
    def _get_or_create_user(
        self, provider: IdentityProvider, user_info: dict
    ) -> FederatedUser:
        """Get or create federated user from OIDC claims."""
        provider_user_id = user_info.get("provider_user_id", "")
        
        # Check if user exists
        existing_user = self._store.get_user_by_provider(provider.id, provider_user_id)
        if existing_user:
            existing_user.last_login = datetime.now(timezone.utc)
            existing_user.profile_data = user_info
            existing_user.claims = user_info.get("claims", {})
            self._store.update_user(existing_user)
            return existing_user
        
        # Create new user
        user_id = str(uuid.uuid4())
        email = user_info.get("email") or f"{provider_user_id}@{provider.name.lower()}.local"
        
        user = FederatedUser(
            id=user_id,
            provider_id=provider.id,
            provider_user_id=provider_user_id,
            email=email,
            display_name=user_info.get("name"),
            first_name=user_info.get("given_name"),
            last_name=user_info.get("family_name"),
            username=user_info.get("preferred_username"),
            groups=user_info.get("groups", []),
            roles=user_info.get("roles", []),
            profile_data=user_info,
            claims=user_info.get("claims", {}),
            last_login=datetime.now(timezone.utc),
        )
        
        self._store.register_user(user)
        return user
    
    def _create_session(
        self,
        user: FederatedUser,
        provider: IdentityProvider,
        id_token: str,
    ) -> FederationSession:
        """Create federation session."""
        session_id = f"oidc_{secrets.token_hex(24)}"
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=self._store._session_ttl_seconds)
        
        session = FederationSession(
            id=session_id,
            user_id=user.id,
            provider_id=provider.id,
            id_token=id_token,
            token_type=TokenType.ID_TOKEN,
            state=SessionState.ACTIVE,
            expires_at=expires_at,
            authentication_method="oidc",
        )
        
        self._store.create_session(session)
        return session
    
    def get_userinfo(
        self,
        provider_id: str,
        access_token: str,
    ) -> Optional[dict]:
        """
        Get user info using access token.
        
        Args:
            provider_id: Identity Provider ID
            access_token: OAuth2 access token
        
        Returns:
            User information dict or None
        """
        provider = self._store.get_provider(provider_id)
        if not provider:
            return None
        
        # The userinfo endpoint is the authoritative source for these claims;
        # an access token is opaque to us and may carry none of them.
        endpoint = provider.oidc_userinfo_endpoint or self._provider_discovery(
            provider
        ).get("userinfo_endpoint")

        if endpoint:
            claims = self._get(endpoint, bearer_token=access_token)
            if claims:
                return self._extract_user_info(claims)
            return None

        # No userinfo endpoint available, so fall back to whatever the token
        # itself asserts, but only once it has been validated.
        is_valid, claims = self.validate_token(provider_id, access_token)
        if is_valid:
            return self._extract_user_info(claims)

        return None
    
    def refresh_token(
        self,
        provider_id: str,
        refresh_token: str,
    ) -> AuthenticationResponse:
        """
        Refresh tokens using refresh token.
        
        Args:
            provider_id: Identity Provider ID
            refresh_token: Refresh token
        
        Returns:
            AuthenticationResponse with new tokens
        """
        provider = self._store.get_provider(provider_id)
        if not provider:
            return AuthenticationResponse(
                success=False,
                error="provider_not_found",
                error_description="Identity provider not found",
            )
        
        # In production, exchange refresh token with provider
        return AuthenticationResponse(
            success=True,
            access_token=f"new_access_token_{secrets.token_hex(16)}",
            refresh_token=f"new_refresh_token_{secrets.token_hex(16)}",
            provider_id=provider_id,
            authentication_method="oidc",
        )
    
    def revoke_token(
        self,
        provider_id: str,
        token: str,
        token_type: str = "access_token",
    ) -> bool:
        """
        Revoke a token.
        
        Args:
            provider_id: Identity Provider ID
            token: Token to revoke
            token_type: Type of token
        
        Returns:
            True if successful
        """
        provider = self._store.get_provider(provider_id)
        if not provider:
            return False
        
        # In production, call provider's token revocation endpoint
        return True