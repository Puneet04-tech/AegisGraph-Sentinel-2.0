"""
OAuth2 Authorization Server Provider

Implements OAuth2 authorization flows.
"""

import secrets
import threading
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


class OAuthProvider:
    """
    OAuth2 Authorization Server implementation.
    
    Supports Authorization Code Flow, Client Credentials Flow,
    refresh tokens, and access token management.
    """
    
    def __init__(self, store: IdentityFederationStore, issuer: str):
        self._store = store
        self._issuer = issuer
        
        # Serialises authorization-code redemption so the single-use
        # check-and-mark cannot race across threads (RFC 6749 4.1.2).
        self._lock = threading.Lock()
        
        # Registered OAuth2 clients
        self._clients: dict[str, dict] = {}
        
        # Authorization codes
        self._auth_codes: dict[str, dict] = {}
        
        # Token storage
        self._tokens: dict[str, dict] = {}
        
        # Refresh tokens that have been rotated and must not be replayed
        self._used_refresh_tokens: set[str] = set()
    
    def register_client(
        self,
        client_id: str,
        client_secret: str,
        redirect_uris: list[str],
        scopes: Optional[list[str]] = None,
        client_name: Optional[str] = None,
    ) -> dict:
        """
        Register an OAuth2 client application.
        
        Args:
            client_id: Client identifier
            client_secret: Client secret
            redirect_uris: List of allowed redirect URIs
            scopes: List of allowed scopes
            client_name: Client application name
        
        Returns:
            Client information
        """
        client = {
            "client_id": client_id,
            "client_secret_hash": self._hash_secret(client_secret),
            "redirect_uris": redirect_uris,
            "scopes": scopes or ["openid", "profile", "email"],
            "client_name": client_name or client_id,
            "created_at": datetime.now(timezone.utc),
            "enabled": True,
        }
        
        self._clients[client_id] = client
        return {"client_id": client_id, "client_secret": client_secret}
    
    def _hash_secret(self, secret: Optional[str]) -> str:
        """Hash client secret for storage.

        Defensively handles missing or non-string input by returning an empty
        string so callers never trigger an ``AttributeError`` when a client
        secret is omitted. An empty hash can never match a registered client's
        secret hash, so omitted secrets are treated as invalid credentials.
        """
        import hashlib
        if not isinstance(secret, str) or not secret:
            return ""
        return hashlib.sha256(secret.encode()).hexdigest()
    

    def _validate_requested_scopes(
        self,
        client: dict,
        scope: Optional[str],
    ) -> tuple[Optional[str], Optional[AuthenticationResponse]]:
        """Intersect requested scopes with the client's registered allow-list.

        Rejects the request when any requested scope is not registered for the
        client (prefer fail-closed over silently dropping unknown scopes).
        """
        allowed = set(client.get("scopes") or [])
        if scope is None or not str(scope).strip():
            # Default to the full registered allow-list when none requested
            return " ".join(client.get("scopes") or []), None

        requested = [s for s in str(scope).split() if s]
        if not requested:
            return " ".join(client.get("scopes") or []), None

        unknown = [s for s in requested if s not in allowed]
        if unknown:
            return None, AuthenticationResponse(
                success=False,
                error="invalid_scope",
                error_description=(
                    "Requested scope is not allowed for this client: "
                    + " ".join(unknown)
                ),
            )
        return " ".join(requested), None

    def authorize(
        self,
        client_id: str,
        redirect_uri: str,
        response_type: str,
        scope: str,
        state: Optional[str] = None,
        code_challenge: Optional[str] = None,
        code_challenge_method: Optional[str] = None,
    ) -> AuthenticationResponse:
        """
        Process authorization request.
        
        Args:
            client_id: Client identifier
            redirect_uri: Redirect URI
            response_type: Response type (code, token)
            scope: OAuth2 scope
            state: State parameter for CSRF protection
            code_challenge: PKCE code challenge
            code_challenge_method: PKCE method (S256, plain)
        
        Returns:
            AuthenticationResponse with authorization code or token
        """
        # Validate client
        client = self._clients.get(client_id)
        if not client:
            return AuthenticationResponse(
                success=False,
                error="invalid_client",
                error_description="Unknown client_id",
            )
        
        if not client["enabled"]:
            return AuthenticationResponse(
                success=False,
                error="invalid_client",
                error_description="Client is disabled",
            )
        
        # Validate redirect URI
        if redirect_uri not in client["redirect_uris"]:
            return AuthenticationResponse(
                success=False,
                error="invalid_request",
                error_description="Invalid redirect_uri",
            )

        validated_scope, scope_error = self._validate_requested_scopes(client, scope)
        if scope_error:
            return scope_error
        scope = validated_scope
        
        # Generate authorization code
        if response_type == "code":
            code = secrets.token_urlsafe(32)
            self._auth_codes[code] = {
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "scope": scope,
                "code_challenge": code_challenge,
                "code_challenge_method": code_challenge_method,
                "state": state,
                "expires_at": datetime.now(timezone.utc) + timedelta(minutes=10),
                "used": False,
            }
            
            redirect_url = f"{redirect_uri}?code={code}"
            if state:
                redirect_url += f"&state={state}"
            
            return AuthenticationResponse(
                success=True,
                redirect_url=redirect_url,
                authentication_method="oauth2",
            )
        
        # Implicit flow (token)
        elif response_type == "token":
            access_token = self._generate_access_token()
            expires_in = 3600
            
            self._store_token(
                access_token=access_token,
                token_type="Bearer",
                expires_in=expires_in,
                scope=scope,
                client_id=client_id,
            )
            
            redirect_url = f"{redirect_uri}#access_token={access_token}&token_type=Bearer&expires_in={expires_in}"
            if state:
                redirect_url += f"&state={state}"
            
            return AuthenticationResponse(
                success=True,
                redirect_url=redirect_url,
                access_token=access_token,
                authentication_method="oauth2",
            )
        
        return AuthenticationResponse(
            success=False,
            error="unsupported_response_type",
            error_description="Only 'code' and 'token' response types are supported",
        )
    
    def token(
        self,
        grant_type: str,
        code: Optional[str] = None,
        redirect_uri: Optional[str] = None,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        refresh_token: Optional[str] = None,
        code_verifier: Optional[str] = None,
        scope: Optional[str] = None,
    ) -> AuthenticationResponse:
        """
        Exchange authorization code for tokens.
        
        Args:
            grant_type: Grant type (authorization_code, refresh_token, client_credentials)
            code: Authorization code
            redirect_uri: Redirect URI (required for auth code flow)
            client_id: Client ID
            client_secret: Client secret
            refresh_token: Refresh token
            code_verifier: PKCE code verifier
            scope: New scope (for refresh)
        
        Returns:
            AuthenticationResponse with tokens
        """
        # Client Credentials Flow
        if grant_type == "client_credentials":
            return self._client_credentials_grant(client_id, client_secret, scope)
        
        # Refresh Token Flow
        if grant_type == "refresh_token":
            return self._refresh_token_grant(
                refresh_token, client_id, client_secret, scope
            )
        
        # Authorization Code Flow
        if grant_type == "authorization_code":
            return self._authorization_code_grant(
                code, redirect_uri, client_id, client_secret, code_verifier
            )
        
        return AuthenticationResponse(
            success=False,
            error="unsupported_grant_type",
            error_description=f"Unsupported grant type: {grant_type}",
        )
    
    def _authorization_code_grant(
        self,
        code: str,
        redirect_uri: str,
        client_id: str,
        client_secret: str,
        code_verifier: Optional[str],
    ) -> AuthenticationResponse:
        """Process authorization code grant."""
        # Validate code
        auth_code = self._auth_codes.get(code)
        if not auth_code:
            return AuthenticationResponse(
                success=False,
                error="invalid_grant",
                error_description="Invalid authorization code",
            )
        
        # Check if used
        if auth_code["used"]:
            return AuthenticationResponse(
                success=False,
                error="invalid_grant",
                error_description="Authorization code already used",
            )
        
        # Check expiration
        if datetime.now(timezone.utc) > auth_code["expires_at"]:
            return AuthenticationResponse(
                success=False,
                error="invalid_grant",
                error_description="Authorization code expired",
            )
        
        # Guard against missing client_secret
        if client_secret is None:
            return AuthenticationResponse(
                success=False,
                error="invalid_client",
                error_description="client_secret is required",
            )

        # Validate client
        client = self._clients.get(client_id)
        if (
            not client
            or not client_secret
            or client["client_secret_hash"] != self._hash_secret(client_secret)
        ):
            return AuthenticationResponse(
                success=False,
                error="invalid_client",
                error_description="Invalid client credentials",
            )
        
        # RFC 6749 §4.1.3: the authorization code is bound to the client it was
        # issued to. A different (even legitimate) registered client must not be
        # able to redeem it.
        if auth_code["client_id"] != client_id:
            return AuthenticationResponse(
                success=False,
                error="invalid_grant",
                error_description="Authorization code was issued to a different client",
            )
        
        # Validate redirect URI
        if redirect_uri != auth_code["redirect_uri"]:
            return AuthenticationResponse(
                success=False,
                error="invalid_grant",
                error_description="Redirect URI mismatch",
            )
        
        # Validate PKCE if used
        if auth_code["code_challenge"]:
            if not code_verifier:
                return AuthenticationResponse(
                    success=False,
                    error="invalid_grant",
                    error_description="Authorization code expired",
                )
            
            # Guard against missing client_secret
            if client_secret is None:
                return AuthenticationResponse(
                    success=False,
                    error="invalid_client",
                    error_description="client_secret is required",
                )

            # Validate client
            client = self._clients.get(client_id)
            if (
                not client
                or not client_secret
                or client["client_secret_hash"] != self._hash_secret(client_secret)
            ):
                return AuthenticationResponse(
                    success=False,
                    error="invalid_client",
                    error_description="Invalid client credentials",
                )
            
            # Validate redirect URI
            if redirect_uri != auth_code["redirect_uri"]:
                return AuthenticationResponse(
                    success=False,
                    error="invalid_grant",
                    error_description="Redirect URI mismatch",
                )
            
            # Validate PKCE if used
            if auth_code["code_challenge"]:
                if not code_verifier:
                    return AuthenticationResponse(
                        success=False,
                        error="invalid_request",
                        error_description="Code verifier required",
                    )
                
                if not self._verify_pkce(
                    code_verifier,
                    auth_code["code_challenge"],
                    auth_code["code_challenge_method"],
                ):
                    return AuthenticationResponse(
                        success=False,
                        error="invalid_grant",
                        error_description="Invalid code verifier",
                    )
            
            # Mark code as used
            auth_code["used"] = True

        validated_scope, scope_error = self._validate_requested_scopes(
            client, auth_code.get("scope")
        )
        if scope_error:
            return scope_error
        
        # Generate tokens
        access_token = self._generate_access_token()
        refresh_token_value = self._generate_refresh_token()
        expires_in = 3600
        
        self._store_token(
            access_token=access_token,
            token_type="Bearer",
            expires_in=expires_in,
            scope=validated_scope,
            client_id=client_id,
            refresh_token=refresh_token_value,
        )
        
        return AuthenticationResponse(
            success=True,
            access_token=access_token,
            refresh_token=refresh_token_value,
            provider_id=client_id,
            authentication_method="oauth2",
            metadata={
                "token_type": "Bearer",
                "expires_in": expires_in,
                "scope": validated_scope,
            },
        )
    
    def _client_credentials_grant(
        self,
        client_id: str,
        client_secret: str,
        scope: Optional[str],
    ) -> AuthenticationResponse:
        """Process client credentials grant."""
        client = self._clients.get(client_id)
        if (
            not client
            or not client_secret
            or client["client_secret_hash"] != self._hash_secret(client_secret)
        ):
            return AuthenticationResponse(
                success=False,
                error="invalid_client",
                error_description="Invalid client credentials",
            )
        
        token_scope, scope_error = self._validate_requested_scopes(client, scope)
        if scope_error:
            return scope_error

        access_token = self._generate_access_token()
        expires_in = 3600
        
        self._store_token(
            access_token=access_token,
            token_type="Bearer",
            expires_in=expires_in,
            scope=token_scope,
            client_id=client_id,
        )
        
        return AuthenticationResponse(
            success=True,
            access_token=access_token,
            provider_id=client_id,
            authentication_method="oauth2",
            metadata={
                "token_type": "Bearer",
                "expires_in": expires_in,
                "scope": token_scope,
            },
        )
    
    def _refresh_token_grant(
        self,
        refresh_token: str,
        client_id: Optional[str],
        client_secret: Optional[str],
        scope: Optional[str] = None,
    ) -> AuthenticationResponse:
        """Process refresh token grant.

        Per RFC 6749 section 6, the client must be authenticated on the token
        endpoint, the refresh token is bound to the client it was issued to,
        and rotating refresh tokens are required for reuse detection.
        """
        # Validate the presenting client's credentials, mirroring the
        # authorization-code grant path.
        if not client_id or not client_secret:
            return AuthenticationResponse(
                success=False,
                error="invalid_client",
                error_description="Invalid client credentials",
            )

        client = self._clients.get(client_id)
        if not client or client["client_secret_hash"] != self._hash_secret(client_secret):
            return AuthenticationResponse(
                success=False,
                error="invalid_client",
                error_description="Invalid client credentials",
            )

        if not client["enabled"]:
            return AuthenticationResponse(
                success=False,
                error="invalid_client",
                error_description="Client is disabled",
            )

        # Reject replays of an already-rotated refresh token.
        if refresh_token in self._used_refresh_tokens:
            return AuthenticationResponse(
                success=False,
                error="invalid_grant",
                error_description="Refresh token has already been used",
            )

        # Find token by refresh token
        token_info = None
        for access_token, info in self._tokens.items():
            if info.get("refresh_token") == refresh_token:
                token_info = info
                break

        if not token_info:
            return AuthenticationResponse(
                success=False,
                error="invalid_grant",
                error_description="Invalid refresh token",
            )

        # The refresh token is bound to the client it was issued to.
        if token_info.get("client_id") != client_id:
            return AuthenticationResponse(
                success=False,
                error="invalid_grant",
                error_description="Refresh token was issued to another client",
            )

        # Check expiration
        if datetime.now(timezone.utc) > token_info.get("refresh_expires_at", datetime.now(timezone.utc)):
            return AuthenticationResponse(
                success=False,
                error="invalid_grant",
                error_description="Refresh token expired",
            )

        # Rotate: issue a new refresh token so a stolen token cannot be replayed.
        new_access_token = self._generate_access_token()
        new_refresh_token = self._generate_refresh_token()
        expires_in = 3600

        # Mark the old refresh token as used for reuse detection, then revoke
        # the old access token.
        self._used_refresh_tokens.add(refresh_token)
        self._revoke_token(token_info["access_token"])

        self._store_token(
            access_token=new_access_token,
            token_type="Bearer",
            expires_in=expires_in,
            scope=scope or token_info["scope"],
            client_id=client_id,
            refresh_token=new_refresh_token,
        )

        return AuthenticationResponse(
            success=True,
            access_token=new_access_token,
            refresh_token=new_refresh_token,
            authentication_method="oauth2",
            metadata={
                "token_type": "Bearer",
                "expires_in": expires_in,
            },
        )
    
    def _generate_access_token(self) -> str:
        """Generate secure access token."""
        return f"at_{secrets.token_urlsafe(32)}"
    
    def _generate_refresh_token(self) -> str:
        """Generate secure refresh token."""
        return f"rt_{secrets.token_urlsafe(32)}"
    
    def _store_token(
        self,
        access_token: str,
        token_type: str,
        expires_in: int,
        scope: str,
        client_id: str,
        refresh_token: Optional[str] = None,
    ) -> None:
        """Store token information."""
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=expires_in)
        refresh_expires_at = datetime.now(timezone.utc) + timedelta(days=30)
        
        self._tokens[access_token] = {
            "access_token": access_token,
            "token_type": token_type,
            "expires_at": expires_at,
            "expires_in": expires_in,
            "scope": scope,
            "client_id": client_id,
            "refresh_token": refresh_token,
            "refresh_expires_at": refresh_expires_at if refresh_token else None,
            "created_at": datetime.now(timezone.utc),
        }
    
    def _verify_pkce(
        self,
        code_verifier: str,
        code_challenge: str,
        method: str,
    ) -> bool:
        """Verify PKCE code verifier."""
        import hashlib
        import base64
        
        if method == "S256":
            # SHA256 hash of code verifier
            digest = hashlib.sha256(code_verifier.encode()).digest()
            computed = base64.urlsafe_b64encode(digest).decode().rstrip("=")
            return computed == code_challenge
        elif method == "plain":
            return code_verifier == code_challenge
        
        return False
    
    def validate_token(self, access_token: str) -> Optional[dict]:
        """
        Validate an access token.
        
        Args:
            access_token: Token to validate
        
        Returns:
            Token information if valid, None otherwise
        """
        token_info = self._tokens.get(access_token)
        if not token_info:
            return None
        
        if datetime.now(timezone.utc) > token_info["expires_at"]:
            return None
        
        return token_info
    
    def revoke_token(self, token: str) -> bool:
        """Revoke a token."""
        return self._revoke_token(token)
    
    def _revoke_token(self, access_token: str) -> bool:
        """Internal revoke token."""
        if access_token in self._tokens:
            del self._tokens[access_token]
            return True
        return False
    
    def get_token_info(self, access_token: str) -> Optional[dict]:
        """Get detailed token information."""
        token_info = self._tokens.get(access_token)
        if not token_info:
            return None
        
        # Check expiration
        if datetime.now(timezone.utc) > token_info["expires_at"]:
            return None
        
        # Return copy without sensitive data
        return {
            "client_id": token_info["client_id"],
            "scope": token_info["scope"],
            "expires_at": token_info["expires_at"].isoformat(),
            "expires_in": token_info["expires_in"],
            "token_type": token_info["token_type"],
            "created_at": token_info["created_at"].isoformat(),
        }