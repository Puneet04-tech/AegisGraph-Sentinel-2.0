"""
Step-Up Authentication Service for Adaptive Authentication & Continuous Authorization.

Manages step-up authentication challenges for high-risk operations,
supporting multiple authentication methods and challenge types.
"""

from __future__ import annotations

import secrets
import string

import pyotp
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
import uuid

from .models import (
    ChallengeType,
    StepUpChallenge,
)
from .store import AdaptiveAuthStore, LRUCache, get_adaptive_auth_store


@dataclass
class ChallengeConfig:
    """Configuration for a challenge type."""
    challenge_type: ChallengeType
    enabled: bool = True
    timeout_seconds: int = 300
    max_attempts: int = 3
    require_verification_code: bool = True


@dataclass
class ChallengeResponse:
    """Response to a challenge verification request."""
    challenge_id: str
    success: bool
    message: str
    remaining_attempts: int
    new_trust_level: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class StepUpAuthService:
    """
    Step-up authentication service.

    Manages the lifecycle of step-up authentication challenges,
    including creation, verification, and expiration.
    """

    DEFAULT_CONFIGS = {
        ChallengeType.SMS_OTP: ChallengeConfig(
            challenge_type=ChallengeType.SMS_OTP,
            timeout_seconds=300,
            max_attempts=3,
        ),
        ChallengeType.EMAIL_OTP: ChallengeConfig(
            challenge_type=ChallengeType.EMAIL_OTP,
            timeout_seconds=600,
            max_attempts=5,
        ),
        ChallengeType.TOTP: ChallengeConfig(
            challenge_type=ChallengeType.TOTP,
            timeout_seconds=60,
            max_attempts=3,
        ),
        ChallengeType.PUSH_NOTIFICATION: ChallengeConfig(
            challenge_type=ChallengeType.PUSH_NOTIFICATION,
            timeout_seconds=120,
            max_attempts=2,
        ),
        ChallengeType.BIOMETRIC: ChallengeConfig(
            challenge_type=ChallengeType.BIOMETRIC,
            timeout_seconds=60,
            max_attempts=3,
        ),
        ChallengeType.HARDWARE_TOKEN: ChallengeConfig(
            challenge_type=ChallengeType.HARDWARE_TOKEN,
            timeout_seconds=60,
            max_attempts=3,
        ),
        ChallengeType.SECURITY_QUESTIONS: ChallengeConfig(
            challenge_type=ChallengeType.SECURITY_QUESTIONS,
            timeout_seconds=600,
            max_attempts=3,
        ),
        ChallengeType.CALLBACK: ChallengeConfig(
            challenge_type=ChallengeType.CALLBACK,
            timeout_seconds=300,
            max_attempts=2,
        ),
    }

    def __init__(self, store: AdaptiveAuthStore):
        self.store = store
        self._configs = self.DEFAULT_CONFIGS.copy()
        self._totp_secrets: LRUCache = LRUCache(maxsize=100000)  # user_id -> secret
        self._verification_codes: Dict[str, str] = {}  # challenge_id -> code
        self._callback_pending: Dict[str, Dict[str, Any]] = {}  # challenge_id -> callback info

    def configure_challenge(
        self,
        challenge_type: ChallengeType,
        enabled: Optional[bool] = None,
        timeout_seconds: Optional[int] = None,
        max_attempts: Optional[int] = None,
    ) -> None:
        """Configure challenge settings."""
        config = self._configs.get(challenge_type)
        if config is None:
            config = ChallengeConfig(challenge_type=challenge_type)
            self._configs[challenge_type] = config

        if enabled is not None:
            config.enabled = enabled
        if timeout_seconds is not None:
            config.timeout_seconds = timeout_seconds
        if max_attempts is not None:
            config.max_attempts = max_attempts

    def create_challenge(
        self,
        session_id: str,
        user_id: str,
        challenge_type: ChallengeType,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Optional[StepUpChallenge]:
        """Create a new step-up challenge."""
        config = self._configs.get(challenge_type)
        if not config or not config.enabled:
            return None

        # Generate challenge
        challenge = StepUpChallenge(
            challenge_id=str(uuid.uuid4()),
            session_id=session_id,
            user_id=user_id,
            challenge_type=challenge_type,
            status="pending",
            created_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(seconds=config.timeout_seconds),
            attempts=0,
            max_attempts=config.max_attempts,
            metadata=metadata or {},
        )

        # Generate verification code based on type
        if config.require_verification_code:
            code = self._generate_verification_code(challenge_type)
            challenge.verification_code = code
            self._verification_codes[challenge.challenge_id] = code

            # For OTP types, generate and store the actual OTP
            if challenge_type in (ChallengeType.SMS_OTP, ChallengeType.EMAIL_OTP):
                otp = self._generate_otp()
                self._verification_codes[f"{challenge.challenge_id}_otp"] = otp
                challenge.metadata["otp_to_send"] = otp  # In production, sent via SMS/email

        # Store challenge
        self.store._challenges[challenge.challenge_id] = challenge

        # Update session with active challenge
        session = self.store.get_session_unsafe(session_id)
        if session:
            session.active_challenges.append(challenge)
            self.store.update_session(session)

        return challenge

    def _generate_verification_code(self, challenge_type: ChallengeType) -> str:
        """Generate a cryptographically secure verification code based on challenge type."""
        if challenge_type in (ChallengeType.TOTP, ChallengeType.HARDWARE_TOKEN):
            alphabet = string.ascii_uppercase + string.digits
            return ''.join(secrets.choice(alphabet) for _ in range(8))
        return ''.join(secrets.choice(string.digits) for _ in range(6))

    def _generate_otp(self) -> str:
        """Generate a cryptographically secure numeric OTP."""
        return ''.join(secrets.choice(string.digits) for _ in range(6))

    def verify_challenge(
        self,
        challenge_id: str,
        response: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> ChallengeResponse:
        """Verify a challenge response."""
        challenge = self.store.get_challenge(challenge_id)
        if not challenge:
            return ChallengeResponse(
                challenge_id=challenge_id,
                success=False,
                message="Challenge not found or expired",
                remaining_attempts=0,
            )

        # Check if expired
        if challenge.is_expired():
            challenge.status = "expired"
            self.store.update_challenge(challenge)
            return ChallengeResponse(
                challenge_id=challenge_id,
                success=False,
                message="Challenge has expired",
                remaining_attempts=0,
            )

        # Check max attempts
        if challenge.is_max_attempts_reached():
            challenge.status = "failed"
            challenge.failure_reason = "Maximum attempts exceeded"
            self.store.update_challenge(challenge)
            self._verification_codes.pop(challenge_id, None)
            self._verification_codes.pop(f"{challenge_id}_otp", None)
            self._callback_pending.pop(challenge_id, None)
            return ChallengeResponse(
                challenge_id=challenge_id,
                success=False,
                message="Maximum attempts exceeded",
                remaining_attempts=0,
            )

        # Increment attempts
        challenge.attempts += 1

        # Verify based on challenge type
        verified = self._verify_response(challenge, response, context)

        if verified:
            challenge.status = "completed"
            challenge.completed_at = datetime.now(timezone.utc)
            self.store.update_challenge(challenge)

            # Update session trust
            session = self.store.get_session_unsafe(challenge.session_id)
            if session:
                session.trust.trust_score = min(1.0, session.trust.trust_score + 0.2)
                # Remove from active challenges
                session.active_challenges = [
                    c for c in session.active_challenges
                    if c.challenge_id != challenge_id
                ]
                self.store.update_session(session)

            return ChallengeResponse(
                challenge_id=challenge_id,
                success=True,
                message="Challenge verified successfully",
                remaining_attempts=challenge.max_attempts - challenge.attempts,
                new_trust_level="elevated",
            )
        else:
            remaining = challenge.max_attempts - challenge.attempts
            self.store.update_challenge(challenge)

            return ChallengeResponse(
                challenge_id=challenge_id,
                success=False,
                message=f"Incorrect verification code. {remaining} attempts remaining.",
                remaining_attempts=remaining,
            )

    def _verify_response(
        self,
        challenge: StepUpChallenge,
        response: str,
        context: Optional[Dict[str, Any]],
    ) -> bool:
        """Verify the response based on challenge type."""
        challenge_type = challenge.challenge_type

        if challenge_type == ChallengeType.TOTP:
            return self._verify_totp(challenge.user_id, response)

        elif challenge_type == ChallengeType.SMS_OTP:
            stored_otp = self._verification_codes.get(f"{challenge.challenge_id}_otp")
            return stored_otp == response

        elif challenge_type == ChallengeType.EMAIL_OTP:
            stored_otp = self._verification_codes.get(f"{challenge.challenge_id}_otp")
            return stored_otp == response

        elif challenge_type == ChallengeType.PUSH_NOTIFICATION:
            return response.lower() == "approved"

        elif challenge_type == ChallengeType.BIOMETRIC:
            return context and context.get("biometric_verified", False)

        elif challenge_type == ChallengeType.HARDWARE_TOKEN:
            return self._verify_totp(challenge.user_id, response)

        elif challenge_type == ChallengeType.SECURITY_QUESTIONS:
            correct_answers = challenge.metadata.get("correct_answers", {})
            provided_answers = context.get("answers", {}) if context else {}
            for question, correct in correct_answers.items():
                if provided_answers.get(question, "").lower() != correct.lower():
                    return False
            return True

        elif challenge_type == ChallengeType.CALLBACK:
            return context and context.get("callback_verified", False)

        return False

    def _verify_totp(self, user_id: str, response: str) -> bool:
        """Verify a TOTP code."""
        secret = self._totp_secrets.get(user_id)
        if not secret:
            secret = self._get_or_create_totp_secret(user_id)

        return pyotp.TOTP(secret).verify(response, valid_window=1)

    def _get_or_create_totp_secret(self, user_id: str) -> str:
        """Return the existing TOTP secret for a user, or generate one if absent."""
        secret = self._totp_secrets.get(user_id)
        if secret:
            return secret
        secret = pyotp.random_base32()
        self._totp_secrets[user_id] = secret
        return secret

    def revoke_totp_secret(self, user_id: str) -> None:
        """Remove a user's TOTP secret to force re-enrollment."""
        self._totp_secrets.pop(user_id, None)

    def initiate_callback(
        self,
        challenge_id: str,
        phone_number: str,
    ) -> bool:
        """Initiate a callback challenge."""
        challenge = self.store.get_challenge(challenge_id)
        if not challenge or challenge.challenge_type != ChallengeType.CALLBACK:
            return False

        self._callback_pending[challenge_id] = {
            "phone_number": phone_number,
            "initiated_at": datetime.now(timezone.utc),
        }

        challenge.metadata["callback_initiated"] = True
        self.store.update_challenge(challenge)
        return True

    def get_active_challenges(
        self,
        session_id: str,
    ) -> List[StepUpChallenge]:
        """Get all active challenges for a session."""
        return self.store.get_session_challenges(session_id)

    def cancel_challenge(self, challenge_id: str) -> bool:
        """Cancel a pending challenge."""
        challenge = self.store.get_challenge(challenge_id)
        if challenge and challenge.status == "pending":
            challenge.status = "cancelled"
            self.store.update_challenge(challenge)
            return True
        return False

    def get_challenge_info(self, challenge_id: str) -> Optional[Dict[str, Any]]:
        """Get challenge information."""
        challenge = self.store.get_challenge(challenge_id)
        if not challenge:
            return None

        return {
            "challenge_id": challenge.challenge_id,
            "session_id": challenge.session_id,
            "user_id": challenge.user_id,
            "challenge_type": challenge.challenge_type.value,
            "status": challenge.status,
            "created_at": challenge.created_at.isoformat(),
            "expires_at": challenge.expires_at.isoformat(),
            "attempts": challenge.attempts,
            "max_attempts": challenge.max_attempts,
            "remaining_attempts": challenge.max_attempts - challenge.attempts,
        }

    def setup_totp(self, user_id: str) -> Dict[str, Any]:
        """Set up TOTP for a user."""
        secret = self._get_or_create_totp_secret(user_id)
        totp = pyotp.TOTP(secret)
        return {
            "secret": secret,
            "provisioning_uri": totp.provisioning_uri(name=user_id, issuer_name="AegisGraph"),
            "algorithm": "SHA1",
            "digits": 6,
            "period": 30,
        }

    def get_available_challenge_types(self) -> List[Dict[str, Any]]:
        """Get list of available and configured challenge types."""
        types_info = []
        for challenge_type, config in self._configs.items():
            types_info.append({
                "type": challenge_type.value,
                "name": challenge_type.name.replace("_", " ").title(),
                "enabled": config.enabled,
                "timeout_seconds": config.timeout_seconds,
                "max_attempts": config.max_attempts,
            })
        return types_info


# Global service instance
_service: Optional[StepUpAuthService] = None


def get_stepup_auth_service() -> StepUpAuthService:
    """Get the global step-up auth service instance."""
    global _service
    if _service is None:
        store = get_adaptive_auth_store()
        _service = StepUpAuthService(store)
    return _service


def reset_service() -> None:
    """Reset the service (for testing)."""
    global _service
    _service = None
