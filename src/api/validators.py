"""
API Input Validation Layer for AegisGraph Sentinel 2.0

Comprehensive validation for:
- Transaction amounts (positive, max limits, precision)
- Timestamps (ISO 8601 UTC format, not future, not too old)
- Account IDs (format, length, allowed characters)
- Currency codes (ISO 4217 compliance)
- Transaction modes (valid types)
- Biometric data (array constraints, value ranges)
- Rate limiting (per account, API key, IP)
"""

from datetime import datetime, timezone, timedelta
from collections import defaultdict
from typing import Tuple, Optional, List, Dict, Any
import threading
import logging

logger = logging.getLogger(__name__)


class ValidationError(Exception):
    """Custom validation exception with helpful suggestions."""

    def __init__(
        self,
        field: str,
        value: Any,
        constraint: str,
        suggestion: str,
    ):
        self.field = field
        self.value = value
        self.constraint = constraint
        self.suggestion = suggestion
        super().__init__(
            f"Validation failed for field '{field}': {constraint}. {suggestion}"
        )


# Valid ISO 4217 currency codes
VALID_CURRENCY_CODES = {
    "INR",
    "USD",
    "EUR",
    "GBP",
    "JPY",
    "AUD",
    "CAD",
    "CHF",
    "CNY",
    "SEK",
    "NZD",
    "SGD",
    "HKD",
    "AED",
    "SAR",
    "MXN",
    "BRL",
    "ZAR",
}

# Valid transaction modes
VALID_MODES = {
    "UPI",
    "NEFT",
    "IMPS",
    "SWIFT",
    "ACH",
    "WIRE",
    "CREDIT_CARD",
    "DEBIT_CARD",
    "NET_BANKING",
}

CANONICAL_TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


class TransactionValidator:
    """Static validation methods for transaction data."""

    @staticmethod
    def validate_amount(amount: float) -> None:
        """
        Validate transaction amount.

        Constraints:
        - Must be positive
        - Max 10 million
        - Max 2 decimal places
        """
        if amount <= 0:
            raise ValidationError(
                field="amount",
                value=amount,
                constraint="positive",
                suggestion="Amount must be greater than 0",
            )

        if amount > 10_000_000:
            raise ValidationError(
                field="amount",
                value=amount,
                constraint="max_amount",
                suggestion="Amount cannot exceed 10,000,000",
            )

        # Check decimal precision (max 2 places)
        if len(str(amount).split(".")[-1]) > 2:
            raise ValidationError(
                field="amount",
                value=amount,
                constraint="decimal_precision",
                suggestion="Amount must have at most 2 decimal places",
            )

    @staticmethod
    def validate_timestamp(timestamp: str) -> None:
        """
        Validate transaction timestamp.

        Constraints:
        - Must be strict ISO 8601 UTC format (YYYY-MM-DDTHH:MM:SSZ)
        - Must not be in the future (within 60 second tolerance)
        - Must not be older than 90 days
        """
        if not isinstance(timestamp, str):
            raise ValidationError(
                field="timestamp",
                value=timestamp,
                constraint="iso8601_format",
                suggestion="Timestamp must be in ISO 8601 UTC format (YYYY-MM-DDTHH:MM:SSZ)",
            )

        try:
            dt = datetime.strptime(timestamp, CANONICAL_TIMESTAMP_FORMAT).replace(
                tzinfo=timezone.utc
            )

        except (ValueError, TypeError) as e:
            raise ValidationError(
                field="timestamp",
                value=timestamp,
                constraint="iso8601_format",
                suggestion="Timestamp must be in ISO 8601 UTC format (YYYY-MM-DDTHH:MM:SSZ)",
            ) from e

        now = datetime.now(timezone.utc)
        tolerance = timedelta(seconds=60)

        # Check if timestamp is in the future (allow 60 second tolerance)
        if dt > now + tolerance:
            raise ValidationError(
                field="timestamp",
                value=timestamp,
                constraint="not_future",
                suggestion="Timestamp cannot be in the future",
            )

        # Check if timestamp is too old (>90 days)
        max_age = timedelta(days=90)
        if now - dt > max_age:
            raise ValidationError(
                field="timestamp",
                value=timestamp,
                constraint="not_too_old",
                suggestion="Timestamp cannot be older than 90 days",
            )

    @staticmethod
    def normalize_timestamp(timestamp: Any) -> str:
        """
        Normalize a timestamp to canonical ISO 8601 UTC format.

        Accepted inputs:
        - Unix epoch seconds
        - timezone-aware ISO 8601 strings
        """
        try:
            if isinstance(timestamp, (int, float)) and not isinstance(timestamp, bool):
                dt = datetime.fromtimestamp(timestamp, tz=timezone.utc)
            elif isinstance(timestamp, str):
                dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
                if dt.tzinfo is None:
                    raise ValidationError(
                        field="timestamp",
                        value=timestamp,
                        constraint="iso8601_format",
                        suggestion=(
                            "Timestamp must include timezone information and use "
                            "ISO 8601 UTC format (YYYY-MM-DDTHH:MM:SSZ)"
                        ),
                    )
            else:
                raise TypeError("Unsupported timestamp type")
        except (ValueError, TypeError) as e:
            if isinstance(e, ValidationError):
                raise
            raise ValidationError(
                field="timestamp",
                value=timestamp,
                constraint="iso8601_format",
                suggestion=(
                    "Timestamp must be in ISO 8601 UTC format "
                    "(YYYY-MM-DDTHH:MM:SSZ) or be a Unix epoch value"
                ),
            ) from e

        return dt.astimezone(timezone.utc).strftime(CANONICAL_TIMESTAMP_FORMAT)

    @staticmethod
    def validate_account_id(account_id: str, field_name: str = "account_id") -> None:
        """
        Validate account ID format.

        Constraints:
        - 3-50 characters
        - Alphanumeric + dash and underscore only
        """
        if not account_id or len(account_id) < 3 or len(account_id) > 50:
            raise ValidationError(
                field=field_name,
                value=account_id,
                constraint="length",
                suggestion="Account ID must be 3-50 characters",
            )

        if not all(c.isalnum() or c in "-_" for c in account_id):
            raise ValidationError(
                field=field_name,
                value=account_id,
                constraint="format",
                suggestion="Account ID can only contain alphanumeric characters, dashes, and underscores",
            )

    @staticmethod
    def validate_currency_code(currency: str) -> None:
        """
        Validate currency code.

        Constraints:
        - Must be valid ISO 4217 code
        """
        if currency.upper() not in VALID_CURRENCY_CODES:
            raise ValidationError(
                field="currency",
                value=currency,
                constraint="iso4217",
                suggestion=f"Currency must be a valid ISO 4217 code. Examples: {', '.join(sorted(list(VALID_CURRENCY_CODES)[:5]))}",
            )

    @staticmethod
    def validate_mode(mode: str) -> None:
        """
        Validate transaction mode.

        Constraints:
        - Must be from valid modes list
        """
        if mode.upper() not in VALID_MODES:
            raise ValidationError(
                field="mode",
                value=mode,
                constraint="invalid_mode",
                suggestion=f"Mode must be one of: {', '.join(sorted(VALID_MODES))}",
            )

    @staticmethod
    def validate_biometrics(hold_times: List[float], flight_times: List[float]) -> None:
        """
        Validate biometric data.

        Constraints:
        - Arrays can have 0-1000 elements each
        - Each value must be 0-10000ms
        - Non-negative values
        """
        for arr_name, arr in [("hold_times", hold_times), ("flight_times", flight_times)]:
            if len(arr) > 1000:
                raise ValidationError(
                    field=arr_name,
                    value=arr,
                    constraint="max_length",
                    suggestion=f"{arr_name} cannot have more than 1000 elements",
                )

            for val in arr:
                if val < 0 or val > 10000:
                    raise ValidationError(
                        field=arr_name,
                        value=val,
                        constraint="value_range",
                        suggestion=f"{arr_name} values must be between 0 and 10000 (milliseconds)",
                    )

    @staticmethod
    def validate_cross_fields(source_account: str, target_account: str) -> None:
        """
        Validate cross-field constraints.

        Constraint:
        - source_account must not equal target_account
        """
        if source_account == target_account:
            raise ValidationError(
                field="target_account",
                value=target_account,
                constraint="different_accounts",
                suggestion="Source and target accounts must be different",
            )


class RateLimiter:
    """Thread-safe rate limiter for API endpoints."""

    def __init__(
        self,
        account_limit: int = 100,  # per minute
        api_key_limit: int = 1000,  # per minute
        ip_limit: int = 500,  # per minute
    ):
        self.account_limit = account_limit
        self.api_key_limit = api_key_limit
        self.ip_limit = ip_limit

        # Tracking: {identifier: (request_count, window_start_time)}
        self.account_requests: Dict[str, Tuple[int, datetime]] = defaultdict(
            lambda: (0, datetime.now(timezone.utc))
        )
        self.apikey_requests: Dict[str, Tuple[int, datetime]] = defaultdict(
            lambda: (0, datetime.now(timezone.utc))
        )
        self.ip_requests: Dict[str, Tuple[int, datetime]] = defaultdict(
            lambda: (0, datetime.now(timezone.utc))
        )

        self._lock = threading.RLock()

    def _check_limit(
        self,
        identifier: str,
        tracking_dict: Dict[str, Tuple[int, datetime]],
        limit: int,
    ) -> Tuple[bool, Optional[int]]:
        """
        Check if identifier is within rate limit.

        Returns:
            (is_allowed, retry_after_seconds)
        """
        now = datetime.now(timezone.utc)
        count, window_start = tracking_dict.get(identifier, (0, now))

        # Check if we're in a new minute
        if (now - window_start).total_seconds() >= 60:
            # Reset window
            tracking_dict[identifier] = (1, now)
            return True, None

        # Still in current window
        if count < limit:
            tracking_dict[identifier] = (count + 1, window_start)
            return True, None
        else:
            # Rate limited
            retry_after = int(
                60 - (now - window_start).total_seconds() + 1
            )
            return False, retry_after

    def check_account_limit(self, account_id: str) -> Tuple[bool, Optional[int]]:
        """Check if account is within rate limit."""
        with self._lock:
            return self._check_limit(
                account_id, self.account_requests, self.account_limit
            )

    def check_api_key_limit(self, api_key: str) -> Tuple[bool, Optional[int]]:
        """Check if API key is within rate limit."""
        with self._lock:
            return self._check_limit(
                api_key, self.apikey_requests, self.api_key_limit
            )

    def check_ip_limit(self, ip_address: str) -> Tuple[bool, Optional[int]]:
        """Check if IP is within rate limit."""
        with self._lock:
            return self._check_limit(ip_address, self.ip_requests, self.ip_limit)

    def reset(self):
        """Reset all tracking data (useful for testing)."""
        with self._lock:
            self.account_requests.clear()
            self.apikey_requests.clear()
            self.ip_requests.clear()


# Global rate limiter instance
_rate_limiter: Optional[RateLimiter] = None


def get_rate_limiter() -> RateLimiter:
    """Get or create the global rate limiter."""
    global _rate_limiter
    if _rate_limiter is None:
        _rate_limiter = RateLimiter()
    return _rate_limiter


def reset_rate_limiter():
    """Reset the global rate limiter (for testing)."""
    global _rate_limiter
    if _rate_limiter is not None:
        _rate_limiter.reset()
