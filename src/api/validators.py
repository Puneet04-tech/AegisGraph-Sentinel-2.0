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

import math
from collections import OrderedDict, defaultdict
from datetime import datetime, timezone, timedelta
from typing import Tuple, Optional, List, Dict, Any
import threading
import logging
from fastapi import Request, Header, HTTPException
import hashlib

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
                if not math.isfinite(val):
                    raise ValidationError(
                        field=arr_name,
                        value=val,
                        constraint="non_finite",
                        suggestion=f"{arr_name} values must not contain NaN or Inf",
                    )
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
        max_entries: int = 10_000,  # max tracked identifiers per bucket
    ):
        self.account_limit = account_limit
        self.api_key_limit = api_key_limit
        self.ip_limit = ip_limit
        self.max_entries = max_entries

        # Use OrderedDict to preserve insertion order for LRU eviction
        self.account_requests: "OrderedDict[str, Tuple[int, datetime]]" = OrderedDict()
        self.apikey_requests: "OrderedDict[str, Tuple[int, datetime]]" = OrderedDict()
        self.ip_requests: "OrderedDict[str, Tuple[int, datetime]]" = OrderedDict()

        self._lock = threading.RLock()

        # Initialize empty entries lazily in _check_limit


    @staticmethod
    def _prune_expired(
        tracking_dict: "OrderedDict[str, Tuple[int, datetime]]",
        now: datetime,
        max_prune: int = 50,
    ) -> None:
        """Remove expired entries from the LRU end (front) of the ordered dict.

        Every access calls ``move_to_end()``, so the least recently used
        entries naturally reside at the front. This makes pruning an
        O(max_prune) scan in the worst case and O(1) when nothing is
        expired.
        Because every access calls ``move_to_end()``, the oldest / least
        recently used entries naturally reside at the front, making this
        an O(max_prune) scan in the worst case and O(1) when there is
        nothing to evict.
        """
        for _ in range(max_prune):
            if not tracking_dict:
                break
            identifier, (_, window_start) = next(iter(tracking_dict.items()))
            if (now - window_start).total_seconds() >= 60:
                del tracking_dict[identifier]
            else:
                break  # remaining entries are even newer

    def _check_limit(
        self,
        identifier: str,
        tracking_dict: "OrderedDict[str, Tuple[int, datetime]]",
        limit: int,
        limit_override: Optional[int] = None,
    ) -> Tuple[bool, Optional[int]]:
        """
        Check if identifier is within rate limit using an LRU eviction policy.

        Returns:
            (is_allowed, retry_after_seconds)
        """
        now = datetime.now(timezone.utc)
        effective_limit = limit_override if limit_override is not None else limit

        # Retrieve current entry or initialize a new one
        entry = tracking_dict.get(identifier)
        if entry is None:
            # New identifier – start a window with count 1
            tracking_dict[identifier] = (1, now)
            # Enforce max size via LRU eviction (pop oldest)
            if len(tracking_dict) > self.max_entries:
                tracking_dict.popitem(last=False)
            self._prune_expired(tracking_dict, now)
            return True, None

        count, window_start = entry

        # If window has expired, reset count and timestamp
        if (now - window_start).total_seconds() >= 60:
            tracking_dict[identifier] = (1, now)
            # Move to end to mark recent use
            tracking_dict.move_to_end(identifier)
            self._prune_expired(tracking_dict, now)
            return True, None

        # Within the same minute window
        if count < effective_limit:
            tracking_dict[identifier] = (count + 1, window_start)
            tracking_dict.move_to_end(identifier)
            self._prune_expired(tracking_dict, now)
            return True, None
        else:
            # Rate limited – calculate retry after seconds
            retry_after = int(60 - (now - window_start).total_seconds() + 1)
            # Move to end to keep LRU ordering consistent
            tracking_dict.move_to_end(identifier)
            self._prune_expired(tracking_dict, now)
            return False, retry_after

    def check_account_limit(self, account_id: str, limit_override: Optional[int] = None) -> Tuple[bool, Optional[int]]:
        """Check if account is within rate limit."""
        with self._lock:
            return self._check_limit(
                account_id, self.account_requests, self.account_limit, limit_override
            )

    def check_api_key_limit(self, api_key: str, limit_override: Optional[int] = None) -> Tuple[bool, Optional[int]]:
        """Check if API key is within rate limit."""
        with self._lock:
            return self._check_limit(
                api_key, self.apikey_requests, self.api_key_limit, limit_override
            )

    def check_ip_limit(self, ip_address: str, limit_override: Optional[int] = None) -> Tuple[bool, Optional[int]]:
        """Check if IP is within rate limit."""
        with self._lock:
            return self._check_limit(ip_address, self.ip_requests, self.ip_limit, limit_override)

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



    if _rate_limiter is not None:
        _rate_limiter.reset()

class StrictRateLimit:
    """FastAPI Dependency to enforce strict endpoint-specific LRU rate limits."""
    
    def __init__(self, ip_limit: Optional[int] = None, api_key_limit: Optional[int] = None):
        self.ip_limit = ip_limit
        self.api_key_limit = api_key_limit
        
    async def __call__(
        self, 
        request: Request, 
        x_api_key: Optional[str] = Header(None, alias="X-API-Key")
    ):
        limiter = get_rate_limiter()
        
        # Enforce IP Limit
        if self.ip_limit is not None:
            client_ip = request.client.host if request.client else "unknown"
            allowed, retry = limiter.check_ip_limit(client_ip, limit_override=self.ip_limit)
            if not allowed:
                raise HTTPException(
                    status_code=429,
                    detail="Too Many Requests from this IP",
                    headers={"Retry-After": str(retry)}
                )
                
        # Enforce API Key Limit
        if self.api_key_limit is not None and x_api_key:
            key_hash = hashlib.sha256(x_api_key.encode("utf-8")).hexdigest()
            allowed, retry = limiter.check_api_key_limit(key_hash, limit_override=self.api_key_limit)
            if not allowed:
                raise HTTPException(
                    status_code=429,
                    detail="Too Many Requests for this API Key",
                    headers={"Retry-After": str(retry)}
                )

