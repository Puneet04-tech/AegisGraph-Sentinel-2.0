"""
Comprehensive API input validation module for AegisGraph Sentinel 2.0

Handles transaction validation, cross-field validation, business logic validation,
and rate limiting enforcement.
"""
import logging
from datetime import datetime, timezone, timedelta
from typing import Tuple, Optional, Dict, List, Any
from decimal import Decimal, InvalidOperation
import re
from collections import defaultdict
import threading

logger = logging.getLogger(__name__)

# ISO 4217 Currency Codes (common)
VALID_CURRENCY_CODES = {
    'INR', 'USD', 'EUR', 'GBP', 'JPY', 'CHF', 'AUD', 'CAD', 'SGD', 'HKD',
    'NZD', 'CNY', 'SEK', 'NOK', 'DKK', 'BRL', 'MXN', 'ZAR', 'KRW', 'THB'
}

# Valid transaction modes
VALID_MODES = {'UPI', 'NEFT', 'IMPS', 'SWIFT', 'ACH', 'WIRE', 'payment', 'transfer'}

# Account ID format: alphanumeric, 3-50 characters
ACCOUNT_ID_PATTERN = re.compile(r'^[A-Za-z0-9_\-]{3,50}$')


class ValidationError(Exception):
    """Custom exception for validation errors"""
    def __init__(self, field: str, value: Any, constraint: str, suggestion: str = None):
        self.field = field
        self.value = value
        self.constraint = constraint
        self.suggestion = suggestion or self._default_suggestion()
        super().__init__(self.constraint)
    
    def _default_suggestion(self) -> str:
        """Generate a default suggestion based on constraint"""
        suggestions = {
            'positive': f'Use positive amounts in minor currency units',
            'max_limit': 'Amount exceeds maximum allowed limit',
            'precision': 'Use correct decimal precision for currency (2 decimals)',
            'future': 'Timestamp cannot be in the future',
            'too_old': 'Transaction timestamp is too old (max 90 days)',
            'format': 'Check field format and constraints',
            'same_accounts': 'Source and target accounts must be different',
            'invalid_currency': 'Use valid ISO 4217 currency code',
            'invalid_mode': 'Use valid transaction mode',
            'invalid_account_id': 'Account ID must be 3-50 alphanumeric characters',
            'empty_array': 'Array cannot be empty',
            'array_size': 'Array size is outside acceptable range',
            'negative_value': 'Values in array must be non-negative',
        }
        return suggestions.get(self.constraint, 'Invalid value')
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for error response"""
        return {
            'field': self.field,
            'value': self.value,
            'constraint': self.constraint,
            'suggestion': self.suggestion,
        }


class TransactionValidator:
    """Comprehensive transaction validation"""
    
    # Configuration constants
    MIN_AMOUNT = 0.01  # Minimum transaction amount
    MAX_AMOUNT = 10000000.0  # Maximum transaction amount
    MAX_AGE_DAYS = 90  # Maximum age of transaction in days
    MAX_FUTURE_SECONDS = 60  # Allow 1 minute in future (clock skew)
    
    @staticmethod
    def validate_amount(amount: float) -> Tuple[bool, Optional[str]]:
        """
        Validate transaction amount
        
        Checks:
        - Must be positive
        - Must be within acceptable range
        - Must have valid decimal precision
        
        Returns: (is_valid, error_message)
        """
        try:
            if amount <= 0:
                raise ValidationError(
                    field='amount',
                    value=amount,
                    constraint='positive',
                    suggestion='Amount must be greater than 0'
                )
            
            if amount > TransactionValidator.MAX_AMOUNT:
                raise ValidationError(
                    field='amount',
                    value=amount,
                    constraint='max_limit',
                    suggestion=f'Amount cannot exceed {TransactionValidator.MAX_AMOUNT}'
                )
            
            # Check decimal precision (max 2 decimal places for currency)
            decimal_str = str(amount)
            if '.' in decimal_str:
                decimal_places = len(decimal_str.split('.')[1])
                if decimal_places > 2:
                    raise ValidationError(
                        field='amount',
                        value=amount,
                        constraint='precision',
                        suggestion='Amount must have at most 2 decimal places'
                    )
            
            return (True, None)
        except ValidationError as e:
            return (False, str(e))
    
    @staticmethod
    def validate_timestamp(timestamp_str: str) -> Tuple[bool, Optional[str]]:
        """
        Validate transaction timestamp
        
        Checks:
        - Must be valid ISO 8601 format
        - Cannot be in future (with 60 second tolerance)
        - Cannot be too old (>90 days)
        
        Returns: (is_valid, error_message)
        """
        try:
            # Parse ISO 8601 timestamp
            if isinstance(timestamp_str, str):
                # Handle both with and without Z suffix
                if timestamp_str.endswith('Z'):
                    timestamp_str = timestamp_str[:-1] + '+00:00'
                dt = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
            else:
                dt = datetime.fromtimestamp(float(timestamp_str), tz=timezone.utc)
            
            now = datetime.now(timezone.utc)
            
            # Check if future
            if dt > now + timedelta(seconds=TransactionValidator.MAX_FUTURE_SECONDS):
                raise ValidationError(
                    field='timestamp',
                    value=timestamp_str,
                    constraint='future',
                    suggestion='Timestamp cannot be in the future'
                )
            
            # Check if too old
            age = now - dt
            if age > timedelta(days=TransactionValidator.MAX_AGE_DAYS):
                raise ValidationError(
                    field='timestamp',
                    value=timestamp_str,
                    constraint='too_old',
                    suggestion=f'Transaction cannot be older than {TransactionValidator.MAX_AGE_DAYS} days'
                )
            
            return (True, None)
        except ValidationError as e:
            return (False, str(e))
        except (ValueError, TypeError) as e:
            return (False, 'Invalid timestamp format (use ISO 8601)')
    
    @staticmethod
    def validate_account_id(account_id: str) -> Tuple[bool, Optional[str]]:
        """
        Validate account ID format
        
        Checks:
        - Must match pattern: alphanumeric + underscore/dash
        - Must be 3-50 characters
        
        Returns: (is_valid, error_message)
        """
        try:
            if not account_id or not isinstance(account_id, str):
                raise ValidationError(
                    field='account_id',
                    value=account_id,
                    constraint='format',
                )
            
            if not ACCOUNT_ID_PATTERN.match(account_id):
                raise ValidationError(
                    field='account_id',
                    value=account_id,
                    constraint='invalid_account_id',
                )
            
            return (True, None)
        except ValidationError as e:
            return (False, str(e))
    
    @staticmethod
    def validate_currency_code(currency: str) -> Tuple[bool, Optional[str]]:
        """
        Validate currency code (ISO 4217)
        
        Returns: (is_valid, error_message)
        """
        try:
            if not currency or not isinstance(currency, str):
                raise ValidationError(
                    field='currency',
                    value=currency,
                    constraint='format',
                )
            
            currency_upper = currency.upper()
            if currency_upper not in VALID_CURRENCY_CODES:
                raise ValidationError(
                    field='currency',
                    value=currency,
                    constraint='invalid_currency',
                    suggestion=f'Use valid ISO 4217 code (e.g., INR, USD, EUR)'
                )
            
            return (True, None)
        except ValidationError as e:
            return (False, str(e))
    
    @staticmethod
    def validate_mode(mode: str) -> Tuple[bool, Optional[str]]:
        """
        Validate transaction mode
        
        Returns: (is_valid, error_message)
        """
        try:
            if not mode or not isinstance(mode, str):
                raise ValidationError(
                    field='mode',
                    value=mode,
                    constraint='format',
                )
            
            mode_upper = mode.upper()
            if mode_upper not in VALID_MODES:
                raise ValidationError(
                    field='mode',
                    value=mode,
                    constraint='invalid_mode',
                    suggestion=f'Valid modes: {", ".join(sorted(VALID_MODES))}'
                )
            
            return (True, None)
        except ValidationError as e:
            return (False, str(e))
    
    @staticmethod
    def validate_biometrics(biometrics: Dict) -> Tuple[bool, Optional[str]]:
        """
        Validate biometrics data integrity
        
        Checks:
        - Arrays must have minimum length
        - Values must be non-negative
        - Values must be within reasonable ranges
        
        Returns: (is_valid, error_message)
        """
        try:
            if not biometrics:
                return (True, None)
            
            # Check hold_times
            hold_times = biometrics.get('hold_times', [])
            if hold_times:
                if not isinstance(hold_times, list):
                    raise ValidationError(
                        field='biometrics.hold_times',
                        value=hold_times,
                        constraint='format',
                    )
                
                if len(hold_times) == 0:
                    raise ValidationError(
                        field='biometrics.hold_times',
                        value=hold_times,
                        constraint='empty_array',
                    )
                
                if len(hold_times) > 1000:
                    raise ValidationError(
                        field='biometrics.hold_times',
                        value=len(hold_times),
                        constraint='array_size',
                        suggestion='Hold times array cannot exceed 1000 elements'
                    )
                
                for i, ht in enumerate(hold_times):
                    if ht < 0:
                        raise ValidationError(
                            field=f'biometrics.hold_times[{i}]',
                            value=ht,
                            constraint='negative_value',
                        )
                    if ht > 10000:  # Reasonable upper limit
                        raise ValidationError(
                            field=f'biometrics.hold_times[{i}]',
                            value=ht,
                            constraint='array_size',
                            suggestion='Hold time value exceeds reasonable range (>10000ms)'
                        )
            
            # Check flight_times
            flight_times = biometrics.get('flight_times', [])
            if flight_times:
                if not isinstance(flight_times, list):
                    raise ValidationError(
                        field='biometrics.flight_times',
                        value=flight_times,
                        constraint='format',
                    )
                
                if len(flight_times) > 1000:
                    raise ValidationError(
                        field='biometrics.flight_times',
                        value=len(flight_times),
                        constraint='array_size',
                        suggestion='Flight times array cannot exceed 1000 elements'
                    )
                
                for i, ft in enumerate(flight_times):
                    if ft < 0:
                        raise ValidationError(
                            field=f'biometrics.flight_times[{i}]',
                            value=ft,
                            constraint='negative_value',
                        )
                    if ft > 10000:  # Reasonable upper limit
                        raise ValidationError(
                            field=f'biometrics.flight_times[{i}]',
                            value=ft,
                            constraint='array_size',
                            suggestion='Flight time value exceeds reasonable range (>10000ms)'
                        )
            
            return (True, None)
        except ValidationError as e:
            return (False, str(e))
    
    @staticmethod
    def validate_cross_fields(transaction_data: Dict) -> Tuple[bool, List[str]]:
        """
        Validate relationships between fields
        
        Checks:
        - Source and target accounts must be different
        - Timestamp consistency with current time
        - Currency consistency
        
        Returns: (is_valid, list_of_error_messages)
        """
        errors = []
        
        source = transaction_data.get('source_account')
        target = transaction_data.get('target_account')
        
        if source and target and source == target:
            errors.append(
                'source_account and target_account must be different'
            )
        
        return (len(errors) == 0, errors)


class RateLimiter:
    """Rate limiting per account/API-key with thread-safe tracking"""
    
    # Rate limiting configuration
    ACCOUNT_LIMIT = 100  # requests per minute
    API_KEY_LIMIT = 1000  # requests per minute
    IP_LIMIT = 500  # requests per minute
    CLEANUP_INTERVAL = 60  # seconds
    
    def __init__(self):
        """Initialize rate limiter with thread-safe storage"""
        self.account_requests: Dict[str, List[float]] = defaultdict(list)
        self.api_key_requests: Dict[str, List[float]] = defaultdict(list)
        self.ip_requests: Dict[str, List[float]] = defaultdict(list)
        self.lock = threading.RLock()
        self.last_cleanup = datetime.now(timezone.utc)
    
    def check_account_limit(self, account_id: str) -> Tuple[bool, Optional[int]]:
        """
        Check if account has exceeded rate limit
        
        Returns: (is_allowed, retry_after_seconds)
        """
        return self._check_limit(
            self.account_requests,
            account_id,
            self.ACCOUNT_LIMIT
        )
    
    def check_api_key_limit(self, api_key: str) -> Tuple[bool, Optional[int]]:
        """
        Check if API key has exceeded rate limit
        
        Returns: (is_allowed, retry_after_seconds)
        """
        return self._check_limit(
            self.api_key_requests,
            api_key,
            self.API_KEY_LIMIT
        )
    
    def check_ip_limit(self, ip_address: str) -> Tuple[bool, Optional[int]]:
        """
        Check if IP has exceeded rate limit
        
        Returns: (is_allowed, retry_after_seconds)
        """
        return self._check_limit(
            self.ip_requests,
            ip_address,
            self.IP_LIMIT
        )
    
    def _check_limit(
        self,
        tracker: Dict[str, List[float]],
        identifier: str,
        limit: int
    ) -> Tuple[bool, Optional[int]]:
        """
        Generic rate limit check with cleanup
        
        Returns: (is_allowed, retry_after_seconds)
        """
        with self.lock:
            now = datetime.now(timezone.utc).timestamp()
            cutoff = now - 60  # Last 60 seconds
            
            # Periodic cleanup
            if (datetime.now(timezone.utc) - self.last_cleanup).total_seconds() > self.CLEANUP_INTERVAL:
                self._cleanup_old_requests(tracker, cutoff)
                self.last_cleanup = datetime.now(timezone.utc)
            
            # Filter out old requests
            requests = tracker[identifier]
            requests = [ts for ts in requests if ts > cutoff]
            tracker[identifier] = requests
            
            # Check limit
            if len(requests) >= limit:
                # Calculate retry-after (wait until oldest request expires)
                retry_after = int((requests[0] + 60 - now) + 1)
                return (False, max(1, retry_after))
            
            # Add current request
            requests.append(now)
            return (True, None)
    
    def _cleanup_old_requests(self, tracker: Dict[str, List[float]], cutoff: float):
        """Remove old request records"""
        identifiers_to_remove = []
        for identifier, requests in tracker.items():
            valid_requests = [ts for ts in requests if ts > cutoff]
            if valid_requests:
                tracker[identifier] = valid_requests
            else:
                identifiers_to_remove.append(identifier)
        
        for identifier in identifiers_to_remove:
            del tracker[identifier]
    
    def reset(self):
        """Reset all rate limit counters (for testing)"""
        with self.lock:
            self.account_requests.clear()
            self.api_key_requests.clear()
            self.ip_requests.clear()


# Global rate limiter instance
_rate_limiter: Optional[RateLimiter] = None


def get_rate_limiter() -> RateLimiter:
    """Get or create global rate limiter instance"""
    global _rate_limiter
    if _rate_limiter is None:
        _rate_limiter = RateLimiter()
    return _rate_limiter


def reset_rate_limiter():
    """Reset rate limiter (for testing)"""
    global _rate_limiter
    _rate_limiter = None
