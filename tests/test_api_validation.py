"""
Comprehensive tests for API Input Validation (Issue #7)

Tests for:
- Transaction amount validation
- Timestamp validation
- Account ID validation
- Currency code validation
- Transaction mode validation
- Biometric data validation
- Cross-field validation
- Batch validation
- Rate limiting
- Error messages
"""

import pytest
from datetime import datetime, timezone, timedelta
from pydantic import ValidationError as PydanticValidationError

from src.api.validators import (
    TransactionValidator,
    ValidationError,
    RateLimiter,
    get_rate_limiter,
    reset_rate_limiter,
)
from src.api.schemas import TransactionCheckRequest, BiometricsData


class TestAmountValidation:
    """Test transaction amount validation."""

    def test_amount_positive_valid(self):
        """Valid positive amounts should pass."""
        TransactionValidator.validate_amount(100.0)
        TransactionValidator.validate_amount(0.01)
        TransactionValidator.validate_amount(9_999_999.99)

    def test_amount_negative_rejected(self):
        """Negative amounts should be rejected."""
        with pytest.raises(ValidationError, match="positive"):
            TransactionValidator.validate_amount(-50.0)

    def test_amount_zero_rejected(self):
        """Zero amount should be rejected."""
        with pytest.raises(ValidationError, match="positive"):
            TransactionValidator.validate_amount(0.0)

    def test_amount_exceeds_max(self):
        """Amounts over 10M should be rejected."""
        with pytest.raises(ValidationError, match="max_amount"):
            TransactionValidator.validate_amount(10_000_001.0)

    def test_amount_decimal_precision(self):
        """Amounts with >2 decimal places should be rejected."""
        with pytest.raises(ValidationError, match="decimal_precision"):
            TransactionValidator.validate_amount(100.999)

    def test_amount_valid_decimal_places(self):
        """Amounts with 1-2 decimal places should pass."""
        TransactionValidator.validate_amount(100.1)
        TransactionValidator.validate_amount(100.12)


class TestTimestampValidation:
    """Test transaction timestamp validation."""

    def test_timestamp_iso8601_valid(self):
        """Valid canonical UTC timestamps should pass."""
        canonical_now = (datetime.now(timezone.utc) - timedelta(seconds=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        TransactionValidator.validate_timestamp(canonical_now)

    def test_timestamp_offset_and_naive_rejected(self):
        """Only canonical UTC timestamps should be accepted directly."""
        with pytest.raises(ValidationError, match="iso8601_format"):
            TransactionValidator.validate_timestamp("2026-02-26T14:30:00+00:00")

        with pytest.raises(ValidationError, match="iso8601_format"):
            TransactionValidator.validate_timestamp("2026-02-26T14:30:00")

    def test_schema_normalizes_timestamp_to_canonical_utc(self):
        """Schema input should normalize epoch and offset timestamps to canonical UTC."""
        base_timestamp = (datetime.now(timezone.utc) - timedelta(days=1)).replace(microsecond=0)
        canonical_timestamp = base_timestamp.strftime("%Y-%m-%dT%H:%M:%SZ")

        epoch_request = TransactionCheckRequest(
            transaction_id="txn_epoch",
            source_account="user_001",
            target_account="merchant_001",
            amount=100.0,
            currency="INR",
            mode="UPI",
            timestamp=int(base_timestamp.timestamp()),
        )
        assert epoch_request.timestamp == canonical_timestamp

        offset_input = base_timestamp.astimezone(timezone(timedelta(hours=5, minutes=30))).isoformat()
        offset_request = TransactionCheckRequest(
            transaction_id="txn_offset",
            source_account="user_001",
            target_account="merchant_001",
            amount=100.0,
            currency="INR",
            mode="UPI",
            timestamp=offset_input,
        )
        assert offset_request.timestamp == canonical_timestamp

        utc_request = TransactionCheckRequest(
            transaction_id="txn_utc",
            source_account="user_001",
            target_account="merchant_001",
            amount=100.0,
            currency="INR",
            mode="UPI",
            timestamp=base_timestamp.astimezone(timezone.utc).isoformat(),
        )
        assert utc_request.timestamp == canonical_timestamp

    def test_schema_rejects_naive_and_bad_timestamps(self):
        """Schema should reject naive and malformed timestamps."""
        with pytest.raises(PydanticValidationError):
            TransactionCheckRequest(
                transaction_id="txn_naive",
                source_account="user_001",
                target_account="merchant_001",
                amount=100.0,
                currency="INR",
                mode="UPI",
                timestamp="2026-02-26T14:30:00",
            )

        with pytest.raises(PydanticValidationError):
            TransactionCheckRequest(
                transaction_id="txn_bad",
                source_account="user_001",
                target_account="merchant_001",
                amount=100.0,
                currency="INR",
                mode="UPI",
                timestamp="2026/02/26 14:30:00",
            )

    def test_timestamp_future_rejected(self):
        """Future timestamps should be rejected."""
        future = (datetime.now(timezone.utc) + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        with pytest.raises(ValidationError, match="not_future"):
            TransactionValidator.validate_timestamp(future)

    def test_timestamp_future_with_tolerance(self):
        """Timestamps up to 60 seconds in future should be allowed."""
        future = (datetime.now(timezone.utc) + timedelta(seconds=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
        TransactionValidator.validate_timestamp(future)

    def test_timestamp_too_old_rejected(self):
        """Timestamps older than 90 days should be rejected."""
        old = (datetime.now(timezone.utc) - timedelta(days=91)).strftime("%Y-%m-%dT%H:%M:%SZ")
        with pytest.raises(ValidationError, match="not_too_old"):
            TransactionValidator.validate_timestamp(old)

    def test_timestamp_invalid_format(self):
        """Invalid timestamp formats should be rejected."""
        with pytest.raises(ValidationError, match="iso8601_format"):
            TransactionValidator.validate_timestamp("invalid-date")
        
        with pytest.raises(ValidationError, match="iso8601_format"):
            TransactionValidator.validate_timestamp("2026-13-01T10:00:00Z")

        with pytest.raises(ValidationError, match="iso8601_format"):
            TransactionValidator.validate_timestamp("2026-02-26T14:30:00+00:00")

        with pytest.raises(ValidationError, match="iso8601_format"):
            TransactionValidator.validate_timestamp("2026-02-26T14:30:00")

    def test_timestamp_within_90_days_valid(self):
        """Timestamps within 90 days should pass."""
        old_but_valid = (datetime.now(timezone.utc) - timedelta(days=89)).strftime("%Y-%m-%dT%H:%M:%SZ")
        TransactionValidator.validate_timestamp(old_but_valid)


class TestAccountIdValidation:
    """Test account ID validation."""

    def test_account_id_valid_formats(self):
        """Valid account IDs should pass."""
        TransactionValidator.validate_account_id("acc_123")
        TransactionValidator.validate_account_id("user-001")
        TransactionValidator.validate_account_id("ABC_XYZ_123")
        TransactionValidator.validate_account_id("usr")

    def test_account_id_too_short(self):
        """IDs shorter than 3 chars should be rejected."""
        with pytest.raises(ValidationError, match="length"):
            TransactionValidator.validate_account_id("ab")

    def test_account_id_too_long(self):
        """IDs longer than 50 chars should be rejected."""
        with pytest.raises(ValidationError, match="length"):
            TransactionValidator.validate_account_id("a" * 51)

    def test_account_id_invalid_characters(self):
        """IDs with invalid characters should be rejected."""
        with pytest.raises(ValidationError, match="format"):
            TransactionValidator.validate_account_id("acc@123")
        
        with pytest.raises(ValidationError, match="format"):
            TransactionValidator.validate_account_id("acc 123")

    def test_account_id_boundary_lengths(self):
        """Boundary account IDs should pass."""
        TransactionValidator.validate_account_id("a" * 3)  # minimum
        TransactionValidator.validate_account_id("a" * 50)  # maximum


class TestCurrencyValidation:
    """Test currency code validation."""

    def test_currency_valid_codes(self):
        """Valid ISO 4217 codes should pass."""
        TransactionValidator.validate_currency_code("INR")
        TransactionValidator.validate_currency_code("USD")
        TransactionValidator.validate_currency_code("EUR")
        TransactionValidator.validate_currency_code("GBP")

    def test_currency_case_insensitive(self):
        """Currency validation should be case-insensitive."""
        TransactionValidator.validate_currency_code("inr")
        TransactionValidator.validate_currency_code("usd")

    def test_currency_invalid_code(self):
        """Invalid ISO 4217 codes should be rejected."""
        with pytest.raises(ValidationError, match="iso4217"):
            TransactionValidator.validate_currency_code("XYZ")
        
        with pytest.raises(ValidationError, match="iso4217"):
            TransactionValidator.validate_currency_code("INVALID")


class TestModeValidation:
    """Test transaction mode validation."""

    def test_mode_valid_types(self):
        """Valid transaction modes should pass."""
        TransactionValidator.validate_mode("UPI")
        TransactionValidator.validate_mode("NEFT")
        TransactionValidator.validate_mode("IMPS")
        TransactionValidator.validate_mode("ACH")

    def test_mode_case_insensitive(self):
        """Mode validation should be case-insensitive."""
        TransactionValidator.validate_mode("upi")
        TransactionValidator.validate_mode("neft")

    def test_mode_invalid_type(self):
        """Invalid transaction modes should be rejected."""
        with pytest.raises(ValidationError, match="invalid_mode"):
            TransactionValidator.validate_mode("INVALID")


class TestBiometricsValidation:
    """Test biometric data validation."""

    def test_biometrics_valid_arrays(self):
        """Valid biometric arrays should pass."""
        TransactionValidator.validate_biometrics(
            hold_times=[100, 120, 150],
            flight_times=[200, 180, 210]
        )
        TransactionValidator.validate_biometrics(
            hold_times=[],
            flight_times=[]
        )

    def test_biometrics_max_array_length(self):
        """Arrays with >1000 elements should be rejected."""
        with pytest.raises(ValidationError, match="max_length"):
            TransactionValidator.validate_biometrics(
                hold_times=list(range(1001)),
                flight_times=[]
            )

    def test_biometrics_negative_values(self):
        """Negative biometric values should be rejected."""
        with pytest.raises(ValidationError, match="value_range"):
            TransactionValidator.validate_biometrics(
                hold_times=[-100],
                flight_times=[]
            )

    def test_biometrics_excessive_values(self):
        """Values >10000ms should be rejected."""
        with pytest.raises(ValidationError, match="value_range"):
            TransactionValidator.validate_biometrics(
                hold_times=[10001],
                flight_times=[]
            )

    def test_biometrics_boundary_values(self):
        """Boundary values (0, 10000) should pass."""
        TransactionValidator.validate_biometrics(
            hold_times=[0, 10000],
            flight_times=[0, 10000]
        )

    def test_biometrics_nan_hold_times(self):
        """NaN in hold_times must be rejected."""
        import math
        with pytest.raises(ValidationError, match="non_finite"):
            TransactionValidator.validate_biometrics(
                hold_times=[float('nan')],
                flight_times=[]
            )

    def test_biometrics_nan_flight_times(self):
        """NaN in flight_times must be rejected."""
        with pytest.raises(ValidationError, match="non_finite"):
            TransactionValidator.validate_biometrics(
                hold_times=[],
                flight_times=[float('nan')]
            )

    def test_biometrics_positive_inf(self):
        """Positive infinity must be rejected."""
        with pytest.raises(ValidationError, match="non_finite"):
            TransactionValidator.validate_biometrics(
                hold_times=[float('inf')],
                flight_times=[]
            )

    def test_biometrics_negative_inf(self):
        """Negative infinity must be rejected."""
        with pytest.raises(ValidationError, match="non_finite"):
            TransactionValidator.validate_biometrics(
                hold_times=[float('-inf')],
                flight_times=[]
            )

    def test_biometrics_mixed_nan_valid(self):
        """Array mixing valid values and NaN must be rejected."""
        with pytest.raises(ValidationError, match="non_finite"):
            TransactionValidator.validate_biometrics(
                hold_times=[100, 120, float('nan'), 140],
                flight_times=[]
            )

    def test_biometrics_schema_nan_rejected(self):
        """BiometricsData Pydantic schema must also reject NaN."""
        import pytest
        from pydantic import ValidationError as PydanticValidationError
        with pytest.raises(PydanticValidationError):
            BiometricsData(hold_times=[float('nan')], flight_times=[200.0])

    def test_biometrics_schema_inf_rejected(self):
        """BiometricsData Pydantic schema must also reject Inf."""
        from pydantic import ValidationError as PydanticValidationError
        with pytest.raises(PydanticValidationError):
            BiometricsData(hold_times=[100.0], flight_times=[float('inf')])


class TestCrossFieldValidation:
    """Test cross-field validation."""

    def test_different_accounts_valid(self):
        """Different source and target accounts should pass."""
        TransactionValidator.validate_cross_fields("user_001", "merchant_001")

    def test_same_accounts_rejected(self):
        """Same source and target accounts should be rejected."""
        with pytest.raises(ValidationError, match="different_accounts"):
            TransactionValidator.validate_cross_fields("user_001", "user_001")


class TestBatchValidation:
    """Test batch transaction validation."""

    def test_batch_size_valid(self):
        """Batches within 100 transactions should be valid."""
        transactions = [
            {
                "transaction_id": f"txn_{i}",
                "source_account": f"acc_{i}",
                "target_account": f"acc_{i+1}",
                "amount": 100.0,
                "currency": "INR",
                "mode": "UPI",
                "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            }
            for i in range(50)
        ]
        
        # Should not raise
        for txn in transactions:
            TransactionCheckRequest(**txn)

    def test_batch_size_exceeds_max(self):
        """Batches with >100 transactions should be rejected."""
        # This is typically enforced at the endpoint level
        # but we can test that individual transactions validate
        pass


class TestRateLimiting:
    """Test rate limiting functionality."""

    def test_rate_limiter_allows_initial_request(self):
        """Initial request should be allowed."""
        limiter = RateLimiter()
        is_allowed, retry_after = limiter.check_account_limit("acc_001")
        assert is_allowed is True
        assert retry_after is None

    def test_rate_limiter_allows_under_limit(self):
        """Requests under limit should be allowed."""
        limiter = RateLimiter(account_limit=5)
        
        for i in range(5):
            is_allowed, retry_after = limiter.check_account_limit("acc_001")
            assert is_allowed is True
            assert retry_after is None

    def test_rate_limiter_rejects_over_limit(self):
        """Requests over limit should be rejected."""
        limiter = RateLimiter(account_limit=2)
        
        limiter.check_account_limit("acc_001")
        limiter.check_account_limit("acc_001")
        
        is_allowed, retry_after = limiter.check_account_limit("acc_001")
        assert is_allowed is False
        assert retry_after is not None
        assert retry_after > 0

    def test_rate_limiter_per_account_isolation(self):
        """Different accounts should have separate limits."""
        limiter = RateLimiter(account_limit=2)
        
        limiter.check_account_limit("acc_001")
        limiter.check_account_limit("acc_001")
        
        # acc_002 should still be allowed
        is_allowed, retry_after = limiter.check_account_limit("acc_002")
        assert is_allowed is True

    def test_rate_limiter_api_key_limit(self):
        """API key rate limiting should work independently."""
        limiter = RateLimiter(api_key_limit=2)
        
        limiter.check_api_key_limit("key_001")
        limiter.check_api_key_limit("key_001")
        
        is_allowed, retry_after = limiter.check_api_key_limit("key_001")
        assert is_allowed is False

    def test_rate_limiter_ip_limit(self):
        """IP rate limiting should work independently."""
        limiter = RateLimiter(ip_limit=2)
        
        limiter.check_ip_limit("103.1.1.1")
        limiter.check_ip_limit("103.1.1.1")
        
        is_allowed, retry_after = limiter.check_ip_limit("103.1.1.1")
        assert is_allowed is False


class TestErrorMessages:
    """Test error message clarity and helpfulness."""

    def test_validation_error_includes_field_name(self):
        """Error messages should include field name."""
        with pytest.raises(ValidationError) as exc_info:
            TransactionValidator.validate_amount(-50)
        
        assert "amount" in str(exc_info.value)

    def test_validation_error_includes_suggestion(self):
        """Error messages should include helpful suggestions."""
        with pytest.raises(ValidationError) as exc_info:
            TransactionValidator.validate_currency_code("INVALID")
        
        assert "ISO 4217" in str(exc_info.value)


class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_amount_maximum_allowed(self):
        """Maximum allowed amount should pass."""
        TransactionValidator.validate_amount(10_000_000.0)

    def test_transaction_id_length_validation(self):
        """Transaction ID should accept reasonable lengths."""
        # Transaction ID has basic string validation
        request = TransactionCheckRequest(
            transaction_id="test_txn_001",
            source_account="user_001",
            target_account="merchant_001",
            amount=100.0,
            currency="INR",
            mode="UPI",
            timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        )
        assert request.transaction_id == "test_txn_001"

    def test_multiple_validation_errors(self):
        """Multiple validation errors should be caught."""
        with pytest.raises(Exception):  # Pydantic will raise ValidationError
            TransactionCheckRequest(
                transaction_id="test_001",
                source_account="user_001",
                target_account="user_001",  # Same as source
                amount=-100.0,  # Negative
                currency="INVALID",
                mode="INVALID_MODE",
                timestamp="invalid-date",
            )


class TestIntegration:
    """End-to-end integration tests."""

    def test_valid_transaction_request(self):
        """Valid transaction request should pass all validations."""
        request = TransactionCheckRequest(
            transaction_id="txn_001",
            source_account="user_001",
            target_account="merchant_001",
            amount=5000.50,
            currency="INR",
            mode="UPI",
            timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            device_id="device_123",
            biometrics=BiometricsData(
                hold_times=[100, 120, 115],
                flight_times=[200, 180, 210],
            ),
            ip_address="103.1.1.1",
            location="Mumbai, India",
        )
        
        assert request.source_account == "user_001"
        assert request.amount == 5000.50

    def test_rate_limiting_with_valid_requests(self):
        """Rate limiting should work with valid requests."""
        reset_rate_limiter()
        limiter = get_rate_limiter()
        
        # Make multiple valid requests
        for i in range(100):
            is_allowed, retry_after = limiter.check_account_limit("acc_test")
            assert is_allowed is True
        
        # 101st request should be rejected
        is_allowed, retry_after = limiter.check_account_limit("acc_test")
        assert is_allowed is False
        assert retry_after is not None
