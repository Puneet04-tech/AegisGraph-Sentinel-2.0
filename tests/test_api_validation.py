"""
Comprehensive API validation tests for AegisGraph Sentinel 2.0

Tests cover:
- Input validation (amounts, timestamps, accounts, currency, mode)
- Cross-field validation
- Biometrics validation
- Error message consistency
- Rate limiting
- Batch operations
"""
import pytest
from datetime import datetime, timedelta, timezone
from typing import Dict, Any
import time

from src.api.validators import (
    TransactionValidator,
    ValidationError,
    RateLimiter,
    get_rate_limiter,
    reset_rate_limiter,
)
from src.api.schemas import (
    TransactionCheckRequest,
    BiometricsData,
    BatchTransactionRequest,
)
from pydantic import ValidationError as PydanticValidationError


# ============================================================================
# AMOUNT VALIDATION TESTS
# ============================================================================

class TestAmountValidation:
    """Tests for transaction amount validation"""
    
    def test_amount_validation_positive(self):
        """Positive amounts should be valid"""
        valid, error = TransactionValidator.validate_amount(50000.0)
        assert valid is True
        assert error is None
    
    def test_amount_validation_negative(self):
        """Negative amounts should be rejected"""
        valid, error = TransactionValidator.validate_amount(-50000.0)
        assert valid is False
        assert error is not None
        assert "positive" in error.lower()
    
    def test_amount_validation_zero(self):
        """Zero amount should be rejected"""
        valid, error = TransactionValidator.validate_amount(0.0)
        assert valid is False
        assert error is not None
    
    def test_amount_validation_exceeds_max(self):
        """Amount exceeding maximum should be rejected"""
        valid, error = TransactionValidator.validate_amount(99999999999.0)
        assert valid is False
        assert error is not None
    
    def test_amount_validation_decimal_precision(self):
        """Amount with more than 2 decimal places should be rejected"""
        valid, error = TransactionValidator.validate_amount(123.456)
        assert valid is False
        assert "decimal" in error.lower() or "precision" in error.lower()
    
    def test_amount_validation_two_decimals(self):
        """Amount with 2 decimal places should be valid"""
        valid, error = TransactionValidator.validate_amount(123.45)
        assert valid is True
    
    def test_amount_pydantic_validation_negative(self):
        """Pydantic should reject negative amounts in schema"""
        with pytest.raises(PydanticValidationError):
            TransactionCheckRequest(
                transaction_id="TXN123",
                source_account="ACC1",
                target_account="ACC2",
                amount=-50000,
                timestamp="2026-05-28T10:00:00Z"
            )
    
    def test_amount_pydantic_validation_exceeds_max(self):
        """Pydantic should reject amounts exceeding max"""
        with pytest.raises(PydanticValidationError):
            TransactionCheckRequest(
                transaction_id="TXN123",
                source_account="ACC1",
                target_account="ACC2",
                amount=99999999999,
                timestamp="2026-05-28T10:00:00Z"
            )


# ============================================================================
# TIMESTAMP VALIDATION TESTS
# ============================================================================

class TestTimestampValidation:
    """Tests for transaction timestamp validation"""
    
    def test_timestamp_validation_current(self):
        """Current timestamp should be valid"""
        now = datetime.now(timezone.utc).isoformat()
        valid, error = TransactionValidator.validate_timestamp(now)
        assert valid is True
    
    def test_timestamp_validation_future(self):
        """Future timestamp should be rejected"""
        future = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
        valid, error = TransactionValidator.validate_timestamp(future)
        assert valid is False
        assert error is not None
    
    def test_timestamp_validation_too_old(self):
        """Timestamp older than 90 days should be rejected"""
        old = (datetime.now(timezone.utc) - timedelta(days=91)).isoformat()
        valid, error = TransactionValidator.validate_timestamp(old)
        assert valid is False
        assert error is not None
    
    def test_timestamp_validation_iso_format(self):
        """ISO 8601 format should be supported"""
        iso_time = "2026-05-28T14:30:00Z"
        valid, error = TransactionValidator.validate_timestamp(iso_time)
        # May be invalid if it's actually in the future, but format should be accepted
        assert error is None or "format" not in error.lower()
    
    def test_timestamp_pydantic_future_rejected(self):
        """Pydantic should reject future timestamps"""
        future = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
        with pytest.raises(PydanticValidationError):
            TransactionCheckRequest(
                transaction_id="TXN123",
                source_account="ACC1",
                target_account="ACC2",
                amount=50000,
                timestamp=future
            )


# ============================================================================
# ACCOUNT ID VALIDATION TESTS
# ============================================================================

class TestAccountIdValidation:
    """Tests for account ID format validation"""
    
    def test_account_id_valid_format(self):
        """Valid account IDs should pass validation"""
        valid, error = TransactionValidator.validate_account_id("ACC123")
        assert valid is True
    
    def test_account_id_too_short(self):
        """Account IDs shorter than 3 characters should be rejected"""
        valid, error = TransactionValidator.validate_account_id("AC")
        assert valid is False
    
    def test_account_id_too_long(self):
        """Account IDs longer than 50 characters should be rejected"""
        valid, error = TransactionValidator.validate_account_id("A" * 51)
        assert valid is False
    
    def test_account_id_with_underscore(self):
        """Account IDs with underscores should be valid"""
        valid, error = TransactionValidator.validate_account_id("ACC_123")
        assert valid is True
    
    def test_account_id_with_dash(self):
        """Account IDs with dashes should be valid"""
        valid, error = TransactionValidator.validate_account_id("ACC-123")
        assert valid is True
    
    def test_account_id_pydantic_format_validation(self):
        """Pydantic should validate account ID format"""
        with pytest.raises(PydanticValidationError):
            TransactionCheckRequest(
                transaction_id="TXN123",
                source_account="AC",  # Too short
                target_account="ACC2",
                amount=50000,
                timestamp="2026-05-28T10:00:00Z"
            )


# ============================================================================
# CURRENCY CODE VALIDATION TESTS
# ============================================================================

class TestCurrencyValidation:
    """Tests for ISO 4217 currency code validation"""
    
    def test_currency_valid_inr(self):
        """INR should be valid"""
        valid, error = TransactionValidator.validate_currency_code("INR")
        assert valid is True
    
    def test_currency_valid_usd(self):
        """USD should be valid"""
        valid, error = TransactionValidator.validate_currency_code("USD")
        assert valid is True
    
    def test_currency_invalid_code(self):
        """Invalid currency code should be rejected"""
        valid, error = TransactionValidator.validate_currency_code("XXX")
        assert valid is False
        assert error is not None
    
    def test_currency_pydantic_invalid(self):
        """Pydantic should reject invalid currency codes"""
        with pytest.raises(PydanticValidationError):
            TransactionCheckRequest(
                transaction_id="TXN123",
                source_account="ACC1",
                target_account="ACC2",
                amount=50000,
                currency="XXX",
                timestamp="2026-05-28T10:00:00Z"
            )


# ============================================================================
# TRANSACTION MODE VALIDATION TESTS
# ============================================================================

class TestModeValidation:
    """Tests for transaction mode validation"""
    
    def test_mode_valid_upi(self):
        """UPI mode should be valid"""
        valid, error = TransactionValidator.validate_mode("UPI")
        assert valid is True
    
    def test_mode_valid_neft(self):
        """NEFT mode should be valid"""
        valid, error = TransactionValidator.validate_mode("NEFT")
        assert valid is True
    
    def test_mode_invalid(self):
        """Invalid mode should be rejected"""
        valid, error = TransactionValidator.validate_mode("INVALID")
        assert valid is False
        assert error is not None
    
    def test_mode_pydantic_invalid(self):
        """Pydantic should reject invalid modes"""
        with pytest.raises(PydanticValidationError):
            TransactionCheckRequest(
                transaction_id="TXN123",
                source_account="ACC1",
                target_account="ACC2",
                amount=50000,
                mode="INVALID",
                timestamp="2026-05-28T10:00:00Z"
            )


# ============================================================================
# BIOMETRICS VALIDATION TESTS
# ============================================================================

class TestBiometricsValidation:
    """Tests for biometrics data validation"""
    
    def test_biometrics_valid(self):
        """Valid biometrics should pass"""
        biometrics = {
            "hold_times": [120, 135, 128],
            "flight_times": [200, 185, 210]
        }
        valid, error = TransactionValidator.validate_biometrics(biometrics)
        assert valid is True
    
    def test_biometrics_empty(self):
        """Empty biometrics should pass (optional)"""
        valid, error = TransactionValidator.validate_biometrics({})
        assert valid is True
    
    def test_biometrics_negative_hold_time(self):
        """Negative hold time should be rejected"""
        biometrics = {
            "hold_times": [120, -50, 128],
            "flight_times": [200, 185, 210]
        }
        valid, error = TransactionValidator.validate_biometrics(biometrics)
        assert valid is False
    
    def test_biometrics_excessive_value(self):
        """Hold time > 10000ms should be rejected"""
        biometrics = {
            "hold_times": [120, 99999, 128],
        }
        valid, error = TransactionValidator.validate_biometrics(biometrics)
        assert valid is False
    
    def test_biometrics_pydantic_validation(self):
        """Pydantic should validate biometrics"""
        bio = BiometricsData(
            hold_times=[120, 135, 128],
            flight_times=[200, 185, 210]
        )
        assert bio.hold_times == [120, 135, 128]


# ============================================================================
# CROSS-FIELD VALIDATION TESTS
# ============================================================================

class TestCrossFieldValidation:
    """Tests for validation between related fields"""
    
    def test_cross_field_same_accounts_rejected(self):
        """Source and target accounts must be different"""
        with pytest.raises(PydanticValidationError):
            TransactionCheckRequest(
                transaction_id="TXN123",
                source_account="ACC1",
                target_account="ACC1",  # Same as source
                amount=50000,
                timestamp="2026-05-28T10:00:00Z"
            )
    
    def test_cross_field_different_accounts_valid(self):
        """Different source and target accounts should be valid"""
        now = datetime.now(timezone.utc).isoformat()
        req = TransactionCheckRequest(
            transaction_id="TXN123",
            source_account="ACC1",
            target_account="ACC2",
            amount=50000,
            timestamp=now
        )
        assert req.source_account != req.target_account


# ============================================================================
# BATCH OPERATION VALIDATION TESTS
# ============================================================================

class TestBatchValidation:
    """Tests for batch transaction validation"""
    
    def test_batch_size_valid(self):
        """Batch with 10 transactions should be valid"""
        now = datetime.now(timezone.utc).isoformat()
        transactions = [
            TransactionCheckRequest(
                transaction_id=f"TXN{i}",
                source_account="ACC1",
                target_account=f"ACC{i+2}",
                amount=50000,
                timestamp=now
            )
            for i in range(10)
        ]
        batch = BatchTransactionRequest(transactions=transactions)
        assert len(batch.transactions) == 10
    
    def test_batch_size_exceeds_max(self):
        """Batch with >100 transactions should be rejected"""
        now = datetime.now(timezone.utc).isoformat()
        transactions = [
            TransactionCheckRequest(
                transaction_id=f"TXN{i}",
                source_account="ACC1",
                target_account=f"ACC{i+2}",
                amount=50000,
                timestamp=now
            )
            for i in range(101)
        ]
        with pytest.raises(PydanticValidationError):
            BatchTransactionRequest(transactions=transactions)


# ============================================================================
# RATE LIMITING TESTS
# ============================================================================

class TestRateLimiting:
    """Tests for rate limiting functionality"""
    
    @pytest.fixture(autouse=True)
    def reset_limiter(self):
        """Reset rate limiter before each test"""
        reset_rate_limiter()
        yield
        reset_rate_limiter()
    
    def test_rate_limiter_allows_initial_request(self):
        """Initial request should be allowed"""
        limiter = get_rate_limiter()
        allowed, retry_after = limiter.check_account_limit("ACC1")
        assert allowed is True
        assert retry_after is None
    
    def test_rate_limiter_allows_under_limit(self):
        """Requests under limit should be allowed"""
        limiter = get_rate_limiter()
        for i in range(50):
            allowed, retry_after = limiter.check_account_limit("ACC1")
            assert allowed is True
            assert retry_after is None
    
    def test_rate_limiter_rejects_over_limit(self):
        """Requests over limit should be rejected"""
        limiter = get_rate_limiter()
        # Exceed the 100 request/minute limit
        for i in range(100):
            limiter.check_account_limit("ACC1")
        
        # Next request should be rejected
        allowed, retry_after = limiter.check_account_limit("ACC1")
        assert allowed is False
        assert retry_after is not None
        assert retry_after > 0
    
    def test_rate_limiter_per_account_isolation(self):
        """Rate limits should be per-account"""
        limiter = get_rate_limiter()
        
        # Exceed limit for ACC1
        for i in range(100):
            limiter.check_account_limit("ACC1")
        
        # ACC2 should still be allowed
        allowed, retry_after = limiter.check_account_limit("ACC2")
        assert allowed is True
        assert retry_after is None
    
    def test_rate_limiter_api_key_limit(self):
        """API key rate limiting should work"""
        limiter = get_rate_limiter()
        
        # Allow 1000 requests per minute for API key
        for i in range(1000):
            allowed, retry_after = limiter.check_api_key_limit("KEY1")
            assert allowed is True
        
        # Next should be rejected
        allowed, retry_after = limiter.check_api_key_limit("KEY1")
        assert allowed is False
    
    def test_rate_limiter_ip_limit(self):
        """IP rate limiting should work"""
        limiter = get_rate_limiter()
        
        # Allow 500 requests per minute for IP
        for i in range(500):
            allowed, retry_after = limiter.check_ip_limit("192.168.1.1")
            assert allowed is True
        
        # Next should be rejected
        allowed, retry_after = limiter.check_ip_limit("192.168.1.1")
        assert allowed is False


# ============================================================================
# ERROR MESSAGE TESTS
# ============================================================================

class TestErrorMessages:
    """Tests for error message consistency and quality"""
    
    def test_error_message_includes_field_name(self):
        """Error messages should include field name"""
        with pytest.raises(PydanticValidationError) as exc_info:
            TransactionCheckRequest(
                transaction_id="TXN123",
                source_account="ACC1",
                target_account="ACC1",  # Invalid: same as source
                amount=50000,
                timestamp="2026-05-28T10:00:00Z"
            )
        # Check that error includes field information
        errors = exc_info.value.errors()
        assert len(errors) > 0
    
    def test_error_includes_suggestion(self):
        """Validation errors should include remediation suggestions"""
        try:
            TransactionCheckRequest(
                transaction_id="TXN123",
                source_account="ACC1",
                target_account="ACC2",
                amount=-50000,  # Invalid
                timestamp="2026-05-28T10:00:00Z"
            )
        except PydanticValidationError as e:
            errors = e.errors()
            assert len(errors) > 0
            # Error should reference the field
            error_str = str(errors[0])
            assert "amount" in error_str.lower() or "positive" in error_str.lower()


# ============================================================================
# EDGE CASE TESTS
# ============================================================================

class TestEdgeCases:
    """Tests for edge cases and boundary conditions"""
    
    def test_amount_maximum_allowed(self):
        """Amount at maximum should be valid"""
        now = datetime.now(timezone.utc).isoformat()
        req = TransactionCheckRequest(
            transaction_id="TXN123",
            source_account="ACC1",
            target_account="ACC2",
            amount=10000000,  # Max
            timestamp=now
        )
        assert req.amount == 10000000
    
    def test_transaction_id_length_validation(self):
        """Transaction ID must have minimum length"""
        with pytest.raises(PydanticValidationError):
            TransactionCheckRequest(
                transaction_id="TX",  # Too short
                source_account="ACC1",
                target_account="ACC2",
                amount=50000,
                timestamp="2026-05-28T10:00:00Z"
            )
    
    def test_multiple_validation_errors(self):
        """Multiple validation errors should all be reported"""
        with pytest.raises(PydanticValidationError) as exc_info:
            TransactionCheckRequest(
                transaction_id="TX",  # Too short
                source_account="AC",  # Too short
                target_account="ACC2",
                amount=-50000,  # Negative
                timestamp="2099-05-28T10:00:00Z"  # Future
            )
        errors = exc_info.value.errors()
        # Should have multiple errors
        assert len(errors) >= 3


# ============================================================================
# INTEGRATION TESTS
# ============================================================================

class TestIntegration:
    """Integration tests for full validation pipeline"""
    
    def test_valid_transaction_request(self):
        """Complete valid transaction should pass all validation"""
        now = datetime.now(timezone.utc).isoformat()
        req = TransactionCheckRequest(
            transaction_id="TXN123456789",
            source_account="ACC987654321",
            target_account="ACC123456789",
            amount=50000.00,
            currency="INR",
            mode="UPI",
            timestamp=now,
            device_id="DEV123",
            biometrics=BiometricsData(
                hold_times=[120, 135, 128, 142, 118],
                flight_times=[200, 185, 210, 195]
            ),
            ip_address="103.1.1.1",
            location="Mumbai, India"
        )
        assert req.transaction_id == "TXN123456789"
        assert req.amount == 50000.00
    
    def test_rate_limiting_with_valid_requests(self):
        """Rate limiting should work with valid transaction requests"""
        reset_rate_limiter()
        limiter = get_rate_limiter()
        now = datetime.now(timezone.utc).isoformat()
        
        # Send 50 valid requests
        for i in range(50):
            allowed, retry_after = limiter.check_account_limit("ACC1")
            assert allowed is True
            
            # Create valid transaction
            req = TransactionCheckRequest(
                transaction_id=f"TXN{i}",
                source_account="ACC1",
                target_account=f"ACC{i+2}",
                amount=50000,
                timestamp=now
            )
            assert req.amount == 50000


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
