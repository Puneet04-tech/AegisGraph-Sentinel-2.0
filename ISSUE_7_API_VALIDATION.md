# [Issue #7] Enhance API Input Validation and Error Handling

## 📋 Issue Description

The API currently has basic input validation through Pydantic schemas, but lacks comprehensive validation for edge cases, malformed data, and complex business logic rules. Additionally, error responses could be more informative and consistent across all endpoints.

**Severity**: Medium  
**Effort**: 4-6 hours (Intermediate)  
**Impact**: Improved reliability, better error messages, production-ready validation

---

## 🎯 Current State

### What Works ✅
- Basic Pydantic schema validation
- JSON validation errors (422 status)
- Request ID correlation
- Exception handler middleware

### What's Missing ❌
- Cross-field validation (e.g., timestamp logic)
- Business logic validation (account constraints)
- Biometrics data integrity checks
- Numeric range validation completeness
- Duplicate transaction detection
- Amount sanity checks
- Comprehensive error messages with remediation hints
- Rate limiting per account/API key
- Request timeout handling
- Batch operation size limits enforcement

---

## 🔍 Problem Analysis

### Example Issues

**1. Missing Amount Validation**
```python
# Current: Only checks if amount exists
# Missing: Amount <= 0, excessive amounts, decimal precision

payload = {"amount": -50000}  # Should be rejected but may not be
payload = {"amount": 99999999999999}  # Should have max limit
payload = {"amount": 123.456789}  # Should enforce currency precision
```

**2. Missing Timestamp Validation**
```python
# Current: Only checks if timestamp exists
# Missing: Future dates, very old dates, timezone handling

payload = {"timestamp": "2099-01-01T00:00:00Z"}  # Future date
payload = {"timestamp": "1990-01-01T00:00:00Z"}  # Too old
```

**3. Missing Biometrics Validation**
```python
# Current: Pass-through if present
# Missing: Array length, value ranges, sanity checks

payload = {
    "biometrics": {
        "hold_times": [999999, -100, 50],  # Should validate ranges
        "flight_times": []  # Should enforce min array length
    }
}
```

**4. Insufficient Error Messages**
```json
// Current response
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid payload"
  }
}

// Desired response (more helpful)
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid transaction amount",
    "details": {
      "field": "amount",
      "value": -50000,
      "constraint": "must be positive",
      "suggestion": "Use positive amounts in minor currency units"
    }
  }
}
```

---

## 📝 Acceptance Criteria

### 1. Enhanced Input Validation
- [ ] Amount validation: positive, max limits, decimal precision
- [ ] Timestamp validation: not in future, not too old, proper timezone handling
- [ ] Account ID validation: format, length constraints
- [ ] Biometrics array validation: length, value ranges, type checking
- [ ] Currency code validation: ISO 4217 compliance
- [ ] Mode validation: enum constraints (UPI, NEFT, SWIFT, etc.)

### 2. Cross-Field Validation
- [ ] Source and target accounts must be different
- [ ] Timestamp cannot be in future
- [ ] Consistent currency across transaction
- [ ] Biometrics timestamp consistency with transaction timestamp

### 3. Enhanced Error Responses
- [ ] Include specific field information
- [ ] Provide constraint details
- [ ] Add remediation suggestions
- [ ] Return all validation errors at once (not just first one)
- [ ] Consistent error format across all endpoints

### 4. Business Logic Validation
- [ ] Duplicate transaction detection (same source/target/amount within 1 minute)
- [ ] Account velocity limits (max 10 transactions per minute per account)
- [ ] Daily transaction limits per account
- [ ] Sanity checks for suspicious patterns

### 5. Rate Limiting Enhancement
- [ ] Per-account rate limiting (100 requests/minute)
- [ ] Per-API-key rate limiting (1000 requests/minute)
- [ ] Per-IP rate limiting (500 requests/minute)
- [ ] Return 429 status with Retry-After header

### 6. Batch Operation Validation
- [ ] Enforce max batch size (currently hardcoded, should be configurable)
- [ ] Validate each transaction in batch individually
- [ ] Return partial success with detailed error per failed transaction
- [ ] Maximum 100 transactions per batch

### 7. Comprehensive Test Coverage
- [ ] 15+ new validation tests
- [ ] Edge case test coverage (negative amounts, future dates, etc.)
- [ ] Error message consistency tests
- [ ] Cross-field validation tests
- [ ] Rate limiting tests

---

## 🛠️ Implementation Plan

### Phase 1: Create Validation Layer
**File**: `src/api/validators.py` (NEW)

```python
class TransactionValidator:
    """Comprehensive transaction validation"""
    
    @staticmethod
    def validate_amount(amount: float) -> Tuple[bool, Optional[str]]:
        """Validate transaction amount"""
        pass
    
    @staticmethod
    def validate_timestamp(timestamp: str) -> Tuple[bool, Optional[str]]:
        """Validate transaction timestamp"""
        pass
    
    @staticmethod
    def validate_biometrics(biometrics: Dict) -> Tuple[bool, Optional[str]]:
        """Validate biometrics data"""
        pass
    
    @staticmethod
    def validate_cross_fields(request: TransactionCheckRequest) -> Tuple[bool, Optional[str]]:
        """Validate relationships between fields"""
        pass

class RateLimiter:
    """Rate limiting per account/API-key"""
    
    def check_limit(self, identifier: str, limit_type: str) -> Tuple[bool, Optional[int]]:
        """Check if request exceeds rate limit"""
        pass
```

### Phase 2: Enhance Schemas
**File**: `src/api/schemas.py`
- Add validators to Pydantic fields
- Add Field constraints (gt, lt, max_length, etc.)
- Add custom validators for complex logic

Example:
```python
from pydantic import Field, field_validator

class TransactionCheckRequest(BaseModel):
    amount: float = Field(..., gt=0, le=10000000, description="Transaction amount (positive)")
    timestamp: str = Field(..., description="ISO 8601 timestamp")
    source_account: str = Field(..., min_length=3, max_length=50)
    target_account: str = Field(..., min_length=3, max_length=50)
    
    @field_validator('amount')
    @classmethod
    def validate_amount_precision(cls, v):
        # Validate decimal places for currency
        pass
    
    @field_validator('timestamp')
    @classmethod
    def validate_timestamp_not_future(cls, v):
        # Ensure timestamp is not in future
        pass
    
    @model_validator(mode='after')
    def validate_cross_fields(self):
        # Validate source != target
        pass
```

### Phase 3: Rate Limiting Integration
**File**: `src/api/main.py`
- Configure SLOWAPI limiters
- Add per-account tracking
- Add quota management

### Phase 4: Error Response Enhancement
**File**: `src/exceptions/error_responses.py`
- Add validation error details
- Add remediation suggestions
- Standardize format

### Phase 5: Comprehensive Testing
**File**: `tests/test_api_validation.py` (NEW)
- 20+ validation test cases
- Edge case coverage
- Error message consistency

---

## 📊 Expected Outcomes

### Code Quality
- ✅ 100% of API inputs validated
- ✅ Consistent error messages
- ✅ Better developer experience (clear error hints)
- ✅ Improved system reliability

### Performance
- ✅ Early validation rejection (fail-fast)
- ✅ Reduced unnecessary processing
- ✅ Better rate limiting prevents abuse

### Test Coverage
- ✅ 20+ new validation tests
- ✅ Full edge case coverage
- ✅ Error message consistency verified

---

## 🔗 Related Files

**Core Files to Modify**:
- `src/api/main.py` - Endpoint validation integration
- `src/api/schemas.py` - Pydantic models with validators
- `src/exceptions/` - Error handling enhancements

**New Files to Create**:
- `src/api/validators.py` - Validation business logic
- `tests/test_api_validation.py` - Comprehensive validation tests

**Reference Files**:
- `src/config/validators.py` - Existing validation patterns
- `tests/test_api_hardening.py` - Existing validation tests
- `tests/test_exception_logging.py` - Error handling examples

---

## 📈 Performance Metrics

| Metric | Target |
|--------|--------|
| Validation latency | <5ms per request |
| Error response size | <2KB |
| Rate limit check overhead | <1ms |
| Test execution time | <10s for full suite |

---

## 💡 Implementation Tips

1. **Use Pydantic Validators** - Leverage `@field_validator` and `@model_validator`
2. **Fail-Fast Pattern** - Validate early, return immediately on first error
3. **Batch Validation** - Collect all errors and return together
4. **Clear Messages** - Include field name, constraint, and suggestion
5. **Extensibility** - Design for easy addition of new validation rules

---

## 🧪 Testing Strategy

```python
# Example validation tests to add

def test_amount_validation_positive():
    """Amount must be positive"""
    pass

def test_amount_validation_negative():
    """Negative amounts should be rejected"""
    pass

def test_amount_validation_exceeds_max():
    """Amount exceeding maximum should be rejected"""
    pass

def test_timestamp_validation_future():
    """Future timestamps should be rejected"""
    pass

def test_timestamp_validation_too_old():
    """Very old timestamps should be rejected"""
    pass

def test_biometrics_validation_empty_array():
    """Empty biometrics arrays should be rejected"""
    pass

def test_cross_field_validation_same_accounts():
    """Source and target accounts must differ"""
    pass

def test_error_message_includes_field_name():
    """Error messages must include field name"""
    pass

def test_error_message_includes_suggestion():
    """Error messages must include remediation suggestion"""
    pass

def test_rate_limiting_per_account():
    """Rate limiting should enforce per-account limits"""
    pass

def test_batch_validation_partial_failure():
    """Batch should report errors per transaction"""
    pass

def test_currency_code_validation():
    """Currency must be valid ISO 4217 code"""
    pass

def test_account_id_format_validation():
    """Account IDs must match expected format"""
    pass

def test_mode_validation_enum():
    """Mode must be valid transaction type"""
    pass

def test_all_validation_errors_returned():
    """All validation errors returned together"""
    pass
```

---

## 📚 Documentation

- Update `DEPLOYMENT.md` with validation rules
- Add validation examples to API docs
- Document error codes and meanings
- Add rate limiting guidelines

---

## ⏱️ Time Estimate

| Task | Time |
|------|------|
| Design & Planning | 30 min |
| Validation Layer Implementation | 1.5 hours |
| Schema Enhancement | 45 min |
| Rate Limiting Integration | 45 min |
| Testing & Edge Cases | 1 hour |
| Documentation | 30 min |
| **Total** | **4-5 hours** |

**Level**: Intermediate

---

## 🏷️ Labels

- `intermediate`
- `enhancement`
- `validation`
- `error-handling`
- `api`
- `production-readiness`

---

## 📌 Milestones

1. Validation layer implemented ✓
2. Enhanced error messages ✓
3. Rate limiting configured ✓
4. Comprehensive tests passing ✓
5. Documentation updated ✓

---

## 🚀 Getting Started

### Prerequisites
- Familiarity with Pydantic validation
- Understanding of FastAPI request/response cycle
- Knowledge of rate limiting concepts

### Branch Name
```bash
issue-#7-api-validation
```

### Initial Commands
```bash
git checkout master
git pull origin master
git checkout -b issue-#7-api-validation
```

---

## 📞 Notes for Implementation

### Key Considerations

1. **Backward Compatibility**: Don't break existing API clients
2. **Clear Error Messages**: Developers should understand what went wrong
3. **Performance**: Validation should not add significant latency (<5ms)
4. **Extensibility**: Easy to add new validation rules
5. **Testing**: Comprehensive coverage of happy path and edge cases

### Production Readiness

This enhancement moves the API closer to production-ready state by:
- Preventing invalid data from entering the system
- Providing clear feedback to API clients
- Protecting against abuse via rate limiting
- Improving system reliability and security

---

## ✅ Definition of Done

- [x] All validation rules implemented
- [x] Error messages enhanced with suggestions
- [x] Rate limiting configured and tested
- [x] 20+ validation tests passing
- [x] Edge cases covered
- [x] No breaking changes
- [x] Documentation updated
- [x] Code review approved
- [x] Ready for merge

---

**Ready to Contribute?** 

1. Create a new branch: `git checkout -b issue-#7-api-validation`
2. Follow the implementation plan
3. Ensure all tests pass: `pytest tests/test_api_validation.py -v`
4. Submit a Pull Request with the issue description

Good luck! 🚀
