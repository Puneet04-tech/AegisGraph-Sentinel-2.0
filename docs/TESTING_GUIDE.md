# Testing Guide

This document explains how to test AegisGraph Sentinel 2.0 effectively and how contributors can validate their changes before creating a Pull Request.

---

# Why Testing Matters

The platform is responsible for detecting financial fraud and making real-time decisions.

Testing helps ensure:

- System reliability
- Stable model behavior
- API correctness
- Prevention of regressions
- Consistent fraud detection performance

---

# Testing Structure

The repository uses the following testing structure:

```text
tests/
├── test_api.py
├── test_models.py
├── test_features.py
└── ...
```

Each test file focuses on a specific component of the system.

---

# Running All Tests

Run the complete test suite:

```bash
pytest tests/
```

Expected result:

```text
All tests passed
```

---

# Running Tests with Coverage

Coverage helps identify untested code.

```bash
pytest --cov=src tests/
```

Example output:

```text
Name                    Coverage
---------------------------------
src/models                 92%
src/features               89%
src/api                    95%
```

Aim to maintain high coverage for critical modules.

---

# Running Specific Tests

### API Tests

```bash
pytest tests/test_api.py
```

### Model Tests

```bash
pytest tests/test_models.py
```

### Feature Tests

```bash
pytest tests/test_features.py
```

---

# Verbose Testing

To see detailed output:

```bash
pytest -v
```

Useful when debugging failures.

---

# Running Tests by Pattern

Run tests matching a keyword:

```bash
pytest -k risk
```

Example:

```bash
pytest -k velocity
```

---

# API Testing

Start the API server:

```bash
python -m src.api.main
```

Visit:

```text
http://localhost:8000/docs
```

Verify:

- Endpoints load correctly
- Requests return expected responses
- Validation errors are handled properly

---

# Manual API Validation

Example request:

```bash
curl -X POST \
http://localhost:8000/api/v1/fraud/check \
-H "Content-Type: application/json" \
-d '{
  "transaction_id":"TXN001",
  "amount":50000
}'
```

Expected:

```json
{
  "risk_score": 0.82,
  "decision": "REVIEW"
}
```

---

# Writing New Tests

When adding features:

1. Create corresponding test file.
2. Test normal behavior.
3. Test edge cases.
4. Test invalid inputs.
5. Test error handling.

Example:

```python
def test_velocity_score():
    score = calculate_velocity(10)
    assert score >= 0
```

---

# Common Testing Scenarios

### Feature Modules

Test:

- Velocity calculations
- Entropy calculations
- Behavioral biometrics
- Voice stress analysis

### Models

Test:

- Model loading
- Prediction output
- Embedding generation

### API

Test:

- Request validation
- Response formatting
- Error handling

---

# Debugging Failed Tests

Common causes:

## Missing Dependencies

Install:

```bash
pip install -r requirements.txt
```

## Incorrect Python Version

Verify:

```bash
python --version
```

Required:

```text
Python 3.9+
```

## Missing Configuration

Verify:

```text
config/config.yaml
.env
```

exist and are configured properly.

---

# Contributor Checklist

Before creating a Pull Request:

- [ ] Tests pass locally
- [ ] Documentation updated
- [ ] No unused imports
- [ ] No hardcoded secrets
- [ ] Feature works as expected
- [ ] Existing functionality unaffected

---

# Continuous Improvement

Future testing enhancements may include:

- Integration testing
- Load testing
- Performance benchmarking
- Security testing
- End-to-end testing

Maintaining a strong testing culture improves software quality and project reliability.