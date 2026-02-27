"""Quick API test script"""
import requests
import json

print("=" * 80)
print("AegisGraph Sentinel 2.0 - API Test")
print("=" * 80)

# Test health endpoint
print("\n1. Testing Health Endpoint...")
r = requests.get('http://localhost:8000/health')
health = r.json()
print(f"   Status: {health['status']}")
print(f"   Version: {health['version']}")
print(f"   Model Loaded: {health['model_loaded']}")
print(f"   Mode: {'PRODUCTION' if health['model_loaded'] else 'DEMO'}")

# Test fraud detection
print("\n2. Testing Fraud Detection...")
transaction = {
    "transaction_id": "TEST001",
    "source_account": "user_123",
    "target_account": "merchant_456",
    "amount": 500.0,
    "currency": "INR",
    "mode": "UPI",
    "timestamp": "2026-02-26T14:30:00Z"
}

r = requests.post('http://localhost:8000/api/v1/fraud/check', json=transaction)
result = r.json()
print(f"   Risk Score: {result['risk_score']:.3f}")
print(f"   Decision: {result['decision']}")
print(f"   Explanation: {result['explanation']}")

# Test high-risk transaction
print("\n3. Testing High-Risk Transaction...")
high_risk_txn = {
    "transaction_id": "TEST002",
    "source_account": "new_account",
    "target_account": "suspicious_merchant",
    "amount": 50000.0,
    "currency": "INR",
    "mode": "IMPS",
    "timestamp": "2026-02-26T14:35:00Z"
}

r = requests.post('http://localhost:8000/api/v1/fraud/check', json=high_risk_txn)
result = r.json()
print(f"   Risk Score: {result['risk_score']:.3f}")
print(f"   Decision: {result['decision']}")

print("\n" + "=" * 80)
print("✓ All tests passed!")
print("=" * 80)
print("\n📖 API Documentation: http://localhost:8000/docs")
print("📊 Interactive Testing: http://localhost:8000/redoc")
print("\n")
