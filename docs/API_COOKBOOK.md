# API Cookbook

This document provides practical examples for interacting with the AegisGraph Sentinel APIs.

---

# Fraud Detection API

## Endpoint

```http
POST /api/v1/fraud/check
```

## Example Request

```json
{
  "transaction_id": "TXN123456",
  "source_account": "ACC111",
  "target_account": "ACC222",
  "amount": 50000,
  "currency": "INR",
  "mode": "UPI"
}
```

## Example Response

```json
{
  "risk_score": 0.91,
  "decision": "BLOCK"
}
```

---

# Voice Stress Analysis

## Endpoint

```http
POST /api/v1/voice/analyze
```

## Example Request

```json
{
  "transaction_id": "TXN123",
  "audio_base64": "<base64-audio>",
  "sample_rate": 16000
}
```

## Example Response

```json
{
  "stress_score": 84
}
```

---

# Predictive Mule Detection

## Endpoint

```http
POST /api/v1/accounts/score-opening
```

## Example Request

```json
{
  "account_id": "ACC_NEW_001",
  "age": 25,
  "profession": "Student"
}
```

## Example Response

```json
{
  "risk_level": "HIGH"
}
```

---

# Honeypot Monitoring

## Active Honeypots

```http
GET /api/v1/honeypot/active
```

### Response

```json
{
  "active_honeypots": 15
}
```

---

# Blockchain Evidence

## Seal Evidence

```http
POST /api/v1/blockchain/seal
```

### Example Response

```json
{
  "evidence_id": "EVID123456"
}
```

---

# Error Response Format

```json
{
  "status": "error",
  "message": "Invalid request payload"
}
```

---

# cURL Example

```bash
curl -X POST \
http://localhost:8000/api/v1/fraud/check \
-H "Content-Type: application/json" \
-d '{
"transaction_id":"TXN001",
"amount":50000
}'
```

---

# Python Example

```python
import requests

response = requests.post(
    "http://localhost:8000/api/v1/fraud/check",
    json={
        "transaction_id":"TXN001",
        "amount":50000
    }
)

print(response.json())
```