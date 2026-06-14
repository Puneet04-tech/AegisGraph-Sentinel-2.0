# AegisGraph Sentinel 2.0 — API Reference

> **Base URL**: `http://localhost:8000`  
> **API Version**: v1  
> **Interactive Docs**: [http://localhost:8000/docs](http://localhost:8000/docs) (Swagger UI) | [http://localhost:8000/redoc](http://localhost:8000/redoc) (ReDoc)

---

## Table of Contents

- [Authentication](#authentication)
- [Common Headers](#common-headers)
- [Error Handling](#error-handling)
- [Endpoints](#endpoints)
  - [Fraud Detection](#1-fraud-detection)
  - [Voice Stress Analysis](#2-voice-stress-analysis)
  - [Predictive Mule Scoring](#3-predictive-mule-scoring)
  - [Honeypot Escrow](#4-honeypot-escrow)
  - [Blockchain Evidence](#5-blockchain-evidence)
- [Response Status Codes](#response-status-codes)
- [Data Types & Enums](#data-types--enums)
- [Rate Limits](#rate-limits)

---

## Authentication

All protected endpoints require an API key passed via the `X-API-Key` request header.

```http
X-API-Key: YOUR_API_KEY
```

**Default development key**: `SUPER_ADMIN`

### Authenticating via Swagger UI

1. Open [http://localhost:8000/docs](http://localhost:8000/docs)
2. Click the **Authorize** button (top right)
3. Enter your API key in the `APIKeyHeader` field
4. Click **Authorize**, then **Close**
5. A 🔒 padlock icon will appear next to all protected endpoints

> ⚠️ Never commit or expose your API key in client-side code or public repositories.

---

## Common Headers

| Header | Required | Description |
|--------|----------|-------------|
| `Content-Type` | Yes | Must be `application/json` for POST requests |
| `X-API-Key` | Yes (protected routes) | Your API key for authentication |

---

## Error Handling

All errors follow a consistent JSON structure:

```json
{
  "detail": "Human-readable error message",
  "error_code": "MACHINE_READABLE_CODE",
  "timestamp": "2026-05-17T10:30:00Z"
}
```

### Common Error Codes

| Error Code | HTTP Status | Description |
|------------|-------------|-------------|
| `UNAUTHORIZED` | 401 | Missing or invalid API key |
| `VALIDATION_ERROR` | 422 | Request body failed schema validation |
| `ACCOUNT_NOT_FOUND` | 404 | Specified account does not exist |
| `TRANSACTION_NOT_FOUND` | 404 | Specified transaction does not exist |
| `EVIDENCE_NOT_FOUND` | 404 | Blockchain evidence ID not found |
| `INTERNAL_ERROR` | 500 | Unexpected server-side error |
| `MODEL_UNAVAILABLE` | 503 | ML model not loaded or not ready |

### Example Error Response

```json
{
  "detail": "API key is missing or invalid.",
  "error_code": "UNAUTHORIZED",
  "timestamp": "2026-05-17T10:30:00Z"
}
```

---

## Endpoints

---

### 1. Fraud Detection

#### `POST /api/v1/fraud/check`

Analyzes a transaction in real-time using the Heterogeneous Temporal Graph Neural Network (HTGNN) and behavioral biometrics. Returns a risk score and decision within the 200–500ms authorization window.

**Authentication**: Required

**Request Body**

```json
{
  "transaction_id": "TXN123456789",
  "source_account": "ACC987654321",
  "target_account": "ACC123456789",
  "amount": 50000.00,
  "currency": "INR",
  "mode": "UPI",
  "timestamp": "2026-02-26T14:30:00Z",
  "device_id": "DEV123",
  "biometrics": {
    "hold_times": [120, 135, 128],
    "flight_times": [200, 185, 210]
  }
}
```

**Request Schema**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `transaction_id` | string | Yes | Unique identifier for the transaction |
| `source_account` | string | Yes | Account initiating the transfer |
| `target_account` | string | Yes | Account receiving the transfer |
| `amount` | float | Yes | Transaction amount in the specified currency |
| `currency` | string | Yes | ISO 4217 currency code (e.g. `INR`, `USD`) |
| `mode` | string | Yes | Payment mode — see [Payment Modes](#payment-modes) |
| `timestamp` | string (ISO 8601) | Yes | Transaction timestamp in UTC |
| `device_id` | string | No | Device identifier for behavioral context |
| `biometrics` | object | No | Keystroke dynamics — see below |
| `biometrics.hold_times` | array[int] | No | Key hold durations in milliseconds |
| `biometrics.flight_times` | array[int] | No | Key flight durations in milliseconds |

**Response Body**

```json
{
  "transaction_id": "TXN123456789",
  "risk_score": 0.76,
  "decision": "REVIEW",
  "risk_factors": [
    "High transaction velocity from source account",
    "Target account flagged in mule network graph"
  ],
  "graph_risk": 0.68,
  "biometric_risk": 0.54,
  "explanation": "Transaction flagged due to elevated graph centrality of target account and atypical keystroke timing.",
  "latency_ms": 112,
  "timestamp": "2026-02-26T14:30:00Z"
}
```

**Response Schema**

| Field | Type | Description |
|-------|------|-------------|
| `transaction_id` | string | Echoed transaction ID |
| `risk_score` | float (0–1) | Composite fraud probability score |
| `decision` | string | `ALLOW`, `REVIEW`, or `BLOCK` — see [Decisions](#decisions) |
| `risk_factors` | array[string] | Human-readable list of contributing risk signals |
| `graph_risk` | float (0–1) | Risk contribution from graph topology analysis |
| `biometric_risk` | float (0–1) | Risk contribution from behavioral biometrics |
| `explanation` | string | Aegis-Oracle natural language explanation |
| `latency_ms` | int | Total inference latency in milliseconds |
| `timestamp` | string (ISO 8601) | Response timestamp |

**Decision Thresholds**

| Decision | Risk Score Range | Action |
|----------|-----------------|--------|
| `ALLOW` | < 0.40 | Transaction proceeds normally |
| `REVIEW` | 0.40 – 0.75 | Flagged for analyst review; may proceed with delay |
| `BLOCK` | > 0.75 | Transaction blocked; honeypot escrow may be triggered |

---

### 2. Voice Stress Analysis

#### `POST /api/v1/voice/analyze`

Analyzes a base64-encoded audio clip for vocal stress patterns indicative of social engineering or coercion. Useful for phone-initiated transactions.

**Authentication**: Required

**Request Body**

```json
{
  "transaction_id": "TXN123",
  "audio_base64": "<base64_encoded_wav>",
  "sample_rate": 16000
}
```

**Request Schema**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `transaction_id` | string | Yes | Associated transaction identifier |
| `audio_base64` | string | Yes | Base64-encoded WAV audio data |
| `sample_rate` | int | Yes | Audio sample rate in Hz (recommended: `16000`) |

**Response Body**

```json
{
  "transaction_id": "TXN123",
  "stress_score": 74,
  "stress_level": "HIGH",
  "indicators": [
    "Elevated pitch variance",
    "Increased speech rate",
    "Tremor detected in vocal signal"
  ],
  "recommendation": "HOLD_FOR_REVIEW",
  "confidence": 0.91
}
```

**Response Schema**

| Field | Type | Description |
|-------|------|-------------|
| `transaction_id` | string | Echoed transaction ID |
| `stress_score` | int (0–100) | Vocal stress intensity score |
| `stress_level` | string | `LOW`, `MEDIUM`, or `HIGH` |
| `indicators` | array[string] | Detected acoustic stress signals |
| `recommendation` | string | `PROCEED`, `HOLD_FOR_REVIEW`, or `ESCALATE` |
| `confidence` | float (0–1) | Model confidence in the stress assessment |

---

### 3. Predictive Mule Scoring

#### `POST /api/v1/accounts/score-opening`

Scores a new or existing account for mule risk at the point of account opening, before any transaction occurs. Achieves 86% precision in pre-transaction detection.

**Authentication**: Required

**Request Body**

```json
{
  "account_id": "ACC_NEW_001",
  "name": "Test User",
  "age": 25,
  "profession": "Student",
  "email": "test@example.com",
  "phone": "+919876543210",
  "device_id": "DEVICE_001",
  "ip_address": "103.45.67.89",
  "stated_address": "Mumbai, India",
  "facial_match": 0.85,
  "document_type": "Aadhaar",
  "initial_deposit": 0.0
}
```

**Request Schema**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `account_id` | string | Yes | Unique identifier for the account being assessed |
| `name` | string | Yes | Account holder's full name |
| `age` | int | Yes | Account holder's age |
| `profession` | string | Yes | Self-declared profession |
| `email` | string | Yes | Email address |
| `phone` | string | Yes | Phone number in E.164 format |
| `device_id` | string | No | Device used during account opening |
| `ip_address` | string | No | IP address at time of opening |
| `stated_address` | string | No | Self-declared address |
| `facial_match` | float (0–1) | No | Facial recognition match score against document |
| `document_type` | string | No | KYC document type (e.g. `Aadhaar`, `PAN`, `Passport`) |
| `initial_deposit` | float | No | Initial deposit amount (INR) |

**Response Body**

```json
{
  "account_id": "ACC_NEW_001",
  "risk_score": 0.61,
  "risk_level": "MEDIUM",
  "risk_factors": [
    "IP address associated with known proxy network",
    "Low initial deposit atypical for stated profession"
  ],
  "recommendation": "ENHANCED_KYC",
  "confidence": 0.87
}
```

**Response Schema**

| Field | Type | Description |
|-------|------|-------------|
| `account_id` | string | Echoed account ID |
| `risk_score` | float (0–1) | Mule probability score |
| `risk_level` | string | `LOW`, `MEDIUM`, or `HIGH` |
| `risk_factors` | array[string] | Contributing signals to the risk score |
| `recommendation` | string | `APPROVE`, `ENHANCED_KYC`, or `REJECT` |
| `confidence` | float (0–1) | Model confidence in the assessment |

---

### 4. Honeypot Escrow

#### `GET /api/v1/honeypot/active`

Returns a list of all currently active honeypot escrow accounts being used for deceptive fund containment.

**Authentication**: Required

**Response Body**

```json
{
  "active_honeypots": [
    {
      "honeypot_id": "HP_001",
      "linked_transaction": "TXN123",
      "created_at": "2026-05-17T08:00:00Z",
      "status": "ACTIVE",
      "amount_contained": 50000.00
    }
  ],
  "total_count": 1
}
```

**Response Schema**

| Field | Type | Description |
|-------|------|-------------|
| `active_honeypots` | array[object] | List of active honeypot escrow records |
| `active_honeypots[].honeypot_id` | string | Unique honeypot identifier |
| `active_honeypots[].linked_transaction` | string | Transaction that triggered the honeypot |
| `active_honeypots[].created_at` | string (ISO 8601) | Honeypot creation timestamp |
| `active_honeypots[].status` | string | `ACTIVE`, `RESOLVED`, or `ESCALATED` |
| `active_honeypots[].amount_contained` | float | Amount held in escrow (INR) |
| `total_count` | int | Total number of active honeypots |

---

#### `GET /api/v1/honeypot/stats`

Returns aggregate statistics for the honeypot escrow system including arrest rates and recovery metrics.

**Authentication**: Required

**Response Body**

```json
{
  "total_honeypots_deployed": 412,
  "active_count": 38,
  "resolved_count": 358,
  "arrest_rate": 0.87,
  "total_amount_recovered": 47000000.00,
  "average_containment_duration_hours": 6.4
}
```

**Response Schema**

| Field | Type | Description |
|-------|------|-------------|
| `total_honeypots_deployed` | int | Cumulative honeypots deployed |
| `active_count` | int | Currently active honeypots |
| `resolved_count` | int | Honeypots that led to resolution |
| `arrest_rate` | float (0–1) | Proportion of cases leading to arrest |
| `total_amount_recovered` | float | Total INR recovered via honeypots |
| `average_containment_duration_hours` | float | Mean time funds are held before resolution |

---

### 5. Blockchain Evidence

#### `POST /api/v1/blockchain/seal`

Seals fraud evidence onto the Hyperledger Fabric blockchain, creating an immutable, court-admissible record in under 100ms.

**Authentication**: Required

**Request Body**

```json
{
  "transaction_id": "TXN123",
  "source_account": "ACC001",
  "target_account": "ACC789",
  "amount": 100000,
  "risk_result": {
    "risk_score": 0.92,
    "decision": "BLOCK"
  },
  "explanation": "High-risk mule chain detected"
}
```

**Request Schema**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `transaction_id` | string | Yes | Transaction to seal as evidence |
| `source_account` | string | Yes | Originating account |
| `target_account` | string | Yes | Destination account |
| `amount` | float | Yes | Transaction amount (INR) |
| `risk_result` | object | Yes | Risk assessment output to seal |
| `risk_result.risk_score` | float | Yes | Fraud probability score |
| `risk_result.decision` | string | Yes | System decision (`ALLOW`, `REVIEW`, `BLOCK`) |
| `explanation` | string | No | Aegis-Oracle explanation to include in evidence |

**Response Body**

```json
{
  "evidence_id": "EVD_abc123xyz",
  "blockchain_hash": "0xf4a3b2c1...",
  "sealed_at": "2026-05-17T10:30:00Z",
  "latency_ms": 87,
  "status": "SEALED"
}
```

**Response Schema**

| Field | Type | Description |
|-------|------|-------------|
| `evidence_id` | string | Unique identifier for the sealed evidence record |
| `blockchain_hash` | string | Hyperledger Fabric transaction hash |
| `sealed_at` | string (ISO 8601) | Timestamp when evidence was sealed |
| `latency_ms` | int | Time taken to seal the evidence |
| `status` | string | `SEALED` or `FAILED` |

---

#### `GET /api/v1/blockchain/verify/{evidence_id}`

Verifies the integrity and authenticity of a previously sealed evidence record.

**Authentication**: Required

**Path Parameters**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `evidence_id` | string | Yes | The evidence ID returned by `/blockchain/seal` |

**Response Body**

```json
{
  "evidence_id": "EVD_abc123xyz",
  "verified": true,
  "blockchain_hash": "0xf4a3b2c1...",
  "sealed_at": "2026-05-17T10:30:00Z",
  "tamper_detected": false,
  "chain_of_custody": [
    {
      "action": "SEALED",
      "actor": "AegisGraph-System",
      "timestamp": "2026-05-17T10:30:00Z"
    }
  ]
}
```

**Response Schema**

| Field | Type | Description |
|-------|------|-------------|
| `evidence_id` | string | Echoed evidence ID |
| `verified` | boolean | `true` if record is intact and unmodified |
| `blockchain_hash` | string | On-chain hash for independent verification |
| `sealed_at` | string (ISO 8601) | Original sealing timestamp |
| `tamper_detected` | boolean | `true` if hash mismatch is detected |
| `chain_of_custody` | array[object] | Ordered log of all actions on this evidence record |

---

## Response Status Codes

| HTTP Code | Meaning |
|-----------|---------|
| `200 OK` | Request succeeded |
| `201 Created` | Resource successfully created |
| `400 Bad Request` | Malformed request syntax |
| `401 Unauthorized` | Missing or invalid API key |
| `404 Not Found` | Resource does not exist |
| `422 Unprocessable Entity` | Request body validation failed |
| `500 Internal Server Error` | Unexpected server error |
| `503 Service Unavailable` | ML model not ready |

---

## Data Types & Enums

### Payment Modes

| Value | Description |
|-------|-------------|
| `UPI` | Unified Payments Interface |
| `NEFT` | National Electronic Funds Transfer |
| `RTGS` | Real-Time Gross Settlement |
| `IMPS` | Immediate Payment Service |
| `CARD` | Debit or credit card transaction |

### Decisions

| Value | Meaning |
|-------|---------|
| `ALLOW` | Transaction is low-risk; proceed normally |
| `REVIEW` | Transaction is medium-risk; flag for analyst |
| `BLOCK` | Transaction is high-risk; block and potentially honeypot |

### Risk Levels

| Value | Score Range |
|-------|-------------|
| `LOW` | 0.00 – 0.39 |
| `MEDIUM` | 0.40 – 0.74 |
| `HIGH` | 0.75 – 1.00 |

---

## Rate Limits

Rate limits are enforced per API key. Exceeding limits returns HTTP `429 Too Many Requests`.

| Endpoint Group | Limit |
|----------------|-------|
| `/api/v1/fraud/*` | 100 requests/minute |
| `/api/v1/voice/*` | 30 requests/minute |
| `/api/v1/accounts/*` | 60 requests/minute |
| `/api/v1/honeypot/*` | 60 requests/minute |
| `/api/v1/blockchain/*` | 60 requests/minute |

> 💡 For higher rate limits in production deployments, contact the development team.

---

*Last updated: May 2026 | AegisGraph Sentinel 2.0*
