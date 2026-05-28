# AegisGraph Sentinel 2.0 — Production HTGNN Architecture

## Executive Summary

This document describes the **production-grade Heterogeneous Temporal Graph Neural Network (HTGNN)** implementation for real-time fraud detection and mule account identification. The system processes transaction streams, constructs dynamic heterogeneous graphs, and learns fraud patterns using graph neural networks.

---

## Part 1: Core Architecture

### 1.1 System Components

```
┌─────────────────────────────────────────────────────────────────┐
│                    Transaction Stream (Kafka)                  │
│         UPI/NEFT/IMPS/Card transfers, ATM withdrawals          │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│              Graph Construction Pipeline                         │
│  • Extract heterogeneous nodes (accounts, devices, IPs)         │
│  • Build edges (transfers, logins, withdrawals)                │
│  • Temporal encoding (edge timestamps)                          │
│  • Window-based snapshots (hourly/daily)                       │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│          Graph Database (Neo4j) + In-Memory Cache (Redis)       │
│  • Persistent: Full historical graphs for training/analysis    │
│  • Cache: Recent subgraphs for low-latency inference           │
└────────────────────────┬────────────────────────────────────────┘
                         │
        ┌────────────────┼────────────────┐
        │                │                │
        ▼                ▼                ▼
   [Training]    [Real-time Inference]  [Batch Scoring]
        │                │                │
        │    ┌───────────┴────────────┐   │
        │    ▼                        ▼   │
        │  ┌──────────────────────────┐  │
        │  │  HTGNN Model (PyTorch)  │  │
        │  │  + Temporal Encoding    │  │
        │  │  + Multi-head Attention │  │
        │  └──────────────────────────┘  │
        │    │                        │   │
        └────┼────────────────────────┼───┘
             │                        │
             ▼                        ▼
      ┌──────────────┐        ┌──────────────┐
      │ Model Store  │        │ Risk Scorer  │
      │ (S3/local)   │        │ + Explainer  │
      └──────────────┘        └──────┬───────┘
                                     │
                                     ▼
                              ┌──────────────┐
                              │  FastAPI     │
                              │  + Streamlit │
                              └──────────────┘
```

### 1.2 Node Types

| Node Type | Examples | Features |
|-----------|----------|----------|
| **Account** | Bank account IDs | balance, KYC_age, verification_level, daily_transactions_avg |
| **Device** | Mobile/laptop IDs | OS, device_type, first_seen_date |
| **IP** | IP addresses | country, ISP, first_seen_date, # accounts_from_ip |
| **Merchant** | Merchant codes | category, verification_status, transaction_count |
| **Phone** | Phone numbers | country_code, verified, # accounts_linked |

### 1.3 Edge Types

| Edge Type | Nodes | Features |
|-----------|-------|----------|
| **TRANSFER** | Account → Account | amount, timestamp, type (UPI/NEFT/etc) |
| **LOGIN** | Account → Device | timestamp, success/fail, duration |
| **WITHDRAW** | Account → ATM | amount, timestamp, location |
| **OWNS** | Account → Device/Phone/IP | timestamp (when linked) |
| **MERCHANTS_FROM** | Account → Merchant | amount, timestamp, count |

### 1.4 Temporal Dimensions

- **Edge Timestamps**: Precise transaction timestamp for temporal encoding
- **Time Windows**: 1h, 6h, 24h, 7d snapshots for pattern learning
- **Decay Factor**: Recent edges weighted higher (λ = 0.01, exponential decay)
- **Temporal Features**: Hour-of-day, day-of-week, absolute time since creation

---

## Part 2: HTGNN Model Design

### 2.1 Model Architecture

```python
HTGNN(
  input_dim=64,           # Node feature dimension
  hidden_dim=128,         # Hidden layer
  output_dim=64,          # Output embedding
  num_node_types=5,       # Account, Device, IP, Merchant, Phone
  num_edge_types=5,       # TRANSFER, LOGIN, WITHDRAW, OWNS, MERCHANTS_FROM
  num_layers=3,           # 3 attention layers
  heads=8,                # 8 attention heads
  dropout=0.2,
  temporal_dim=16         # Temporal encoding dimension
)
```

### 2.2 Key Components

**1. Temporal Encoding Layer**
- Sinusoidal positional encoding (Transformer-style) for edge timestamps
- Time-decay weighting: $w(t) = e^{-\lambda \cdot \Delta t}$
- Relative temporal features (time since account creation, etc.)

**2. Type-Specific Transformations**
- Separate linear layers for each node type (handles heterogeneity)
- Separate attention mechanisms for each edge type
- Relation-specific attention parameters

**3. Multi-Head Attention**
- 8 attention heads per layer
- Allows model to attend to different interaction types in parallel
- Concatenated and normalized across heads

**4. Temporal Message Passing**
- Messages from neighbors weighted by temporal decay
- Recent neighbors have more influence
- Supports learning of time-dependent patterns

### 2.3 Fraud Detection Head

```
[HTGNN Output] 
    → [Graph Pooling (attention-weighted sum)]
    → [Dense(64 → 32)]
    → [ReLU + Dropout]
    → [Dense(32 → 16)]
    → [Dense(16 → 1 + Sigmoid)]
    → [Risk Score ∈ [0, 1]]
```

---

## Part 3: Data & Training

### 3.1 Dataset Structure

**Raw Transaction Data:**
```json
{
  "transaction_id": "TXN_001",
  "source_account": "ACC_123",
  "target_account": "ACC_456",
  "amount": 50000,
  "timestamp": "2026-02-26T14:30:00Z",
  "mode": "UPI",
  "source_device_id": "DEV_A1",
  "source_ip": "192.168.1.1",
  "fraud_label": 0
}
```

**Graph Construction:**
- Time window: transactions from past 7 days
- Nodes: unique accounts, devices, IPs, merchants in time window
- Edges: transfer, login, withdrawal relationships
- Features: constructed from aggregated account statistics

### 3.2 Training Pipeline

1. **Data Preprocessing**
   - Normalize features (account balance, transaction amounts)
   - Temporal encoding of edge timestamps
   - One-hot encode categorical features
   - Handle missing values with imputation

2. **Graph Batching**
   - Sample transaction windows (hourly/daily)
   - Extract subgraph around each transaction
   - Use k-hop neighborhood (k=2)
   - Negative sampling (random negative accounts)

3. **Loss Function**
   - Focal Loss for class imbalance (fraud is ~1-2% of transactions)
   - $L = -\alpha (1-p_t)^\gamma \log(p_t)$
   - α=0.25, γ=2.0 (standard settings)

4. **Metrics**
   - ROC-AUC (primary metric)
   - Precision/Recall at different thresholds
   - F1 score (balanced)
   - Confusion matrix (TP, FP, FN, TN)
   - Average precision (PR-AUC)

### 3.3 Training Configuration

```yaml
training:
  batch_size: 32
  num_epochs: 50
  learning_rate: 0.001
  weight_decay: 0.0001
  optimizer: adam
  scheduler: cosine_annealing
  early_stopping_patience: 10
  
  loss:
    type: focal
    alpha: 0.25
    gamma: 2.0
  
  validation_split: 0.15
  test_split: 0.15
```

---

## Part 4: Real-Time Inference

### 4.1 Streaming Inference Pipeline

1. **Transaction Arrives** → FastAPI endpoint
2. **Subgraph Extraction**
   - Query Neo4j for k-hop neighborhood
   - Include transactions from last 24h
3. **Feature Extraction**
   - Node features: account stats, device history
   - Edge features: amounts, timestamps, types
4. **HTGNN Inference**
   - Forward pass through model
   - Output: risk score ∈ [0, 1]
5. **Risk Decision**
   - score ≥ 0.9: BLOCK
   - score ≥ 0.6: REVIEW
   - score < 0.6: ALLOW
6. **Explainability**
   - Attention weights from HTGNN
   - Identify high-influence neighbors
   - Trace suspicious paths

### 4.2 Latency Budget

```
Subgraph extraction:      50ms  (Neo4j query)
Feature engineering:      30ms  (aggregation)
Model inference:          20ms  (GPU forward pass)
Risk scoring + decision:  10ms  (logic)
──────────────────────────────
Total latency:           110ms  (target: <200ms for compliance)
```

---

## Part 5: Fraud Patterns

### 5.1 Mule Ring Detection

**Pattern**: Circular/linear chains of accounts rapidly moving funds

```
Algorithm:
1. For each high-risk account, extract out-neighbors
2. Track fund flow: A→B→C→D→...
3. Detect if chain re-enters source or forms a cycle
4. Score based on:
   - Chain length (longer = more suspicious)
   - Time between hops (shorter = more suspicious)
   - Participation in multiple rings
```

### 5.2 Fan-In / Fan-Out Patterns

**High Fan-Out** (distribution hub):
- Account with many outgoing transfers
- Each transfer to new account
- Risk = node.out_degree * avg_amount / node.balance

**High Fan-In** (collection account):
- Account with many incoming transfers
- From diverse source accounts
- Risk = node.in_degree * num_unique_sources

### 5.3 Velocity Anomalies

```
velocity_score = (
  (transaction_amount / account.daily_avg) * 0.4 +
  (transactions_today / account.daily_avg_count) * 0.3 +
  (account.age_days < 7 ? 1.0 : 0.0) * 0.3
)
```

### 5.4 Temporal Fraud Chains

**Learning Objective**: Detect sequences of events indicating coordinated fraud

```
Example Chain:
  T-60m: Account created (Suspicious)
  T-50m: Device linked from NEW IP
  T-40m: Receives transfer from known mule account
  T-20m: Large transfer to merchant (SUSPICIOUS)
  
Model learns weights for each edge type + temporal gaps
```

---

## Part 6: Explainability

### 6.1 Attention-Based Explanations

- Output HTGNN attention weights for each neighbor
- Trace which neighbors contributed most to risk score
- Visualize attention flow graph

### 6.2 Path Explanations

```
"Transaction flagged due to:"
1. Source account linked to 3 known mule accounts (weight: 0.4)
2. Target account has high fan-in from mule network (weight: 0.3)
3. Late-night transaction from new device (weight: 0.2)
4. Transaction amount 5x account daily average (weight: 0.1)

Suspicious neighbors (by influence):
  - ACC_MULE_001: attention=0.35
  - ACC_MULE_002: attention=0.28
  - DEV_UNKNOWN: attention=0.22
```

### 6.3 Visualization

- Subgraph visualization (Plotly/D3.js)
- Attention heatmaps
- Risk contribution breakdown

---

## Part 7: Scalability

### 7.1 Graph Database (Neo4j)

**Schema**:
```cypher
(Account {id, balance, kyc_age, verification_level})
  -[:TRANSFER {amount, timestamp, mode}]->
(Account)

(Account)
  -[:OWNS {timestamp}]->
(Device {id, os, device_type})

(Account)
  -[:OWNS {timestamp}]->
(IP {address, country, isp})

(Account)
  -[:MERCHANTS_TO {amount, timestamp}]->
(Merchant {code, category, status})
```

**Indexing**:
- Account ID (primary)
- Device ID (lookup)
- IP address (lookup)
- Timestamp (for time-window queries)

### 7.2 Caching (Redis)

```
Keys:
  account:{id}:features → account stats (TTL: 1h)
  account:{id}:neighbors:1h → 1-hop neighbors (TTL: 10m)
  account:{id}:neighbors:2h → 2-hop neighbors (TTL: 10m)
  model:inference_cache:{graph_hash} → model output (TTL: 5m)
```

### 7.3 Streaming (Kafka)

**Topics**:
- `transactions` — incoming transaction stream
- `fraud_alerts` — high-risk transactions for investigation
- `model_scores` — all transaction scores for logging/analysis
- `graph_updates` — incremental graph changes

**Processing**:
- Kafka consumer → transaction ingestion
- Real-time subgraph updates
- Async model inference with result publishing

### 7.4 Model Serving

- **Primary**: FastAPI with model in memory
- **Async Queue**: Celery/RabbitMQ for batch scoring
- **Fallback**: Redis cache for recent queries
- **Distributed**: Model sharding across GPUs if volume requires

---

## Part 8: Production Engineering

### 8.1 Configuration Management

```yaml
# config/production.yaml
system:
  name: AegisGraph Sentinel 2.0
  environment: production
  
model:
  type: HTGNN
  checkpoint: s3://aegis-models/prod/htgnn_v2_best.pt
  version: "2.0.0"
  device: cuda
  
databases:
  neo4j:
    uri: bolt://neo4j:7687
    user: ${NEO4J_USER}
    password: ${NEO4J_PASSWORD}
    max_connections: 50
  
  redis:
    host: redis
    port: 6379
    db: 0
    ttl_seconds: 3600
  
streaming:
  kafka:
    bootstrap_servers: kafka:9092
    topic_transactions: transactions
    consumer_group: fraud_detection
    
api:
  host: 0.0.0.0
  port: 8000
  workers: 4
  max_request_size_mb: 100
  timeout_seconds: 30
  
inference:
  batch_size: 32
  max_latency_ms: 200
  cache_enabled: true
  fallback_to_heuristics: true
  
security:
  auth_enabled: true
  rate_limit_per_minute: 1000
  api_keys_from_env: true
```

### 8.2 Logging & Monitoring

```python
# Structured logging
logger.info(
  "transaction_scored",
  transaction_id="TXN_001",
  risk_score=0.85,
  decision="REVIEW",
  inference_time_ms=120,
  model_version="2.0.0",
  graph_size=245
)
```

**Metrics to track**:
- Transaction latency (p50, p95, p99)
- Model inference latency
- Cache hit rate
- Database query latency
- API error rate
- False positive/negative rates (when ground truth available)

### 8.3 Error Handling

- Graceful degradation: if HTGNN fails, fallback to heuristics
- Structured exception handling
- Circuit breaker for external dependencies (Neo4j, Kafka)
- Retry logic with exponential backoff

---

## Part 9: Research & Best Practices

### 9.1 HTGNN Architecture Variants

1. **Heterogeneous Graph Attention Networks (HAN)**
   - Separate attention for each edge type
   - Meta-path guided aggregation
   - Reference: Wang et al., 2019

2. **Relational Graph Convolutional Networks (R-GCN)**
   - Per-relation weights
   - Simpler than HAN but less expressive

3. **Temporal Graph Networks (TGN)**
   - Explicit temporal encoding
   - Faster inference for streaming
   - Reference: Rossi et al., 2020

4. **Dynamic Heterogeneous Graph Neural Network (DyHGNN)**
   - Combines temporal + heterogeneous
   - Best for our use case
   - Reference: Guo et al., 2021

### 9.2 Fraud Detection Specific Techniques

- **Contrastive Learning**: Learn to distinguish fraud vs normal from same neighbors
- **Graph Autoencoders**: Reconstruct graph structure, anomalies have high reconstruction error
- **Explainable GNNs (GNNExplainer)**: Identify which subgraph caused the prediction
- **Link Prediction**: Predict future suspicious transfers
- **Community Detection**: Identify fraud rings as dense communities

### 9.3 Known Limitations

1. **Cold Start Problem**: New accounts have sparse neighborhoods
   - Mitigation: Use account creation features, KYC data, device history
   
2. **Concept Drift**: Fraud patterns evolve over time
   - Mitigation: Periodic retraining (weekly), online learning

3. **Graph Size**: Full transaction graph can exceed 10M nodes
   - Mitigation: Time-windowed subgraphs, sampling, sharding

4. **Interpretability**: GNN decisions can be hard to explain
   - Mitigation: Attention weights, path tracing, LIME/SHAP

5. **False Positives**: High FP rate impacts customer experience
   - Mitigation: Tiered decision (BLOCK vs REVIEW), analyst review queue

---

## Part 10: Infrastructure Requirements

### 10.1 Hardware (Estimated)

```
Development:
- 4-core CPU, 16GB RAM, 256GB SSD
- 1x GPU (RTX 3060 or better, 6GB VRAM)

Production:
- 16-core CPU, 64GB RAM, 2TB SSD
- 2x GPUs (A100 or RTX 6000, 40GB each)
- Kubernetes cluster (3+ nodes)

Neo4j:
- 8-core CPU, 32GB RAM (heap: 20GB)
- 1TB SSD (NVMe preferred)

Kafka:
- 3-node cluster
- 4-core CPU, 8GB RAM each
- 500GB SSD each
```

### 10.2 Network

- **Transactions/second**: 10k-100k (depending on bank size)
- **Latency**: <200ms per transaction
- **Bandwidth**: ~50Mbps inbound, 10Mbps outbound
- **Availability**: 99.9% SLA

### 10.3 Costs (Annual, AWS Estimate)

```
GPU instances:           $150k
Neo4j Enterprise:        $80k
Kafka/streaming:         $40k
Data storage:            $30k
Monitoring/logging:      $20k
R&D/optimization:        $50k
────────────────────────────
Total:                   ~$370k/year
(Smaller deployments: $50-150k/year)
```

---

## Part 11: Deployment & Operations

### 11.1 Deployment Process

1. **Model Training** (weekly)
   - Collect last week's transactions
   - Retrain HTGNN
   - Validate on holdout test set
   - If metrics improve, stage model

2. **Model Validation**
   - A/B test: new model vs current model
   - Monitor FP rate, FN rate, latency
   - 7-day shadow mode (log decisions, don't enforce)
   - Gradual rollout (10% → 50% → 100%)

3. **Monitoring**
   - Real-time dashboards (Grafana)
   - Alert on metric degradation
   - Daily model performance report
   - Fraud ring analysis (weekly)

---

## Summary: What's Real vs What's Heuristic

**Real HTGNN Components** ✓
- Graph construction from transaction streams
- Heterogeneous node/edge types
- Temporal encoding and decay
- Multi-head attention mechanism
- Learned model weights from training

**Heuristics** (fallback/supplementary)
- Velocity thresholds
- Simple degree-based risk
- Time-of-day checks
- Fixed rule-based patterns

**Decision Logic** (hybrid)
- HTGNN risk score: 70% weight
- Heuristic rules: 30% weight
- Thresholds: 0.6 (review), 0.9 (block)

---

**References:**
- HAN (Heterogeneous Attention Networks): Wang et al., 2019
- TGN (Temporal Graph Networks): Rossi et al., 2020
- DyHGNN: Guo et al., 2021
- GNNExplainer: Ying et al., 2019
- FraudBench: Zhou et al., 2023

**Next Steps:** Implement core modules following this architecture.
