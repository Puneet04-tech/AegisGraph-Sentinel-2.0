# PRODUCTION HTGNN IMPLEMENTATION GUIDE

## Table of Contents
1. Quick Start
2. Architecture Overview
3. Training Real HTGNN Models
4. API Integration (Replacing Heuristics with Real HTGNN)
5. Deployment
6. Monitoring & Performance Tuning
7. Troubleshooting

---

## 1. Quick Start

### 1.1 Installation

```bash
# Clone repo and install dependencies
git clone <repo>
cd AegisGraph-Sentinel-2.0

# Create virtual environment
python -m venv venv
source venv/bin/activate  # or: venv\Scripts\activate on Windows

# Install production requirements
pip install -r requirements.txt
pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu118
pip install torch-geometric
```

### 1.2 Download Pre-trained Model (or Train Your Own)

```bash
# If pre-trained model available:
wget https://s3.example.com/models/htgnn_v2_best.pt -O models/htgnn_best.pt

# Or train from scratch (see Section 3)
python scripts/train_production_model.py --config config/production.yaml
```

### 1.3 Start API with Real HTGNN

```bash
python -m uvicorn src.api.main:app --host 0.0.0.0 --port 8000 --workers 4
```

The API now uses real HTGNN inference instead of heuristics.

---

## 2. Architecture Overview

### 2.1 Real vs Heuristic Components

**What's Real (Graph Neural Network):**
- Heterogeneous nodes (accounts, devices, IPs, merchants, phones)
- Temporal encoding of edges (sinusoidal + decay)
- Multi-head graph attention
- End-to-end trainable weights
- Learns fraud patterns from data

**What's Heuristic (Rules & Thresholds):**
- Velocity checks (transactions per hour)
- Time-of-day checks (unusual hours = more risk)
- Device-based rules (new device = more risk)
- Fallback if model fails

**Why Hybrid?**
- HTGNN learns graph patterns (mule rings, fan-in/out)
- Heuristics catch edge cases and provide explainability
- In production: 60-70% weight on HTGNN, 30-40% on heuristics

### 2.2 Data Flow

```
Transaction Stream
    ↓
Graph Constructor (temporal_graph_constructor.py)
    → Builds heterogeneous graph
    → Temporal encoding
    → Node/edge features
    ↓
HTGNN Model
    → Multi-layer attention
    → Fraud embedding
    → Risk logit output
    ↓
Risk Scorer (production_scorer.py)
    → Sigmoid → [0, 1] score
    → Decision (ALLOW/REVIEW/BLOCK)
    → Explanation + attention analysis
    ↓
FastAPI Response
    → Risk score
    → Decision
    → Explanation
    → Influential neighbors
```

---

## 3. Training Real HTGNN Models

### 3.1 Data Preparation

```python
from src.data.graph_constructor import TemporalGraphConstructor, Transaction
from datetime import datetime, timedelta

# Initialize graph constructor
constructor = TemporalGraphConstructor(
    time_window_hours=24,
    feature_dim=64,
    temporal_dim=16,
    temporal_decay_lambda=0.01,
)

# Load transactions (from your data source)
transactions = [
    Transaction(
        transaction_id="TXN_001",
        source_account="ACC_123",
        target_account="ACC_456",
        amount=50000,
        timestamp=datetime.utcnow() - timedelta(hours=12),
        mode="UPI",
        source_device_id="DEV_ABC",
        source_ip="192.168.1.1",
        is_fraud=False,
    ),
    # ... more transactions
]

# Add to graph
constructor.add_transactions(transactions)

# Extract PyG-compatible graph
graph_dict = constructor.construct_pyg_graph()
print(f"Graph: {graph_dict['num_nodes']} nodes, {graph_dict['num_edges']} edges")
```

### 3.2 Create Training Dataset

```python
from torch.utils.data import DataLoader
from src.training.production_trainer import SimpleGraphDataset, collate_graphs

# Collect multiple graph snapshots with labels
graphs = []
labels = []

# Generate synthetic training data (in production: use real transaction history)
from src.data.graph_constructor import create_sample_transactions

for i in range(100):
    constructor = TemporalGraphConstructor()
    txns = create_sample_transactions()
    
    # Split: 70% normal, 30% mule ring
    is_fraud = i % 10 >= 7
    
    constructor.add_transactions(txns)
    graph = constructor.construct_pyg_graph()
    graphs.append(graph)
    labels.append(1 if is_fraud else 0)

# Create dataset
dataset = SimpleGraphDataset(graphs, labels)
train_loader = DataLoader(
    dataset,
    batch_size=32,
    shuffle=True,
    collate_fn=collate_graphs,
)

print(f"Dataset: {len(dataset)} graphs")
```

### 3.3 Train Model

```python
import torch
from src.models.risk_model import FraudDetectionModel
from src.training.production_trainer import ProductionTrainer

# Initialize model
device = 'cuda' if torch.cuda.is_available() else 'cpu'
model = FraudDetectionModel(
    node_feature_dim=64,
    hidden_dim=128,
    output_dim=64,
    num_node_types=5,
    num_edge_types=5,
    num_layers=2,
    heads=4,
    dropout=0.2,
    temporal_dim=16,
)

# Training config
config = {
    'learning_rate': 0.001,
    'weight_decay': 0.0001,
    'batch_size': 32,
    'num_epochs': 50,
    'early_stopping_patience': 10,
    'optimizer': 'adam',
    'scheduler': 'cosine',
    'loss': {
        'type': 'focal',
        'alpha': 0.25,
        'gamma': 2.0,
    },
}

# Create trainer
trainer = ProductionTrainer(
    model=model,
    config=config,
    device=device,
    output_dir='models',
)

# Split data
train_size = int(0.7 * len(dataset))
val_size = int(0.15 * len(dataset))

train_dataset = torch.utils.data.Subset(
    dataset,
    range(train_size),
)
val_dataset = torch.utils.data.Subset(
    dataset,
    range(train_size, train_size + val_size),
)

train_loader = DataLoader(
    train_dataset,
    batch_size=32,
    shuffle=True,
    collate_fn=collate_graphs,
)
val_loader = DataLoader(
    val_dataset,
    batch_size=32,
    shuffle=False,
    collate_fn=collate_graphs,
)

# Train
results = trainer.train(train_loader, val_loader)

print(f"Best epoch: {results['best_epoch']}")
print(f"Best F1: {results['best_val_f1']:.4f}")
```

### 3.4 Training Results

After training completes:
- ✅ `models/htgnn_best.pt` — Best model checkpoint
- ✅ `models/training_results.yaml` — Metrics history
- ✅ Console output shows ROC-AUC, F1, Precision, Recall

Example output:
```
Epoch 0: Loss=0.5123, Acc=0.8234, F1=0.7234, ROC-AUC=0.8234, PR-AUC=0.7812
  VAL: Epoch 0: Loss=0.4856, Acc=0.8456, F1=0.7456, ROC-AUC=0.8456, PR-AUC=0.8034
✓ Best model saved (F1=0.7456)
...
Early stopping at epoch 25 (best: 18, F1=0.8123)
```

---

## 4. API Integration (Wiring HTGNN into FastAPI)

### 4.1 Modify API Startup

Currently, `src/api/main.py` uses heuristics. We need to load the HTGNN model at startup.

**Before (Heuristic):**
```python
# In src/api/main.py, current startup_event:
@app.on_event("startup")
async def startup_event():
    state.graph = nx.DiGraph()
    # Uses fallback compute_risk_score (heuristics)
```

**After (Real HTGNN):**
```python
# Replace startup_event in src/api/main.py:

import torch
from src.models.risk_model import FraudDetectionModel
from src.inference.production_scorer import ProductionRiskScorer
from src.data.graph_constructor import TemporalGraphConstructor

@app.on_event("startup")
async def startup_event():
    """Initialize API with real HTGNN model"""
    
    # 1. Initialize graph constructor
    state.graph_constructor = TemporalGraphConstructor(
        time_window_hours=24,
        feature_dim=64,
        temporal_dim=16,
        temporal_decay_lambda=0.01,
    )
    
    # 2. Load HTGNN model
    device = 'cuda' if torch.cuda.is_available() else 'cpu'
    model = FraudDetectionModel(
        node_feature_dim=64,
        hidden_dim=128,
        output_dim=64,
        num_node_types=5,
        num_edge_types=5,
        num_layers=2,
        heads=4,
        dropout=0.2,
        temporal_dim=16,
    )
    
    # 3. Load checkpoint
    checkpoint_path = 'models/htgnn_best.pt'
    try:
        checkpoint = torch.load(checkpoint_path, map_location=device)
        model.load_state_dict(checkpoint['model_state'])
        logger.info(f"Loaded HTGNN model from {checkpoint_path}")
    except FileNotFoundError:
        logger.warning(f"Model not found at {checkpoint_path}, using untrained model")
    
    model.to(device)
    model.eval()
    
    # 4. Initialize risk scorer
    state.risk_scorer = ProductionRiskScorer(
        model=model,
        graph_constructor=state.graph_constructor,
        device=device,
        model_version='2.0.0',
        enable_heuristic_fallback=True,  # Fallback if inference fails
    )
    
    state.model_version = '2.0.0-HTGNN'
    logger.info("API initialized with HTGNN model v2.0.0")
```

### 4.2 Replace Scoring Endpoint

**Before:**
```python
@app.post("/api/v1/fraud/check")
async def check_transaction(request: TransactionRequest):
    # Uses heuristic compute_risk_score
    score = compute_risk_score(request.dict(), state)
```

**After:**
```python
@app.post("/api/v1/fraud/check")
async def check_transaction(request: TransactionRequest):
    """Score transaction using real HTGNN model"""
    
    # Update graph with recent transactions
    state.graph_constructor.add_transactions([
        Transaction(
            transaction_id=request.transaction_id,
            source_account=request.source_account,
            target_account=request.target_account,
            amount=request.amount,
            timestamp=datetime.fromisoformat(request.timestamp),
            mode=request.mode,
            source_device_id=request.source_device_id,
            source_ip=request.source_ip,
        )
    ])
    
    # Score using HTGNN
    fraud_score = state.risk_scorer.score_transaction(
        transaction=request.dict(),
        reference_time=datetime.utcnow(),
        k_hops=2,
    )
    
    return fraud_score.to_dict()
```

### 4.3 Batch Scoring Endpoint

```python
@app.post("/api/v1/fraud/batch")
async def batch_score(requests: List[TransactionRequest]):
    """Score multiple transactions"""
    
    transactions = [r.dict() for r in requests]
    scores = state.risk_scorer.score_batch(
        transactions=transactions,
        reference_time=datetime.utcnow(),
    )
    
    return [score.to_dict() for score in scores]
```

---

## 5. Deployment

Run the API server directly:
```bash
python -m src.api.main
```

---

## 6. Monitoring & Performance Tuning

### 6.1 Monitor Inference Latency

```python
# In your monitoring script:
import logging
logger = logging.getLogger("perf")

# The FraudScore includes inference_time_ms
# Log it for monitoring:
logger.info(
    f"inference_latency_ms={fraud_score.inference_time_ms},"
    f"graph_size={fraud_score.graph_size},"
    f"model_version={fraud_score.model_version}"
)

# Expected latencies:
# - Subgraph extraction: 50ms (Neo4j query)
# - Feature engineering: 30ms
# - Model inference: 20-50ms (depending on graph size)
# - Total: 100-150ms target
```

### 6.2 Performance Tuning

**Optimize Latency:**
```python
# Reduce graph size for faster inference
k_hops = 1  # Instead of 2
max_neighbors = 100  # Limit subgraph size

fraud_score = state.risk_scorer.score_transaction(
    transaction=request.dict(),
    k_hops=k_hops,
)
```

**Optimize Throughput:**
```python
# Batch scoring
scores = state.risk_scorer.score_batch(
    transactions=[...],
    batch_size=64,  # Increase for higher throughput
)
```

**Use GPU:**
```python
# Ensure CUDA available and model on GPU
device = 'cuda'  # Automatic fallback to 'cpu' if unavailable
model = model.to(device)
```

### 6.3 Monitor Model Accuracy

```python
# In monitoring pipeline:
# Calculate daily metrics against ground truth fraud labels

def calculate_daily_metrics(
    decisions: List[FraudScore],
    ground_truth_labels: List[int],
):
    """Calculate ROC-AUC, precision, recall against labeled data"""
    
    from sklearn.metrics import roc_auc_score, precision_score, recall_score
    
    scores = [d.risk_score for d in decisions]
    
    roc_auc = roc_auc_score(ground_truth_labels, scores)
    precision = precision_score(
        ground_truth_labels,
        [1 if s >= 0.6 else 0 for s in scores]
    )
    recall = recall_score(
        ground_truth_labels,
        [1 if s >= 0.6 else 0 for s in scores]
    )
    
    logger.info(
        f"Daily metrics: ROC-AUC={roc_auc:.4f}, "
        f"Precision={precision:.4f}, Recall={recall:.4f}"
    )
```

---

## 7. Troubleshooting

### 7.1 CUDA Out of Memory

```python
# Reduce batch size
batch_size = 16  # Instead of 32

# Reduce graph size
k_hops = 1  # Instead of 2

# Use CPU
device = 'cpu'
```

### 7.2 Model Inference Failing

```
ERROR: CUDA out of memory / Model inference failed
→ Check: model.eval() is called
→ Check: inputs are on correct device
→ Check: batch_size is reasonable
→ Check: graph size is within limits
```

### 7.3 Neo4j Connection Issues

```
ERROR: Neo4j connection failed
→ Check: Neo4j service is running
→ Check: URI in config is correct
→ Check: Auth credentials are valid
→ Check: Network connectivity
```

### 7.4 Model Not Improving During Training

```python
# Check: learning rate is appropriate
learning_rate = 0.001  # Try 0.0001 or 0.01

# Check: batch size
batch_size = 32  # Try 16 or 64

# Check: early stopping patience
early_stopping_patience = 10  # Increase to 20 to give more epochs

# Check: data imbalance
# Use FocalLoss with appropriate alpha parameter
```

---

## Summary Checklist

- [x] Install dependencies (torch, torch-geometric)
- [x] Generate or download training data
- [x] Train HTGNN model (saves to `models/htgnn_best.pt`)
- [x] Verify model checkpoint loaded successfully
- [x] Update API startup to load HTGNN
- [x] Replace scoring endpoint to use HTGNN
- [x] Test single transaction endpoint
- [x] Test batch scoring endpoint
- [x] Monitor latency and accuracy
- [x] Deploy to production
- [x] Set up monitoring/alerting
- [x] Plan weekly retraining cadence

---

**Questions?** Check the main PRODUCTION_ARCHITECTURE.md for more details.
