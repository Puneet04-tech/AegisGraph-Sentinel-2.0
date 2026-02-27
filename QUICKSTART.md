# Quick Start Guide

## Installation

### 1. Create Virtual Environment

```bash
cd "AegisGraph Sentinel 2.0"
python -m venv venv

# Windows
.\venv\Scripts\activate

# Linux/Mac
source venv/bin/activate
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Generate Synthetic Data

```bash
python -m src.data.data_generator
```

This will create:
- `data/synthetic/accounts.json`
- `data/synthetic/transactions.json`
- `data/synthetic/fraud_chains.json`
- `data/synthetic/graph.gpickle`

## Running the API Server

### Start the server:

```bash
python -m src.api.main
```

The API will be available at:
- **API Endpoint**: http://localhost:8000
- **Documentation**: http://localhost:8000/docs
- **Alternative Docs**: http://localhost:8000/redoc

### Test the API:

```bash
# Health check
curl http://localhost:8000/health

# Check a transaction
curl -X POST http://localhost:8000/api/v1/fraud/check \
  -H "Content-Type: application/json" \
  -d '{
    "transaction_id": "TXN123456789",
    "source_account": "ACC987654321",
    "target_account": "ACC123456789",
    "amount": 50000.00,
    "currency": "INR",
    "mode": "UPI",
    "timestamp": "2026-02-26T14:30:00Z",
    "biometrics": {
      "hold_times": [120, 135, 128, 142, 118],
      "flight_times": [200, 185, 210, 195]
    }
  }'
```

## Python API Usage

```python
import requests

# Transaction data
transaction = {
    "transaction_id": "TXN123456789",
    "source_account": "ACC987654321",
    "target_account": "ACC123456789",
    "amount": 50000.00,
    "currency": "INR",
    "mode": "UPI",
    "timestamp": "2026-02-26T14:30:00Z",
    "biometrics": {
        "hold_times": [120, 135, 128, 142, 118],
        "flight_times": [200, 185, 210, 195]
    }
}

# Check transaction
response = requests.post(
    "http://localhost:8000/api/v1/fraud/check",
    json=transaction
)

result = response.json()
print(f"Risk Score: {result['risk_score']}")
print(f"Decision: {result['decision']}")
print(f"Explanation: {result['explanation']}")
```

## Model Training (Advanced)

```python
from src.training.trainer import Trainer
from src.models.risk_model import FraudDetectionModel
from src.utils.helpers import load_config

# Load config
config = load_config('config/config.yaml')

# Create model
model = FraudDetectionModel(
    node_feature_dim=32,
    hidden_dim=128,
    output_dim=64,
    num_node_types=5,
    num_edge_types=4,
)

# Create trainer
trainer = Trainer(model, config)

# Train (requires prepared DataLoader)
# trainer.train(train_loader, val_loader)
```

## Directory Structure

```
AegisGraph Sentinel 2.0/
├── config/              # Configuration files
├── src/
│   ├── models/         # Neural network models
│   ├── features/       # Feature extraction
│   ├── training/       # Training pipeline
│   ├── inference/      # Risk scoring
│   ├── api/            # FastAPI service
│   ├── data/           # Data generation
│   └── utils/          # Utilities
├── data/               # Generated data (created at runtime)
├── models/             # Saved models (created at runtime)
├── logs/               # Logs (created at runtime)
└── notebooks/          # Jupyter notebooks
```

## Key Features

### 1. **Hesitation Monitor**
Analyzes keystroke dynamics to detect stress patterns:
```python
from src.features.behavioral_biometrics import analyze_keystroke_data

results = analyze_keystroke_data(
    press_times=[0.0, 0.15, 0.32, 0.48],
    release_times=[0.12, 0.28, 0.45, 0.62],
)

print(f"Stress Score: {results['stress_score']}")
```

### 2. **Velocity Analysis**
Computes transaction kinetic energy:
```python
from src.features.velocity_calculator import VelocityCalculator

calculator = VelocityCalculator()
features = calculator.compute_all_features(transactions, current_time)
print(f"Kinetic Energy: {features['kinetic_energy']}")
```

### 3. **Entropy Calculation**
Measures network diversity:
```python
from src.features.entropy_calculator import compute_entropy_risk_score

entropy_risk = compute_entropy_risk_score(account, graph)
print(f"Entropy Risk: {entropy_risk}")
```

### 4. **Explainable AI**
Generate human-readable explanations:
```python
from src.inference.explainer import generate_explanation

explanation = generate_explanation(transaction, risk_result)
print(explanation['explanation'])
```

## Configuration

Edit `config/config.yaml` to customize:
- Model architecture
- Risk scoring weights
- Thresholds
- Training hyperparameters

## Troubleshooting

### Port already in use
```bash
# Change port in config/config.yaml
api:
  port: 8001
```

### CUDA out of memory
```bash
# Use CPU in config/config.yaml
model:
  device: "cpu"
```

### Import errors
```bash
# Ensure you're in the project root and venv is activated
cd "AegisGraph Sentinel 2.0"
.\venv\Scripts\activate  # Windows
pip install -r requirements.txt
```

## Next Steps

1. **Explore the API**: Visit http://localhost:8000/docs
2. **Generate Data**: Run the data generator
3. **Train Model**: Prepare your dataset and train
4. **Deploy**: Use Docker for production deployment

## Support

For questions or issues, please refer to the full documentation in the project report.
