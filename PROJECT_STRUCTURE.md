# AegisGraph Sentinel 2.0 - Project Structure

## Directory Organization

```
AegisGraph Sentinel 2.0/
│
├── README.md                      # Main project documentation
├── QUICKSTART.md                  # Quick start guide
├── requirements.txt               # Python dependencies
├── .gitignore                     # Git ignore patterns
│
├── config/                        # Configuration files
│   └── config.yaml               # Main configuration
│
├── src/                          # Source code
│   ├── __init__.py
│   │
│   ├── models/                   # Neural network models
│   │   ├── __init__.py
│   │   ├── htgat.py             # HTGAT layer implementation
│   │   ├── temporal_encoding.py  # Temporal encoding
│   │   └── risk_model.py        # Complete fraud detection model
│   │
│   ├── features/                 # Feature extraction modules
│   │   ├── __init__.py
│   │   ├── behavioral_biometrics.py  # Keystroke dynamics analysis
│   │   ├── velocity_calculator.py    # Transaction velocity
│   │   └── entropy_calculator.py     # Graph entropy
│   │
│   ├── training/                 # Training pipeline
│   │   ├── __init__.py
│   │   ├── losses.py            # Loss functions (Focal Loss, etc.)
│   │   └── trainer.py           # Training loop
│   │
│   ├── inference/                # Inference and scoring
│   │   ├── __init__.py
│   │   ├── risk_scorer.py       # Risk scoring pipeline
│   │   └── explainer.py         # Aegis-Oracle explainer
│   │
│   ├── api/                      # FastAPI service
│   │   ├── __init__.py
│   │   ├── main.py              # FastAPI application
│   │   └── schemas.py           # Pydantic schemas
│   │
│   ├── data/                     # Data generation and processing
│   │   ├── __init__.py
│   │   ├── data_generator.py   # Synthetic fraud data generator
│   │   └── graph_builder.py     # Graph construction (to be added)
│   │
│   └── utils/                    # Utility functions
│       ├── __init__.py
│       └── helpers.py           # Helper functions
│
├── notebooks/                    # Jupyter notebooks
│   ├── 01_data_exploration.ipynb
│   └── 02_model_training.ipynb
│
├── tests/                        # Unit tests
│   └── test_models.py
│
├── data/                         # Generated data (runtime)
│   └── synthetic/
│       ├── accounts.json
│       ├── transactions.json
│       ├── fraud_chains.json
│       └── graph.gpickle
│
├── models/                       # Saved model checkpoints (runtime)
│   ├── htgnn_best.pt
│   └── htgnn_final.pt
│
├── logs/                         # Training and inference logs (runtime)
│   └── training.log
│
├── docker/                       # Docker configuration
│   └── Dockerfile
│
└── example_usage.py              # Example scripts
    └── example_training.py
```

## Module Description

### `src/models/`
Core neural network architectures:
- **htgat.py**: Heterogeneous Temporal Graph Attention Network implementation
- **temporal_encoding.py**: Sinusoidal temporal encoding for edges
- **risk_model.py**: Complete fraud detection model combining HTGAT with risk prediction

### `src/features/`
Feature extraction and analysis:
- **behavioral_biometrics.py**: Keystroke dynamics and stress detection
- **velocity_calculator.py**: Transaction velocity and kinetic energy
- **entropy_calculator.py**: Graph entropy and structural anomaly detection

### `src/training/`
Model training infrastructure:
- **losses.py**: Custom loss functions (Focal Loss for imbalanced data)
- **trainer.py**: Training loop with early stopping and checkpointing

### `src/inference/`
Real-time fraud detection:
- **risk_scorer.py**: Multi-modal risk scoring combining all signals
- **explainer.py**: Aegis-Oracle explainable AI engine

### `src/api/`
REST API service:
- **main.py**: FastAPI application with endpoints
- **schemas.py**: Pydantic request/response schemas

### `src/data/`
Data generation and processing:
- **data_generator.py**: Synthetic fraud data with chain/star/mesh topologies

### `src/utils/`
Common utilities:
- **helpers.py**: Configuration loading, logging, device management

## Data Flow

```
Transaction Request
        ↓
[FastAPI Endpoint] → Validate input (schemas.py)
        ↓
[Risk Scorer] → Extract features
        ↓
    ┌───┴────┬──────────┬──────────┐
    ↓        ↓          ↓          ↓
[HTGNN] [Velocity] [Behavior] [Entropy]
    ↓        ↓          ↓          ↓
    └───┬────┴──────────┴──────────┘
        ↓
[Risk Aggregation] → Weighted combination
        ↓
[Decision Engine] → ALLOW / REVIEW / BLOCK
        ↓
[Aegis-Oracle] → Generate explanation
        ↓
Return response with risk score and explanation
```

## Key Features Implementation

### 1. **Hesitation Monitor**
- Location: `src/features/behavioral_biometrics.py`
- Function: `KeystrokeDynamicsAnalyzer.detect_stress()`
- Analyzes: Hold time, flight time, WPM, error rate

### 2. **Honeypot Virtual Escrow**
- Location: To be integrated in decision engine
- Concept: Deception-based fund containment

### 3. **Aegis-Oracle**
- Location: `src/inference/explainer.py`
- Class: `AegisOracle`
- Generates: Human-readable explanations

## Running Components

### Start API Server
```bash
python -m src.api.main
```

### Generate Synthetic Data
```bash
python -m src.data.data_generator
```

### Train Model
```bash
python example_training.py
```

### Test API
```bash
python example_usage.py
```

## Configuration

All settings are in `config/config.yaml`:
- Model architecture
- Training hyperparameters
- Risk scoring weights
- API settings
- Database connections

## Extension Points

### Adding New Features
1. Create feature extractor in `src/features/`
2. Integrate in `src/inference/risk_scorer.py`
3. Add weight in config file

### Adding New Models
1. Implement model in `src/models/`
2. Update `risk_model.py` to use new architecture
3. Adjust training pipeline if needed

### Adding New Endpoints
1. Define schema in `src/api/schemas.py`
2. Add endpoint in `src/api/main.py`
3. Update documentation

## Performance Considerations

- **Inference**: <200ms p99 latency target
- **Scalability**: Horizontal scaling via load balancer
- **Caching**: Redis for hot subgraphs
- **Optimization**: Model quantization, pruning, distillation

## Security

- Data encryption: AES-256 at rest, TLS 1.3 in transit
- Privacy: Only timing data collected, no keystroke content
- Authentication: JWT tokens (to be implemented)
- Rate limiting: To be added for production
