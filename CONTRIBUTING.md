# Contributing to AegisGraph Sentinel 2.0

Thank you for your interest in contributing! This guide will help you get set up and understand the project structure.

We welcome contributions from students, researchers, and industry professionals working on financial fraud detection and graph neural networks.

## Table of Contents
- [Quick Start](#quick-start)
- [Development Environment](#development-environment)
- [Project Structure](#project-structure)
- [Graph Schema](#graph-schema)
- [Running Tests](#running-tests)
- [Code Style](#code-style)
- [Submitting Changes](#submitting-changes)

## Quick Start

```bash
# Clone the repository
git clone https://github.com/Brijeshrath67/AegisGraph-Sentinel-2.0.git
cd AegisGraph-Sentinel-2.0

# Create virtual environment (Python 3.9+ required)
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Configure settings
cp config/config.yaml.example config/config.yaml

# Generate synthetic training data
python -m src.data.synthetic_data_gen

# Train the model
python -m src.training.train

# Start the API server
python -m src.api.main
```

## Development Environment

### Python Version
- **Minimum**: Python 3.9
- **Recommended**: Python 3.11+

### Environment Variables
Create a `.env` file in the project root:

```bash
# Optional: Override default settings
LOG_LEVEL=INFO
DEVICE=cpu  # cuda, mps, or cpu
MODEL_PATH=models/htgnn_best.pt
```

### Core Dependencies
- **PyTorch** (2.0+) - Deep learning framework
- **PyTorch Geometric** - Graph neural networks
- **FastAPI** - REST API
- **NetworkX** - Graph manipulation

### Optional Dependencies
- **Redis** - Caching layer
- **Neo4j** - Graph database (for production)
- **librosa** - Voice stress analysis

## Project Structure

```
AegisGraph Sentinel 2.0/
├── config/                 # Configuration files
│   ├── config.yaml        # Main configuration
│   └── thresholds.yaml    # Detection thresholds
├── src/
│   ├── models/            # HTGAT and neural network models
│   │   ├── htgat.py       # Heterogeneous Temporal Graph Attention
│   │   ├── temporal_encoding.py
│   │   └── risk_model.py
│   ├── features/          # Feature extraction modules
│   │   ├── behavioral_biometrics.py  # Keystroke dynamics
│   │   ├── velocity_calculator.py    # Transaction velocity
│   │   ├── entropy_calculator.py     # Graph entropy
│   │   ├── honeypot_escrow.py        # Innovation 2
│   │   ├── predictive_mule_identification.py  # Innovation 4
│   │   ├── voice_stress_analysis.py  # Innovation 5
│   │   ├── blockchain_evidence.py     # Innovation 6
│   │   └── aegis_oracle_explainer.py # Innovation 3
│   ├── inference/         # Risk scoring and explanation
│   │   ├── risk_scorer.py
│   │   └── explainer.py
│   ├── training/          # Training pipeline
│   │   ├── trainer.py
│   │   └── losses.py
│   ├── api/              # FastAPI service
│   │   ├── main.py
│   │   └── schemas.py
│   └── utils/            # Helper utilities
│       └── helpers.py
├── tests/                 # Unit tests
├── data/                  # Generated datasets (created at runtime)
├── models/                # Saved model checkpoints (created at runtime)
└── app.py                # Streamlit web interface
```

## Graph Schema

### Node Types
The fraud detection graph contains 5 node types:

| Node Type | Description | Example |
|-----------|-------------|---------|
| **Account** | Bank account | ACC123456789 |
| **Device** | Mobile/computer | DEV_abc123 |
| **ATM** | ATM machine | ATM_MUM_001 |
| **Merchant** | Payment merchant | MERCHANT_XYZ |
| **IP** | IP address | 192.168.1.1 |

### Edge Types
Connections between nodes:

| Edge Type | Description | Attributes |
|-----------|-------------|------------|
| **Transfer** | Money transfer between accounts | amount, timestamp, mode |
| **Login** | Device login to account | timestamp, location, success |
| **Withdrawal** | Cash withdrawal | amount, atm_id, timestamp |
| **Association** | Social linking | relationship_type |

### Key Node Attributes
```python
# Account node
{
    'account_id': str,
    'account_type': str,  # savings, current, wallet
    'balance': float,
    'is_mule': bool,
    'risk_score': float  # 0-1
}

# Device node
{
    'device_id': str,
    'device_type': str,
    'fingerprint': str
}
```

### Key Edge Attributes
```python
# Transfer edge
{
    'amount': float,
    'timestamp': datetime,
    'mode': str,  # UPI, IMPS, NEFT, RTGS
    'transaction_id': str
}

# Login edge
{
    'timestamp': datetime,
    'ip_address': str,
    'location': str,
    'success': bool
}
```

### Graph Building
The system builds a dynamic subgraph for each transaction:
1. Extract k-hop neighbors (k=3 by default)
2. Limit to 1000 nodes / 5000 edges for performance
3. Apply temporal filtering (configurable window)

## Running Tests

### Run All Tests
```bash
pytest tests/
```

### Run with Coverage
```bash
pytest --cov=src tests/
```

### Run Specific Test File
```bash
pytest tests/test_models.py
pytest tests/test_api.py
pytest tests/test_features.py
```

### Run Tests by Pattern
```bash
pytest -k "test_risk"
pytest -v  # Verbose output
```

### Start API for Testing
```bash
# Terminal 1: Start API
python -m src.api.main

# Terminal 2: Run tests
pytest tests/test_api.py -v
```

### API Testing (Manual)
Once the API is running:
```bash
# Health check
curl http://localhost:8000/health

# Run comprehensive test
python test_all_innovations_comprehensive.py
```

## Code Style

### Formatting
We use **Black** for code formatting:
```bash
black src/ tests/
```

### Import Sorting
We use **isort**:
```bash
isort src/ tests/
```

### Type Checking
We use **mypy**:
```bash
mypy src/
```

### Pre-commit Hooks
Install pre-commit to run checks automatically:
```bash
pip install pre-commit
pre-commit install
```

### Linting
```bash
flake8 src/ tests/
```

## Submitting Changes

### Branch Naming Convention
- `issue-#<number>` - For fixing specific issues (e.g., `issue-#12`)
- `feature/<name>` - For new features (e.g., `feature/add-lateral-movement`)
- `hotfix/<name>` - For urgent fixes

### Pull Request Process

1. **Create a branch**:
   ```bash
   git checkout -b issue-#12
   ```

2. **Make your changes**:
   - Follow code style guidelines
   - Add tests for new functionality
   - Update documentation if needed

3. **Run tests locally**:
   ```bash
   pytest tests/  # All tests should pass
   ```

4. **Commit with clear messages**:
   ```bash
   git add .
   git commit -m "feat: Add lateral movement detection
   
   - Track betweenness centrality history per account
   - Detect spikes from baseline using std multiplier
   - Add +0.25 risk for lateral movement
   - References MITRE ATT&CK TA0008"
   ```

5. **Push and create PR**:
   ```bash
   git push origin issue-#12
   ```
   Then create a PR on GitHub with:
   - Clear title describing the change
   - Summary of what was changed and why
   - Links to related issues

### Commit Message Format
We follow [Conventional Commits](https://www.conventionalcommits.org/):
- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation
- `refactor:` Code refactoring
- `test:` Adding tests
- `chore:` Maintenance

### PR Title Examples
- `fix: Resolve hardcoded threshold in risk_scorer.py`
- `feat: Add honeypot escrow activation logic`
- `docs: Update CONTRIBUTING.md with graph schema`

## Getting Help

- **Issues**: Open a GitHub issue for bugs or feature requests
- **Discussions**: Use GitHub Discussions for questions
- **Documentation**: Check `docs/` folder for detailed docs

---

**We welcome contributions from students, researchers, and industry professionals!** 

For GSoC applicants: See our project ideas and don't hesitate to ask questions about the graph-based fraud detection approach.