# 🚀 New Contributor Onboarding Guide

Welcome to **AegisGraph Sentinel 2.0**! This guide is designed to help you go from zero to a working local development environment as smoothly as possible.

> 💡 For code style rules, commit conventions, and PR guidelines, see [CONTRIBUTING.md](../CONTRIBUTING.md).

---

## Table of Contents

- [Prerequisites](#prerequisites)
- [Environment Setup](#environment-setup)
- [Dependency Installation](#dependency-installation)
- [Local Development Workflow](#local-development-workflow)
- [Branching Strategy](#branching-strategy)
- [Submitting a Pull Request](#submitting-a-pull-request)
- [Troubleshooting](#troubleshooting)

---

## Prerequisites

Before you begin, make sure you have the following installed:

| Tool | Minimum Version | Check Command |
|------|----------------|---------------|
| Python | 3.9+ (3.11+ recommended) | `python --version` |
| Git | Any recent version | `git --version` |
| pip | Latest | `pip --version` |

Optional but useful for production setups:
- **Redis** — for caching
- **Neo4j** — graph database
- **CUDA** — if you want GPU-accelerated training

---

## Environment Setup

### 1. Fork and Clone the Repository

First, fork the repository on GitHub by clicking the **Fork** button at the top right. Then clone your fork locally:

```bash
git clone https://github.com/your-username/AegisGraph-Sentinel-2.0.git
cd AegisGraph-Sentinel-2.0
```

Add the original repo as `upstream` so you can sync future changes:

```bash
git remote add upstream https://github.com/Puneet04-tech/AegisGraph-Sentinel-2.0.git
```

Verify your remotes:

```bash
git remote -v
# origin    https://github.com/your-username/AegisGraph-Sentinel-2.0.git (fetch)
# upstream  https://github.com/Puneet04-tech/AegisGraph-Sentinel-2.0.git (fetch)
```

### 2. Create a Virtual Environment

It's important to use a virtual environment to keep project dependencies isolated from your system Python.

```bash
# Create the virtual environment
python -m venv venv

# Activate it — Mac/Linux
source venv/bin/activate

# Activate it — Windows
venv\Scripts\activate
```

You should see `(venv)` in your terminal prompt when it's active.

### 3. Configure Environment Variables

Copy the example config files:

```bash
cp config/config.yaml.example config/config.yaml
cp .env.example .env          # if .env.example exists
```

Open `.env` and set the following:

```bash
LOG_LEVEL=INFO
DEVICE=cpu          # Use: cuda, mps, or cpu
MODEL_PATH=models/htgnn_best.pt
API_URL=http://localhost:8000
CORS_ORIGINS=http://localhost:3000,http://localhost:8501
```

> 💡 Use `DEVICE=cuda` only if you have an NVIDIA GPU with CUDA installed.

---

## Dependency Installation

```bash
# Upgrade pip first to avoid version conflicts
pip install --upgrade pip

# Install all project dependencies
pip install -r requirements.txt
```

### Core Libraries Installed

| Library | Purpose |
|---------|---------|
| PyTorch (2.0+) | Deep learning framework |
| PyTorch Geometric | Graph neural networks |
| FastAPI | REST API server |
| NetworkX | Graph manipulation |

### Optional: Install Dev Tools

```bash
pip install pre-commit black isort mypy flake8
pre-commit install
```

This sets up automatic code formatting checks before every commit.

---

## Local Development Workflow

### Step 1: Generate Training Data

The project uses synthetic data for development. Generate it with:

```bash
python -m src.data.data_generator
```

This creates data files in the `data/` directory (created at runtime).

### Step 2: Train the Model

```bash
python -m src.training.trainer
```

Trained model checkpoints are saved in the `models/` directory.

### Step 3: Start the API Server

```bash
python -m src.api.main
```

- API will be available at: `http://localhost:8000`
- Interactive Swagger docs at: `http://localhost:8000/docs`

### Step 4: (Optional) Launch the Web Interface

```bash
streamlit run app.py
```

### Step 5: Run Tests

Always run tests before pushing your changes:

```bash
# Run all tests
pytest tests/

# Run with coverage report
pytest --cov=src tests/

# Run a specific test file
pytest tests/test_models.py -v
```

### Quick Health Check

Once the API is running, verify it's working:

```bash
curl http://localhost:8000/health
```

---

## Branching Strategy

### Why We Use Branches

Working on a branch (instead of directly on `main`) keeps your changes isolated. This means:
- Your work doesn't interfere with others
- Maintainers can review your changes cleanly
- You can easily update your fork if `main` gets new commits while you're working

### Branch Naming Convention

Always create a new branch from an up-to-date `main`:

```bash
# First, sync your fork with upstream
git checkout main
git pull upstream main

# Then create your branch
git checkout -b <branch-name>
```

| Type | Pattern | Example |
|------|---------|---------|
| Bug fix / Issue | `issue-#<number>` | `issue-#1137` |
| New feature | `feature/<name>` | `feature/add-lateral-movement` |
| Urgent fix | `hotfix/<name>` | `hotfix/fix-null-risk-score` |
| Documentation | `docs/<name>` | `docs/onboarding-guide` |

> ⚠️ **Never commit directly to `main`.** Always work on a feature/issue branch.

### Keeping Your Branch Up to Date

If `main` gets new commits while you're working, sync your branch:

```bash
git fetch upstream
git rebase upstream/main
```

---

## Submitting a Pull Request

1. **Commit your changes** with a clear message:

```bash
git add .
git commit -m "docs: Add new contributor onboarding guide

- Added environment setup steps
- Added branching strategy explanation
- Added troubleshooting section
- Closes #1137"
```

2. **Push your branch** to your fork:

```bash
git push origin issue-#1137
```

3. **Open a Pull Request** on GitHub:
   - Go to the original repository
   - Click **New Pull Request**
   - Select your branch
   - Fill in the PR template:
     - Clear title (e.g. `docs: Add ONBOARDING.md for new contributors`)
     - Summary of what you changed and why
     - Reference the issue: `Closes #1137`

4. **Wait for review** — a maintainer will review and may request changes.

---

## Troubleshooting

### ❌ `ModuleNotFoundError` after installing requirements

Your virtual environment might not be activated.

```bash
# Mac/Linux
source venv/bin/activate

# Windows
venv\Scripts\activate

# Then reinstall
pip install -r requirements.txt
```

### ❌ `config/config.yaml` not found

You haven't copied the example config file yet:

```bash
cp config/config.yaml.example config/config.yaml
```

### ❌ PyTorch Geometric install fails

PyTorch Geometric has specific version requirements. Install it manually matching your PyTorch version:

```bash
pip install torch-scatter torch-sparse torch-geometric \
  -f https://data.pyg.org/whl/torch-$(python -c "import torch; print(torch.__version__)").html
```

### ❌ API server won't start (port already in use)

Another process is using port 8000. Kill it:

```bash
# Mac/Linux
lsof -ti:8000 | xargs kill -9

# Windows
netstat -ano | findstr :8000
taskkill /PID <PID> /F
```

### ❌ `pytest` not found

```bash
pip install pytest pytest-cov
```

### ❌ CUDA not detected (GPU not being used)

Verify your CUDA installation:

```bash
python -c "import torch; print(torch.cuda.is_available())"
```

If it prints `False`, either CUDA isn't installed or your PyTorch version doesn't match your CUDA version. Visit [pytorch.org](https://pytorch.org/get-started/locally/) to install the correct version.

### ❌ `pre-commit` hooks failing on commit

Run the formatters manually, then try committing again:

```bash
black src/ tests/
isort src/ tests/
git add .
git commit -m "your message"
```

---

## Still Stuck?

- 💬 Open a [GitHub Discussion](https://github.com/Puneet04-tech/AegisGraph-Sentinel-2.0/discussions) for questions
- 🐛 Open a [GitHub Issue](https://github.com/Puneet04-tech/AegisGraph-Sentinel-2.0/issues) for bugs
- 📂 Check the `docs/` folder for additional documentation

---

**We're glad you're here. Welcome to the team! 🎉**
