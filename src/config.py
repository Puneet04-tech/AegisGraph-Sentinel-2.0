import os
from pathlib import Path
from typing import Literal, Optional
from pydantic import BaseModel, SecretStr, Field

# Base Directory of the Project
BASE_DIR = Path(__file__).resolve().parent.parent

def get_bool_env(key: str, default: bool) -> bool:
    """Helper to safely parse boolean environment variables."""
    val = os.getenv(key)
    if val is None:
        return default
    return val.lower() in ("true", "1", "yes")

class AppSettings(BaseModel):
    """
    Centralized Application Configuration using core Pydantic.
    Completely decoupled from external settings packages to ensure full 
    backward compatibility with Python 3.9 CI environments.
    """
    ENV: Literal["dev", "test", "prod"] = Field(default_factory=lambda: os.getenv("ENV", "dev"))
    DEBUG: bool = Field(default_factory=lambda: get_bool_env("DEBUG", True))
    PROJECT_NAME: str = Field(default_factory=lambda: os.getenv("PROJECT_NAME", "AegisGraph-Sentinel-2.0"))
    
    # Server Configurations
    HOST: str = Field(default_factory=lambda: os.getenv("HOST", "0.0.0.0"))
    PORT: int = Field(default_factory=lambda: int(os.getenv("PORT", "8000")))
    
    # Database Configuration
    DATABASE_URL: str = Field(default_factory=lambda: os.getenv("DATABASE_URL", "postgresql+asyncpg://postgres:postgres@localhost:5432/aegis_db"))
    
    # Security & Third-Party Secrets
    SECRET_KEY: SecretStr = Field(default_factory=lambda: SecretStr(os.getenv("SECRET_KEY", "fallback-insecure-key-change-in-production")))
    SLACK_WEBHOOK_URL: Optional[str] = Field(default_factory=lambda: os.getenv("SLACK_WEBHOOK_URL"))
    
    # ML Model Registry Paths
    MODEL_DIR: Path = BASE_DIR / "models"
    BIOMETRICS_LSTM_ONNX_PATH: Path = BASE_DIR / "models" / "biometrics_lstm.onnx"
    HTGNN_MODEL_PATH: Path = BASE_DIR / "models" / "htgnn_model.pt"

# Instantiate a single global settings object to import across modules
settings = AppSettings()