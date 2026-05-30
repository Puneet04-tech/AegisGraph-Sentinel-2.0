import os
from pathlib import Path
from typing import Literal, Optional
from pydantic import SecretStr, Field
from pydantic_settings import BaseSettings, SettingsConfigDict

# Base Directory of the Project
BASE_DIR = Path(__file__).resolve().parent.parent

class AppSettings(BaseSettings):
    """
    Centralized Application Configuration.
    Enforces type-safety and fail-fast validation on startup.
    """
    # Environment Profiles
    ENV: Literal["dev", "test", "prod"] = "dev"
    DEBUG: bool = True
    PROJECT_NAME: str = "AegisGraph-Sentinel-2.0"
    
    # Server Configurations
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    
    # Database Configuration
    DATABASE_URL: str = "postgresql+asyncpg://postgres:postgres@localhost:5432/aegis_db"
    
    # Security & Third-Party Secrets (SecretStr hides values from plaintext logs)
    SECRET_KEY: SecretStr = Field(default="fallback-insecure-key-change-in-production")
    SLACK_WEBHOOK_URL: Optional[str] = None
    
    # ML Model Registry Paths
    MODEL_DIR: Path = BASE_DIR / "models"
    BIOMETRICS_LSTM_ONNX_PATH: Path = BASE_DIR / "models" / "biometrics_lstm.onnx"
    HTGNN_MODEL_PATH: Path = BASE_DIR / "models" / "htgnn_model.pt"

    # Configuration for loading source
    model_config = SettingsConfigDict(
        env_file=os.path.join(BASE_DIR, ".env"),
        env_file_encoding="utf-8",
        extra="ignore",  # Gracefully ignore extra system environment variables
        case_sensitive=True
    )

# Instantiate a single global settings object to import across modules
settings = AppSettings()