import os
import secrets
from pathlib import Path
from typing import Literal, Optional
from pydantic import BaseModel, SecretStr, Field, field_validator

# Base Directory of the Project
BASE_DIR = Path(__file__).resolve().parent.parent

def get_bool_env(key: str, default: bool) -> bool:
    """Helper to safely parse boolean environment variables."""
    val = os.getenv(key)
    if val is None:
        return default
    return val.lower() in ("true", "1", "yes")

def generate_secure_key() -> str:
    """Generate a cryptographically secure random key for development.

    Returns:
        A 32-byte random hex string suitable for development use.
        NOT FOR PRODUCTION - always set SECRET_KEY environment variable.
    """
    return secrets.token_hex(32)

class AppSettings(BaseModel):
    """
    Centralized Application Configuration using core Pydantic.
    Completely decoupled from external settings packages to ensure full
    backward compatibility with Python 3.9 CI environments.

    Security: SECRET_KEY must be explicitly set in production (ENV=prod).
    Development uses a generated key, but production deployment requires
    explicit configuration to prevent JWT forgery attacks.
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
    # Must be set explicitly in production. Development uses generated key.
    SECRET_KEY: SecretStr = Field(
        default_factory=lambda: SecretStr(
            os.getenv("SECRET_KEY") or generate_secure_key()
        )
    )
    SLACK_WEBHOOK_URL: Optional[str] = Field(default_factory=lambda: os.getenv("SLACK_WEBHOOK_URL"))

    # ML Model Registry Paths
    MODEL_DIR: Path = BASE_DIR / "models"
    BIOMETRICS_LSTM_ONNX_PATH: Path = BASE_DIR / "models" / "biometrics_lstm.onnx"
    HTGNN_MODEL_PATH: Path = BASE_DIR / "models" / "htgnn_model.pt"

    @field_validator("SECRET_KEY", mode="after")
    @classmethod
    def validate_secret_key_in_production(cls, v: SecretStr, info) -> SecretStr:
        """Enforce strong SECRET_KEY in production environments.

        In production (ENV=prod), SECRET_KEY must be explicitly configured.
        Using default generated keys in production enables trivial JWT forgery
        because the key is not cryptographically bound to the deployment.

        Args:
            v: The SECRET_KEY value
            info: Pydantic validation context with other field values

        Returns:
            SecretStr: The validated secret key

        Raises:
            ValueError: If running in production without explicit SECRET_KEY
        """
        env = info.data.get("ENV", "dev")

        # Only enforce in production
        if env != "prod":
            return v

        # Check if SECRET_KEY was explicitly set
        secret_from_env = os.getenv("SECRET_KEY")
        if not secret_from_env:
            raise ValueError(
                "SECRET_KEY must be explicitly set when ENV='prod'. "
                "Production deployments cannot use generated or default keys. "
                "This prevents JWT forgery attacks and ensures secure token signing. "
                "Set SECRET_KEY to a cryptographically random value (e.g., 'python -c \"import secrets; print(secrets.token_hex(32))\"')."
            )

        # Validate minimum length (32 bytes = 64 hex chars)
        if len(secret_from_env) < 32:
            raise ValueError(
                f"SECRET_KEY in production must be at least 32 characters long. "
                f"Current length: {len(secret_from_env)}. "
                "Use 'python -c \"import secrets; print(secrets.token_hex(32))\"' to generate a secure key."
            )

        return v

# Instantiate a single global settings object to import across modules
settings = AppSettings()