import os
import secrets
import logging
from pathlib import Path
from typing import Literal, Optional
from pydantic import BaseModel, SecretStr, Field, model_validator

logger = logging.getLogger(__name__)

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
    secret_key_was_generated: bool = Field(default=False, exclude=True)
    SECRET_KEY: SecretStr = Field(
        default_factory=lambda: SecretStr(
            os.getenv("SECRET_KEY") or generate_secure_key()
        )
    )
    SLACK_WEBHOOK_URL: Optional[str] = Field(default_factory=lambda: os.getenv("SLACK_WEBHOOK_URL"))

    def is_generated_secret_key(self) -> bool:
        """Return True if the SECRET_KEY was auto-generated."""
        return self.secret_key_was_generated

    # ML Model Registry Paths
    MODEL_DIR: Path = BASE_DIR / "models"
    BIOMETRICS_LSTM_ONNX_PATH: Path = BASE_DIR / "models" / "biometrics_lstm.onnx"
    HTGNN_MODEL_PATH: Path = BASE_DIR / "models" / "htgnn_model.pt"

    @model_validator(mode="after")
    def validate_secret_key_configuration(self) -> "AppSettings":
        """Enforce strong SECRET_KEY in production environments.

        In production (ENV=prod), SECRET_KEY must be explicitly configured.
        Using default generated keys in production enables trivial JWT forgery
        because the key is not cryptographically bound to the deployment.

        In non-production environments, logs a warning when using auto-generated keys.

        Returns:
            AppSettings: The validated settings instance

        Raises:
            ValueError: If running in production without explicit SECRET_KEY
        """
        secret_from_env = os.getenv("SECRET_KEY")
        was_generated = secret_from_env is None

        # Set the flag to track if key was generated
        self.secret_key_was_generated = was_generated

        # In non-production, warn if using generated key
        if self.ENV != "prod" and was_generated:
            logger.warning(
                "No SECRET_KEY configured. Using auto-generated development key. "
                "This key will change on each restart, invalidating any existing tokens. "
                "Set SECRET_KEY environment variable for persistent sessions.",
                extra={
                    "event_type": "config_generated_secret_key",
                    "environment": self.ENV,
                    "generated_key": True,
                }
            )

        # Only enforce explicit key in production
        if self.ENV != "prod":
            return self

        # Production requires explicit SECRET_KEY
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

        return self

# Instantiate a single global settings object to import across modules
settings = AppSettings()