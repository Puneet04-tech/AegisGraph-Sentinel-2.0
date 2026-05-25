import logging

logger = logging.getLogger(__name__)


def validate_environment(settings=None, startup_logger=None):
    """Validate required environment variables on startup."""
    from .settings import get_settings
    from .validators import validate_runtime_settings

    active_settings = settings or get_settings(refresh=True)
    return validate_runtime_settings(
        active_settings,
        logger=startup_logger or logger,
    )
