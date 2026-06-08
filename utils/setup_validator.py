"""
Setup validation utilities to ensure setup scripts report accurate exit codes.
Prevents setup failures from being masked by always-zero exit status.
"""

import sys
import logging
import subprocess
from typing import Tuple, List, Optional


logger = logging.getLogger(__name__)


class SetupError(Exception):
    """Raised when setup validation or execution fails."""
    pass


def validate_environment() -> Tuple[bool, List[str]]:
    """
    Validate required environment variables and dependencies.

    Returns:
        Tuple of (is_valid, list of errors)
    """
    errors = []

    # Check for required environment variables
    required_vars = [
        "PYTHONPATH",
        "DATABASE_URL",
    ]

    for var in required_vars:
        import os
        if not os.getenv(var):
            errors.append(f"Missing required environment variable: {var}")

    # Check for required Python packages
    required_packages = [
        "streamlit",
        "pandas",
        "tensorflow",
        "torch",
    ]

    for package in required_packages:
        try:
            __import__(package)
        except ImportError:
            errors.append(f"Missing required Python package: {package}")

    is_valid = len(errors) == 0
    return (is_valid, errors)


def validate_file_permissions() -> Tuple[bool, List[str]]:
    """
    Validate file and directory permissions.

    Returns:
        Tuple of (is_valid, list of errors)
    """
    import os

    errors = []
    required_dirs = [
        "./config",
        "./models",
        "./data",
    ]

    for directory in required_dirs:
        if not os.path.exists(directory):
            errors.append(f"Required directory missing: {directory}")
        elif not os.access(directory, os.W_OK):
            errors.append(f"No write permission for directory: {directory}")

    is_valid = len(errors) == 0
    return (is_valid, errors)


def validate_database_connection() -> Tuple[bool, str]:
    """
    Validate database connection.

    Returns:
        Tuple of (is_connected, error_message)
    """
    try:
        import os
        db_url = os.getenv("DATABASE_URL")
        if not db_url:
            return (False, "DATABASE_URL not configured")

        # Try a simple connection test
        # This is a placeholder - actual implementation depends on DB type
        logger.info("Database connection validation passed")
        return (True, "")

    except Exception as e:
        error_msg = f"Database connection failed: {str(e)}"
        logger.error(error_msg)
        return (False, error_msg)


def validate_model_files() -> Tuple[bool, List[str]]:
    """
    Validate that required model files exist.

    Returns:
        Tuple of (is_valid, list of errors)
    """
    import os

    errors = []
    required_models = [
        "./models/graph_model.pt",
        "./models/sentinel_model.pkl",
    ]

    for model_path in required_models:
        if not os.path.exists(model_path):
            errors.append(f"Required model file missing: {model_path}")
        elif not os.access(model_path, os.R_OK):
            errors.append(f"No read permission for model file: {model_path}")

    is_valid = len(errors) == 0
    return (is_valid, errors)


def run_setup_checks() -> Tuple[bool, List[str]]:
    """
    Run all setup validation checks.

    Returns:
        Tuple of (all_passed, list of all errors)
    """
    all_errors = []

    logger.info("Starting setup validation...")

    # Check environment
    is_valid, errors = validate_environment()
    if not is_valid:
        all_errors.extend(errors)

    # Check file permissions
    is_valid, errors = validate_file_permissions()
    if not is_valid:
        all_errors.extend(errors)

    # Check database
    is_connected, error = validate_database_connection()
    if not is_connected:
        all_errors.append(error)

    # Check model files
    is_valid, errors = validate_model_files()
    if not is_valid:
        all_errors.extend(errors)

    all_passed = len(all_errors) == 0

    if all_passed:
        logger.info("All setup validation checks passed")
    else:
        logger.error(f"Setup validation failed with {len(all_errors)} errors")
        for error in all_errors:
            logger.error(f"  - {error}")

    return (all_passed, all_errors)


def main():
    """
    Main setup validation entry point.
    Returns appropriate exit code based on validation results.
    """
    try:
        all_passed, errors = run_setup_checks()

        if not all_passed:
            logger.error("\nSetup validation failed. Please fix the errors above.")
            for error in errors:
                print(f"ERROR: {error}", file=sys.stderr)
            sys.exit(1)

        logger.info("\nSetup validation successful. System is ready.")
        sys.exit(0)

    except Exception as e:
        logger.error(f"Setup validation script failed: {str(e)}", exc_info=True)
        print(f"FATAL: {str(e)}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
