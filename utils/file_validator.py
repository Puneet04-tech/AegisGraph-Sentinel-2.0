"""
File upload validation utilities to enforce size limits and prevent abuse.
Ensures all file uploads respect configured size constraints.
"""

import os
import logging
from typing import Optional, Tuple

logger = logging.getLogger(__name__)

# Get max upload size from environment or use default (5 MB)
MAX_BATCH_UPLOAD_BYTES = int(os.getenv("MAX_BATCH_UPLOAD_BYTES", 5 * 1024 * 1024))
MAX_AUDIO_UPLOAD_BYTES = int(os.getenv("MAX_AUDIO_UPLOAD_BYTES", 25 * 1024 * 1024))
MAX_IMAGE_UPLOAD_BYTES = int(os.getenv("MAX_IMAGE_UPLOAD_BYTES", 10 * 1024 * 1024))


class FileUploadError(Exception):
    """Raised when file upload validation fails."""
    pass


def validate_file_size(
    uploaded_file,
    max_bytes: int = MAX_BATCH_UPLOAD_BYTES,
    file_type: str = "file"
) -> Tuple[bool, Optional[str]]:
    """
    Validate uploaded file size.

    Args:
        uploaded_file: Streamlit UploadedFile object
        max_bytes: Maximum allowed file size in bytes
        file_type: Description of file type for error messages

    Returns:
        Tuple of (is_valid, error_message)
    """
    if uploaded_file is None:
        return (True, None)

    # Get file size safely
    file_size = getattr(uploaded_file, "size", 0)

    if file_size == 0:
        error_msg = f"Cannot determine {file_type} size. File may be empty or corrupted."
        logger.warning(error_msg)
        return (False, error_msg)

    if file_size > max_bytes:
        max_mb = max_bytes // (1024 * 1024)
        actual_mb = file_size / (1024 * 1024)
        error_msg = (
            f"{file_type.capitalize()} too large: {actual_mb:.1f}MB exceeds "
            f"maximum allowed size of {max_mb}MB"
        )
        logger.warning(f"File upload rejected: {error_msg}")
        return (False, error_msg)

    logger.debug(f"{file_type} size validation passed: {file_size} bytes")
    return (True, None)


def validate_csv_file(uploaded_file) -> Tuple[bool, Optional[str]]:
    """
    Validate CSV file upload.

    Args:
        uploaded_file: Streamlit UploadedFile object (CSV)

    Returns:
        Tuple of (is_valid, error_message)
    """
    if uploaded_file is None:
        return (True, None)

    # Check file size
    is_valid, error_msg = validate_file_size(
        uploaded_file,
        MAX_BATCH_UPLOAD_BYTES,
        "CSV file"
    )
    if not is_valid:
        return (False, error_msg)

    # Check file name
    if not uploaded_file.name.lower().endswith('.csv'):
        error_msg = "File must be a CSV file (.csv)"
        logger.warning(f"Invalid file type: {uploaded_file.name}")
        return (False, error_msg)

    logger.info(f"CSV file validation passed: {uploaded_file.name}")
    return (True, None)


def validate_audio_file(uploaded_file) -> Tuple[bool, Optional[str]]:
    """
    Validate audio file upload.

    Args:
        uploaded_file: Streamlit UploadedFile object (audio)

    Returns:
        Tuple of (is_valid, error_message)
    """
    if uploaded_file is None:
        return (True, None)

    # Check file size with audio-specific limit
    is_valid, error_msg = validate_file_size(
        uploaded_file,
        MAX_AUDIO_UPLOAD_BYTES,
        "Audio file"
    )
    if not is_valid:
        return (False, error_msg)

    # Check file extension
    audio_extensions = {'.wav', '.mp3', '.ogg', '.flac', '.m4a'}
    file_ext = os.path.splitext(uploaded_file.name)[1].lower()

    if file_ext not in audio_extensions:
        error_msg = f"Audio file must be one of: {', '.join(audio_extensions)}"
        logger.warning(f"Invalid audio format: {file_ext}")
        return (False, error_msg)

    logger.info(f"Audio file validation passed: {uploaded_file.name}")
    return (True, None)


def validate_image_file(uploaded_file) -> Tuple[bool, Optional[str]]:
    """
    Validate image file upload.

    Args:
        uploaded_file: Streamlit UploadedFile object (image)

    Returns:
        Tuple of (is_valid, error_message)
    """
    if uploaded_file is None:
        return (True, None)

    # Check file size with image-specific limit
    is_valid, error_msg = validate_file_size(
        uploaded_file,
        MAX_IMAGE_UPLOAD_BYTES,
        "Image file"
    )
    if not is_valid:
        return (False, error_msg)

    # Check file extension
    image_extensions = {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp'}
    file_ext = os.path.splitext(uploaded_file.name)[1].lower()

    if file_ext not in image_extensions:
        error_msg = f"Image file must be one of: {', '.join(image_extensions)}"
        logger.warning(f"Invalid image format: {file_ext}")
        return (False, error_msg)

    logger.info(f"Image file validation passed: {uploaded_file.name}")
    return (True, None)


def check_upload_limit(uploaded_file, file_type: str = "file") -> bool:
    """
    Check if file exceeds upload limit. Raises exception if invalid.

    Args:
        uploaded_file: Streamlit UploadedFile object
        file_type: Type of file being validated

    Returns:
        True if file is valid

    Raises:
        FileUploadError: If file validation fails
    """
    if file_type.lower() == "csv":
        is_valid, error_msg = validate_csv_file(uploaded_file)
    elif file_type.lower() == "audio":
        is_valid, error_msg = validate_audio_file(uploaded_file)
    elif file_type.lower() == "image":
        is_valid, error_msg = validate_image_file(uploaded_file)
    else:
        is_valid, error_msg = validate_file_size(uploaded_file)

    if not is_valid:
        raise FileUploadError(error_msg)

    return True


def get_file_size_mb(uploaded_file) -> float:
    """
    Get file size in megabytes.

    Args:
        uploaded_file: Streamlit UploadedFile object

    Returns:
        File size in MB
    """
    file_size = getattr(uploaded_file, "size", 0)
    return file_size / (1024 * 1024) if file_size > 0 else 0


def format_max_size(max_bytes: int) -> str:
    """
    Format maximum size in human-readable form.

    Args:
        max_bytes: Size in bytes

    Returns:
        Formatted size string (e.g., "5 MB")
    """
    if max_bytes >= 1024 * 1024 * 1024:
        return f"{max_bytes / (1024 * 1024 * 1024):.1f} GB"
    elif max_bytes >= 1024 * 1024:
        return f"{max_bytes / (1024 * 1024):.1f} MB"
    elif max_bytes >= 1024:
        return f"{max_bytes / 1024:.1f} KB"
    else:
        return f"{max_bytes} bytes"
