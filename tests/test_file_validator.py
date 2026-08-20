"""Unit tests for utils.file_validator upload validation helpers."""

import pytest

from utils.file_validator import (
    MAX_AUDIO_UPLOAD_BYTES,
    MAX_BATCH_UPLOAD_BYTES,
    MAX_IMAGE_UPLOAD_BYTES,
    FileUploadError,
    check_upload_limit,
    format_max_size,
    get_file_size_mb,
    validate_audio_file,
    validate_csv_file,
    validate_file_size,
    validate_image_file,
)


class FakeUploadedFile:
    """Minimal stand-in for a Streamlit UploadedFile object."""

    def __init__(self, name, size):
        self.name = name
        self.size = size


def test_validate_file_size_accepts_within_limit() -> None:
    is_valid, error_msg = validate_file_size(
        FakeUploadedFile("data.csv", 1024), MAX_BATCH_UPLOAD_BYTES, "CSV file"
    )
    assert is_valid is True
    assert error_msg is None


def test_validate_file_size_rejects_over_limit() -> None:
    over = MAX_BATCH_UPLOAD_BYTES + 1
    is_valid, error_msg = validate_file_size(
        FakeUploadedFile("big.csv", over), MAX_BATCH_UPLOAD_BYTES, "CSV file"
    )
    assert is_valid is False
    assert error_msg is not None
    assert "too large" in error_msg


def test_validate_file_size_rejects_at_limit() -> None:
    is_valid, _ = validate_file_size(
        FakeUploadedFile("at-limit.csv", MAX_BATCH_UPLOAD_BYTES)
    )
    assert is_valid is True


def test_validate_file_size_none_upload() -> None:
    is_valid, error_msg = validate_file_size(None)
    assert is_valid is True
    assert error_msg is None


def test_validate_file_size_unknown_size() -> None:
    is_valid, error_msg = validate_file_size(FakeUploadedFile("x.csv", 0))
    assert is_valid is False
    assert error_msg is not None
    assert "Cannot determine" in error_msg


def test_validate_file_size_missing_size_attr() -> None:
    class NoSize:
        name = "x.csv"

    is_valid, error_msg = validate_file_size(NoSize())
    assert is_valid is False
    assert error_msg is not None


def test_validate_csv_file_accepts_csv() -> None:
    is_valid, error_msg = validate_csv_file(FakeUploadedFile("transactions.csv", 2048))
    assert is_valid is True
    assert error_msg is None


def test_validate_csv_file_rejects_extension() -> None:
    is_valid, error_msg = validate_csv_file(FakeUploadedFile("data.xlsx", 2048))
    assert is_valid is False
    assert "CSV" in error_msg


def test_validate_csv_file_case_insensitive_extension() -> None:
    is_valid, _ = validate_csv_file(FakeUploadedFile("DATA.CSV", 2048))
    assert is_valid is True


def test_validate_csv_file_respects_size_limit() -> None:
    is_valid, error_msg = validate_csv_file(
        FakeUploadedFile("huge.csv", MAX_BATCH_UPLOAD_BYTES + 1)
    )
    assert is_valid is False
    assert "too large" in error_msg


def test_validate_csv_file_none() -> None:
    is_valid, error_msg = validate_csv_file(None)
    assert is_valid is True
    assert error_msg is None


def test_validate_audio_file_accepts_known_extensions() -> None:
    for ext in (".wav", ".mp3", ".ogg", ".flac", ".m4a"):
        is_valid, error_msg = validate_audio_file(
            FakeUploadedFile(f"call{ext}", MAX_AUDIO_UPLOAD_BYTES - 1)
        )
        assert is_valid is True, ext
        assert error_msg is None


def test_validate_audio_file_rejects_extension() -> None:
    is_valid, error_msg = validate_audio_file(FakeUploadedFile("call.txt", 1024))
    assert is_valid is False
    assert "Audio file must be one of" in error_msg


def test_validate_audio_file_rejects_over_audio_limit() -> None:
    is_valid, error_msg = validate_audio_file(
        FakeUploadedFile("long.wav", MAX_AUDIO_UPLOAD_BYTES + 1)
    )
    assert is_valid is False
    assert "too large" in error_msg


def test_validate_image_file_accepts_known_extensions() -> None:
    for ext in (".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp"):
        is_valid, error_msg = validate_image_file(
            FakeUploadedFile(f"photo{ext}", MAX_IMAGE_UPLOAD_BYTES - 1)
        )
        assert is_valid is True, ext
        assert error_msg is None


def test_validate_image_file_rejects_extension() -> None:
    is_valid, error_msg = validate_image_file(FakeUploadedFile("photo.pdf", 1024))
    assert is_valid is False
    assert "Image file must be one of" in error_msg


def test_validate_image_file_rejects_over_image_limit() -> None:
    is_valid, error_msg = validate_image_file(
        FakeUploadedFile("photo.png", MAX_IMAGE_UPLOAD_BYTES + 1)
    )
    assert is_valid is False
    assert "too large" in error_msg


@pytest.mark.parametrize(
    ("file_type", "filename", "size"),
    [
        ("csv", "ok.csv", 1024),
        ("audio", "ok.wav", 1024),
        ("image", "ok.png", 1024),
    ],
)
def test_check_upload_limit_valid_types(file_type, filename, size) -> None:
    assert check_upload_limit(FakeUploadedFile(filename, size), file_type) is True


def test_check_upload_limit_raises_on_invalid() -> None:
    with pytest.raises(FileUploadError):
        check_upload_limit(FakeUploadedFile("bad.exe", 1024), "csv")


def test_check_upload_limit_unknown_type_uses_default() -> None:
    assert check_upload_limit(FakeUploadedFile("data.bin", 1024), "other") is True


def test_get_file_size_mb() -> None:
    assert get_file_size_mb(FakeUploadedFile("x.csv", 5 * 1024 * 1024)) == 5.0
    assert get_file_size_mb(FakeUploadedFile("x.csv", 1024)) == pytest.approx(1024 / (1024 * 1024))
    assert get_file_size_mb(FakeUploadedFile("x.csv", 0)) == 0
    assert get_file_size_mb(None) == 0


def test_format_max_size() -> None:
    assert format_max_size(512) == "512 bytes"
    assert format_max_size(2048) == "2.0 KB"
    assert format_max_size(2 * 1024 * 1024) == "2.0 MB"
    assert format_max_size(3 * 1024 * 1024 * 1024) == "3.0 GB"
