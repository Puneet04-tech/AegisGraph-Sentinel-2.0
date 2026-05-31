import pytest

from src.training.storage_backends import LocalBackend


def test_local_backend_load_rejects_path_traversal(tmp_path):
    base_dir = tmp_path / "artifacts"
    backend = LocalBackend(base_dir)

    outside_source = tmp_path / "secret.txt"
    outside_source.write_text("top-secret", encoding="utf-8")

    with pytest.raises(ValueError, match="outside storage base directory"):
        backend.load("../secret.txt", tmp_path / "output.txt")
