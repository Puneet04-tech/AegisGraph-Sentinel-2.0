"""Pytest registry tests.

Run in isolation with:
pytest --noconftest tests/training/test_model_registry.py -v
"""

import json
from pathlib import Path

import pytest
torch = pytest.importorskip("torch", reason="torch not installed")

import src.training.model_registry as model_registry_module
from src.training.model_registry import ModelRegistry


def test_manifest_initialised_on_first_use(tmp_path):
    registry = ModelRegistry(tmp_path)

    manifest_path = tmp_path / "registry_manifest.json"
    assert manifest_path.exists(), "Registry manifest should be created on first use"
    assert registry.get_manifest() == {
        "versions": [],
        "champion_version_id": None,
    }


def test_save_version_creates_artifact_and_manifest_entry(tmp_path):
    registry = ModelRegistry(tmp_path)

    version_id = registry.save_version(
        epoch=3,
        checkpoint={"model_state": {"weight": torch.tensor([1.0])}},
        metrics={},
    )

    artifact_path = tmp_path / "htgnn_v_epoch_3.pt"
    manifest = registry.get_manifest()

    assert version_id == "v_epoch_3", "save_version should use the epoch-based version id"
    assert artifact_path.exists(), "Versioned checkpoint artifact was not written"
    assert len(manifest["versions"]) == 1, "Manifest should contain exactly one version entry"
    entry = manifest["versions"][0]
    assert entry["version_id"] == "v_epoch_3"
    assert entry["stage"] == "candidate"


def test_save_version_returns_version_id(tmp_path):
    registry = ModelRegistry(tmp_path)

    version_id = registry.save_version(
        epoch=7,
        checkpoint={"model_state": {}},
        metrics={},
    )

    assert version_id == "v_epoch_7"


def test_save_version_refreshes_manifest_before_write(tmp_path):
    registry = ModelRegistry(tmp_path)
    manifest_path = tmp_path / "registry_manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "versions": [
                    {
                        "version_id": "v_epoch_1",
                        "epoch": 1,
                        "stage": "candidate",
                        "metrics": {},
                        "saved_at": "2026-01-01T00:00:00Z",
                        "artifact_path": "htgnn_v_epoch_1.pt",
                    }
                ],
                "champion_version_id": None,
            }
        ),
        encoding="utf-8",
    )
    registry._manifest = {
        "versions": [],
        "champion_version_id": None,
    }

    registry.save_version(epoch=2, checkpoint={"model_state": {}}, metrics={})

    with manifest_path.open("r", encoding="utf-8") as handle:
        manifest = json.load(handle)

    version_ids = [entry["version_id"] for entry in manifest["versions"]]
    assert version_ids == ["v_epoch_1", "v_epoch_2"]


def test_promote_champion_sets_stage_and_manifest_key(tmp_path):
    registry = ModelRegistry(tmp_path)
    registry.save_version(epoch=1, checkpoint={"model_state": {}}, metrics={})
    registry.save_version(epoch=2, checkpoint={"model_state": {}}, metrics={})

    registry.promote_champion("v_epoch_2")
    manifest = registry.get_manifest()

    assert manifest["champion_version_id"] == "v_epoch_2"
    stages = {entry["version_id"]: entry["stage"] for entry in manifest["versions"]}
    assert stages["v_epoch_2"] == "champion"
    assert stages["v_epoch_1"] == "candidate"


def test_promote_champion_refreshes_manifest_before_write(tmp_path):
    registry = ModelRegistry(tmp_path)
    registry.save_version(epoch=1, checkpoint={"model_state": {}}, metrics={})
    manifest_path = tmp_path / "registry_manifest.json"

    with manifest_path.open("r", encoding="utf-8") as handle:
        manifest = json.load(handle)
    manifest["versions"].append(
        {
            "version_id": "v_epoch_99",
            "epoch": 99,
            "stage": "candidate",
            "metrics": {},
            "saved_at": "2026-01-01T00:00:00Z",
            "artifact_path": "htgnn_v_epoch_99.pt",
        }
    )
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    registry._manifest = {
        "versions": [
            {
                "version_id": "v_epoch_1",
                "epoch": 1,
                "stage": "candidate",
                "metrics": {},
                "saved_at": "2026-01-01T00:00:00Z",
                "artifact_path": "htgnn_v_epoch_1.pt",
            }
        ],
        "champion_version_id": None,
    }

    registry.promote_champion("v_epoch_1")

    with manifest_path.open("r", encoding="utf-8") as handle:
        manifest = json.load(handle)

    version_ids = [entry["version_id"] for entry in manifest["versions"]]
    assert version_ids == ["v_epoch_1", "v_epoch_99"]
    assert manifest["champion_version_id"] == "v_epoch_1"
    assert manifest["versions"][1]["stage"] == "candidate"


def test_promote_champion_raises_on_unknown_version(tmp_path):
    registry = ModelRegistry(tmp_path)

    with pytest.raises(ValueError, match="Unknown version_id"):
        registry.promote_champion("v_epoch_999")


def test_manifest_written_atomically(tmp_path, monkeypatch):
    registry = ModelRegistry(tmp_path)
    calls: list[tuple[Path, Path]] = []
    original_replace = model_registry_module.os.replace

    def recording_replace(src, dst):
        calls.append((Path(src), Path(dst)))
        return original_replace(src, dst)

    monkeypatch.setattr(model_registry_module.os, "replace", recording_replace)

    registry.save_version(
        epoch=5,
        checkpoint={"model_state": {}},
        metrics={},
    )

    assert len(calls) == 1, "Manifest should be written with a single atomic replace"
    src_path, dst_path = calls[0]
    assert src_path.name.endswith(".tmp"), "Atomic manifest write should use a .tmp source file"
    assert dst_path == tmp_path / "registry_manifest.json"


def test_load_champion_returns_false_when_no_champion(tmp_path):
    registry = ModelRegistry(tmp_path)
    model = torch.nn.Linear(2, 1)

    assert registry.load_champion(model, "cpu") is False


def test_load_champion_loads_state_dict(tmp_path):
    registry = ModelRegistry(tmp_path)
    model = torch.nn.Linear(2, 1)
    checkpoint = {"model_state": model.state_dict()}

    registry.save_version(epoch=1, checkpoint=checkpoint, metrics={})
    registry.promote_champion("v_epoch_1")

    model2 = torch.nn.Linear(2, 1)
    assert registry.load_champion(model2, "cpu") is True

    for key, expected_tensor in model.state_dict().items():
        actual_tensor = model2.state_dict()[key]
        assert torch.equal(
            actual_tensor,
            expected_tensor,
        ), f"Parameter {key} did not match the champion state dict"


def test_load_champion_returns_false_when_artifact_missing(tmp_path):
    registry = ModelRegistry(tmp_path)
    model = torch.nn.Linear(2, 1)

    registry.save_version(epoch=4, checkpoint={"model_state": model.state_dict()}, metrics={})
    registry.promote_champion("v_epoch_4")

    artifact_path = tmp_path / "htgnn_v_epoch_4.pt"
    artifact_path.unlink()

    assert registry.load_champion(model, "cpu") is False


def test_registry_survives_corrupt_manifest(tmp_path):
    manifest_path = tmp_path / "registry_manifest.json"
    manifest_path.write_text("{not valid json", encoding="utf-8")

    registry = ModelRegistry(tmp_path)
    manifest = registry.get_manifest()

    assert manifest == {
        "versions": [],
        "champion_version_id": None,
    }

    with manifest_path.open("r", encoding="utf-8") as handle:
        loaded = json.load(handle)
    assert loaded == manifest, "Recovered manifest file should contain valid JSON"


def test_get_manifest_returns_deep_copy(tmp_path):
    registry = ModelRegistry(tmp_path)
    manifest = registry.get_manifest()
    manifest["versions"].append({"version_id": "mutated"})
    manifest["champion_version_id"] = "mutated"

    fresh_manifest = registry.get_manifest()
    assert fresh_manifest == {
        "versions": [],
        "champion_version_id": None,
    }, "Mutating the returned manifest should not affect registry state"


def test_custom_backend_receives_save_and_load_calls(tmp_path):
    """A custom backend passed to ModelRegistry is called on save and load."""
    from pathlib import Path

    import torch

    from src.training.storage_backends import StorageBackend

    class RecordingBackend(StorageBackend):
        def __init__(self):
            self.saved: list[str] = []
            self.loaded: list[str] = []

        def save(self, local_path: Path, artifact_key: str) -> str:
            self.saved.append(artifact_key)
            return str(local_path)

        def load(self, artifact_key: str, local_path: Path) -> None:
            self.loaded.append(artifact_key)

        def exists(self, artifact_key: str) -> bool:
            return False

    backend = RecordingBackend()
    registry = ModelRegistry(tmp_path, backend=backend)
    model = torch.nn.Linear(2, 1)

    registry.save_version(
        epoch=1,
        checkpoint={"model_state": model.state_dict()},
        metrics={},
    )

    assert backend.saved == ["htgnn_v_epoch_1.pt"], (
        "Backend.save should be called once with the artifact filename"
    )
