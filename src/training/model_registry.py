"""Local filesystem model registry with atomic manifest updates for production checkpoints."""

from __future__ import annotations

import copy
import hashlib
import json
import logging
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional, Union

from .storage_backends import LocalBackend, StorageBackend

logger = logging.getLogger(__name__)


class ModelRegistry:
    """Manage versioned model artifacts and a JSON manifest on the local filesystem."""

    def __init__(
        self,
        registry_dir: Union[str, Path],
        backend: Optional[StorageBackend] = None,
        max_history: int = 50,
    ):
        """Initialise the registry directory and load its manifest."""
        self.registry_dir = Path(registry_dir)
        self.registry_dir.mkdir(parents=True, exist_ok=True)
        self.backend = backend or LocalBackend(self.registry_dir)
        self.manifest_path = self.registry_dir / "registry_manifest.json"
        self._manifest_lock = threading.RLock()
        self._max_history = max_history
        self._manifest = self._load_manifest()

    def save_version(self, epoch: int, checkpoint: dict, metrics: dict) -> str:
        """Save a checkpoint as a versioned artifact and record it in the manifest."""
        version_id = f"v_epoch_{epoch}"
        artifact_name = f"htgnn_{version_id}.pt"
        # Resolve the full artifact path and verify containment within the registry directory
        artifact_path = (self.registry_dir / artifact_name).resolve()
        if not artifact_path.is_relative_to(self.registry_dir.resolve()):
            raise ValueError(f"Invalid artifact_path {artifact_path} outside of registry_dir {self.registry_dir}")

        # Atomic write: save to temp file, compute checksum, then rename.
        tmp_path = artifact_path.with_suffix(".tmp")
        import torch  # type: ignore

        torch.save(checkpoint, tmp_path)

        with open(tmp_path, "rb") as f:
            artifact_sha256 = hashlib.sha256(f.read()).hexdigest()

        tmp_path.rename(artifact_path)
        self.backend.save(artifact_path, artifact_name)

        entry = {
            "version_id": version_id,
            "epoch": epoch,
            "stage": "candidate",
            "metrics": metrics,
            "saved_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "artifact_path": artifact_name,
            "artifact_sha256": artifact_sha256,
        }
        with self._manifest_lock:
            self._manifest = self._load_manifest()  # Refresh manifest to avoid overwriting concurrent updates
            self._manifest["versions"].append(entry)
            if len(self._manifest["versions"]) > self._max_history:
                self._manifest["versions"] = self._manifest["versions"][-self._max_history:]
            self._write_manifest()
        return version_id

    def promote_champion(self, version_id: str) -> None:
        """Promote one manifest entry to champion and demote the others."""
        with self._manifest_lock:
            manifest = self._load_manifest()
            versions = manifest.get("versions", [])
            found = False
            for entry in versions:
                if isinstance(entry, dict) and entry.get("version_id") == version_id:
                    entry["stage"] = "champion"
                    found = True
                elif isinstance(entry, dict):
                    entry["stage"] = "candidate"

            if not found:
                raise ValueError(f"Unknown version_id: {version_id}")

            manifest["champion_version_id"] = version_id
            self._manifest = manifest
            self._write_manifest()

    def load_champion(self, model: Any, device: str) -> bool:
        """Load the champion checkpoint into the supplied model if one exists."""
        with self._manifest_lock:
            champion_version_id = self._manifest.get("champion_version_id")
            entry = self._find_version_entry(champion_version_id) if champion_version_id else None

        if not champion_version_id:
            logger.warning("No champion version recorded in %s", self.manifest_path)
            return False

        if entry is None:
            logger.warning(
                "Champion version %s is missing from registry manifest",
                champion_version_id,
            )
            return False

        try:
            artifact_path = self._resolve_registry_artifact_path(entry["artifact_path"])
        except ValueError as exc:
            logger.warning("Refusing champion artifact outside registry_dir: %s", exc)
            return False

        if not artifact_path.exists():
            try:
                self.backend.load(entry["artifact_path"], artifact_path)
            except Exception as exc:  # pragma: no cover - defensive logging path
                logger.warning("Failed to fetch champion checkpoint to %s: %s", artifact_path, exc)
                return False

        if not artifact_path.exists():
            logger.warning("Champion artifact not found at %s", artifact_path)
            return False

        # Verify checksum if recorded in manifest
        expected_sha256 = entry.get("artifact_sha256")
        if expected_sha256:
            with open(artifact_path, "rb") as f:
                actual_sha256 = hashlib.sha256(f.read()).hexdigest()
            if actual_sha256 != expected_sha256:
                logger.warning(
                    "Champion artifact %s checksum mismatch (expected=%s, actual=%s)",
                    artifact_path, expected_sha256, actual_sha256,
                )
                return False

        try:
            import torch  # type: ignore

            checkpoint = torch.load(artifact_path, map_location=device, weights_only=True)
            model.load_state_dict(checkpoint["model_state"])
        except Exception as exc:
            logger.warning("Failed to load champion checkpoint from %s: %s", artifact_path, exc)
            return False

        return True

    def get_manifest(self) -> dict:
        """Return a deep copy of the current manifest."""
        with self._manifest_lock:
            return copy.deepcopy(self._manifest)

    def _default_manifest(self) -> dict[str, Any]:
        """Create a fresh manifest structure."""
        return {
            "versions": [],
            "champion_version_id": None,
        }

    def _load_manifest(self) -> dict[str, Any]:
        """Load the manifest from disk or initialise a new one."""
        with self._manifest_lock:
            if not self.manifest_path.exists():
                manifest = self._default_manifest()
                self._manifest = manifest
                self._write_manifest()
                return manifest

            try:
                with self.manifest_path.open("r", encoding="utf-8") as handle:
                    manifest = json.load(handle)
            except (OSError, json.JSONDecodeError) as exc:
                logger.warning("Resetting invalid registry manifest at %s: %s", self.manifest_path, exc)
                manifest = self._default_manifest()
                self._manifest = manifest
                self._write_manifest()
                return manifest

            if not isinstance(manifest, dict):
                logger.warning("Registry manifest at %s was not a JSON object; resetting", self.manifest_path)
                manifest = self._default_manifest()
                self._manifest = manifest
                self._write_manifest()
                return manifest

            changed = False
            if not isinstance(manifest.get("versions"), list):
                manifest["versions"] = []
                changed = True
            if "champion_version_id" not in manifest:
                manifest["champion_version_id"] = None
                changed = True

            if changed:
                self._manifest = manifest
                self._write_manifest()
            return manifest

    def _write_manifest(self) -> None:
        """Atomically persist the in-memory manifest to disk."""
        tmp_path = self.manifest_path.with_suffix(self.manifest_path.suffix + ".tmp")
        with tmp_path.open("w", encoding="utf-8") as handle:
            json.dump(self._manifest, handle, indent=2, sort_keys=False)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, self.manifest_path)

    def _find_version_entry(self, version_id: str) -> Optional[dict[str, Any]]:
        """Return the manifest entry for a version id if it exists."""
        for entry in self._manifest.get("versions", []):
            if isinstance(entry, dict) and entry.get("version_id") == version_id:
                return entry
        return None

    def _resolve_registry_artifact_path(self, artifact_name: str) -> Path:
        """Resolve a manifest artifact path and ensure it stays inside the registry directory."""
        registry_root = self.registry_dir.resolve()
        artifact_path = (registry_root / Path(artifact_name)).resolve()
        if not artifact_path.is_relative_to(registry_root):
            raise ValueError(
                f"Invalid artifact_path {artifact_name} outside of registry_dir {self.registry_dir}"
            )
        return artifact_path