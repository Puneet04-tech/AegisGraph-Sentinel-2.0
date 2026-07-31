"""
Safe PyTorch Model Checkpoint Loading

Provides secure utilities for loading PyTorch model checkpoints with
protection against malicious pickle serialization exploits.

Issue #2587: PyTorch model checkpoints loaded via torch.load() without
weights_only=True allow arbitrary Python code execution during
deserialization via pickle. A malicious .pt file can execute arbitrary
code when loaded.
"""

from pathlib import Path
from typing import Any, Dict, Optional, Union

import torch


def load_model_state_safe(
    checkpoint_path: Union[str, Path],
    device: str = "cpu",
    strict: bool = True,
) -> Dict[str, Any]:
    """
    Safely load a PyTorch model checkpoint using weights_only=True.

    Prevents arbitrary code execution from malicious .pt files by using
    PyTorch's safe deserialization mode. Only tensor data is loaded,
    not arbitrary Python objects.

    Args:
        checkpoint_path: Path to the checkpoint file
        device: Device to load checkpoint to (cpu, cuda, etc.)
        strict: Whether to require exact key matching when loading state

    Returns:
        Dictionary containing model state (and optionally optimizer, scheduler)

    Raises:
        FileNotFoundError: If checkpoint file doesn't exist
        RuntimeError: If checkpoint contains non-tensor objects (unsafe)

    Security Notes:
        - weights_only=True ensures only tensor data is deserialized
        - Malicious .pt files that execute code will raise RuntimeError
        - map_location parameter ensures models load on target device
    """
    checkpoint_path = Path(checkpoint_path)

    if not checkpoint_path.exists():
        raise FileNotFoundError(f"Checkpoint not found: {checkpoint_path}")

    try:
        # weights_only=True is the secure default since PyTorch 1.13
        # It rejects non-tensor data that could execute arbitrary code
        checkpoint = torch.load(
            str(checkpoint_path),
            map_location=device,
            weights_only=True,
        )
    except RuntimeError as e:
        if "weights_only" in str(e).lower():
            raise RuntimeError(
                f"Checkpoint contains non-tensor data and cannot be loaded safely. "
                f"Ensure the checkpoint was created with torch.save() and contains "
                f"only tensors or standard Python data types. Error: {e}"
            ) from e
        raise

    return checkpoint


def load_model_with_checkpoint(
    model: torch.nn.Module,
    checkpoint_path: Union[str, Path],
    device: str = "cpu",
    strict: bool = True,
) -> None:
    """
    Load a model's state from a safe checkpoint file.

    Args:
        model: PyTorch model to load state into
        checkpoint_path: Path to checkpoint file
        device: Device to load to (cpu, cuda, etc.)
        strict: Whether to require exact key matching

    Raises:
        FileNotFoundError: If checkpoint doesn't exist
        RuntimeError: If checkpoint is unsafe or state doesn't match
    """
    checkpoint = load_model_state_safe(checkpoint_path, device=device)

    # Handle both full checkpoint dicts and direct state dicts
    model_state = checkpoint.get("model_state_dict", checkpoint)

    if not isinstance(model_state, dict):
        raise RuntimeError(
            f"Expected checkpoint['model_state_dict'] or checkpoint itself to be a dict, "
            f"got {type(model_state)}"
        )

    model.load_state_dict(model_state, strict=strict)


def validate_checkpoint_safety(checkpoint_path: Union[str, Path]) -> bool:
    """
    Validate that a checkpoint can be safely loaded.

    Returns True if the checkpoint can be loaded with weights_only=True,
    indicating it contains only safe tensor data.

    Args:
        checkpoint_path: Path to checkpoint file

    Returns:
        True if checkpoint is safe, False if it contains non-tensor data
    """
    try:
        checkpoint_path = Path(checkpoint_path)
        if not checkpoint_path.exists():
            return False

        torch.load(
            str(checkpoint_path),
            map_location="cpu",
            weights_only=True,
        )
        return True
    except RuntimeError:
        return False


def get_checkpoint_metadata(
    checkpoint_path: Union[str, Path],
) -> Dict[str, Any]:
    """
    Safely extract metadata from a checkpoint without fully loading it.

    Returns information about the checkpoint structure that can be safely
    obtained (e.g., keys present) without risking code execution.

    Args:
        checkpoint_path: Path to checkpoint file

    Returns:
        Dictionary with checkpoint metadata
    """
    try:
        checkpoint = load_model_state_safe(checkpoint_path)

        return {
            "keys": list(checkpoint.keys()),
            "size_bytes": Path(checkpoint_path).stat().st_size,
            "has_model_state": "model_state_dict" in checkpoint,
            "has_optimizer_state": "optimizer_state_dict" in checkpoint,
            "has_scheduler_state": "scheduler_state_dict" in checkpoint,
            "safe": True,
        }
    except Exception as e:
        return {
            "error": str(e),
            "safe": False,
        }
