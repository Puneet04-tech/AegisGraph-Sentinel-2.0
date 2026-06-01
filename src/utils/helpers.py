"""
Helper utilities for AegisGraph Sentinel
"""
# Working on utility functions for the project

from logging import config

import yaml
import torch
import numpy as np
from pathlib import Path
from typing import Dict, Any, Optional
import logging
from datetime import datetime
import functools

class ConfigValidationError(Exception):
    """Raised when configuration validation fails"""
    pass


def validate_dataset_splits(config: dict) -> list:
    """
    Validate dataset split configuration.
    """
    errors = []

    data_config = config.get("data", {})

    train_split = data_config.get("train_split")
    val_split = data_config.get("val_split")
    test_split = data_config.get("test_split")

    if None not in (train_split, val_split, test_split):
        total = train_split + val_split + test_split

        if abs(total - 1.0) > 1e-6:
            errors.append(
                f"Dataset splits must sum to 1.0, got {total}"
            )

        for name, value in [
            ("train_split", train_split),
            ("val_split", val_split),
            ("test_split", test_split),
        ]:
            if value < 0 or value > 1:
                errors.append(
                    f"{name} must be between 0 and 1"
                )

    return errors

def load_config(config_path: str = "config/config.yaml") -> dict:
    """
    Load configuration from YAML file
    
    Args:
        config_path: Path to config file
    
    Returns:
        Configuration dictionary
    """
    path = Path(config_path)
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")
    
    with open(path, 'r') as f:
        config = yaml.safe_load(f)

    errors = validate_dataset_splits(config)

    if errors:
        raise ConfigValidationError(
            "Dataset split validation failed:\n"
            + "\n".join(f"  - {e}" for e in errors)
        )

    return config


def save_config(config: dict, config_path: str = "config/config.yaml"):
    """
    Save configuration to YAML file
    
    Args:
        config: Configuration dictionary
        config_path: Path to save config
    """
    path = Path(config_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(path, 'w') as f:
        yaml.dump(config, f, default_flow_style=False)


def setup_logger(name: str, log_file: Optional[str] = None, level: int = logging.INFO) -> logging.Logger:
    """
    Setup logger with console and optional file output
    
    Args:
        name: Logger name
        log_file: Optional log file path
        level: Logging level
    
    Returns:
        Configured logger
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)

    # Keep logger setup idempotent so repeated calls do not duplicate handlers.
    if not logger.handlers:
        console_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )

        console_handler = logging.StreamHandler()
        console_handler.setLevel(level)
        console_handler.setFormatter(console_formatter)
        logger.addHandler(console_handler)

        # File handler is configured once alongside the console handler.
        if log_file:
            file_handler = logging.FileHandler(log_file)
            file_handler.setLevel(level)
            file_handler.setFormatter(console_formatter)
            logger.addHandler(file_handler)
    
    return logger


def set_seed(seed: int = 42):
    """
    Set random seed for reproducibility
    
    Args:
        seed: Random seed
    """
    import random
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed(seed)
        torch.cuda.manual_seed_all(seed)
    torch.backends.cudnn.deterministic = True
    torch.backends.cudnn.benchmark = False


def count_parameters(model: torch.nn.Module) -> int:
    """
    Count trainable parameters in a PyTorch model
    
    Args:
        model: PyTorch model
    
    Returns:
        Number of trainable parameters
    """
    return sum(p.numel() for p in model.parameters() if p.requires_grad)


def get_device(device: Optional[str] = None) -> torch.device:
    """
    Get torch device (CUDA/MPS/CPU)
    
    Args:
        device: Device string ('cuda', 'mps', 'cpu', or None for auto)
    
    Returns:
        torch.device
    """
    requested_device = device.strip().lower() if isinstance(device, str) else device

    if requested_device == 'cpu':
        return torch.device('cpu')

    if requested_device == 'cuda' and torch.cuda.is_available():
        return torch.device('cuda')

    if (
        requested_device == 'mps'
        and hasattr(torch.backends, 'mps')
        and torch.backends.mps.is_available()
    ):
        return torch.device('mps')

    if requested_device in {'cuda', 'mps'}:
        logging.getLogger(__name__).warning(
            "Requested %s device is unavailable; falling back to best available device",
            requested_device,
        )
    elif requested_device is not None:
        raise ValueError(f"Unsupported torch device: {device!r}")

    if torch.cuda.is_available():
        return torch.device('cuda')
    if hasattr(torch.backends, 'mps') and torch.backends.mps.is_available():
        return torch.device('mps')
    return torch.device('cpu')


def format_time(seconds: float) -> str:
    """
    Format seconds into human-readable time string
    
    Args:
        seconds: Time in seconds
    
    Returns:
        Formatted time string
    """
    if seconds < 60:
        return f"{seconds:.2f}s"
    elif seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.2f}m"
    else:
        hours = seconds / 3600
        return f"{hours:.2f}h"


def pretty_print_dict(d: dict, indent: int = 0):
    """
    Pretty print dictionary
    
    Args:
        d: Dictionary to print
        indent: Indentation level
    """
    for key, value in d.items():
        print('  ' * indent + str(key) + ':', end=' ')
        if isinstance(value, dict):
            print()
            pretty_print_dict(value, indent + 1)
        else:
            print(value)


class Timer:
    """Context manager for timing code blocks"""
    
    def __init__(self, name: str = "Timer", verbose: bool = True):
        self.name = name
        self.verbose = verbose
        self.start_time = None
        self.elapsed = None
    
    def __enter__(self):
        self.start_time = datetime.now()
        return self
    
    def __exit__(self, *args):
        self.elapsed = (datetime.now() - self.start_time).total_seconds()
        if self.verbose:
            print(f"{self.name}: {format_time(self.elapsed)}")


def ensure_dir(path: str):
    """
    Ensure directory exists
    
    Args:
        path: Directory path
    """
    Path(path).mkdir(parents=True, exist_ok=True)


def get_timestamp() -> str:
    """
    Get current timestamp string
    
    Returns:
        ISO format timestamp
    """
    return datetime.utcnow().isoformat() + 'Z'


# ==============================================================================
# THRESHOLD LOADING AND VALIDATION
# ==============================================================================

class ThresholdValidationError(Exception):
    """Raised when threshold validation fails"""
    pass


def validate_thresholds(thresholds: dict) -> list:
    """
    Validate threshold values for correctness
    
    Args:
        thresholds: Threshold configuration dictionary
    
    Returns:
        List of validation errors (empty if valid)
    """
    errors = []
    
    # Risk scoring: validate ranges
    if 'risk_scoring' in thresholds:
        rs = thresholds['risk_scoring']
        if not (0 <= rs.get('block', 1) <= 1):
            errors.append("risk_scoring.block must be between 0 and 1")
        if not (0 <= rs.get('review', 1) <= 1):
            errors.append("risk_scoring.review must be between 0 and 1")
        if not (0 <= rs.get('allow', 1) <= 1):
            errors.append("risk_scoring.allow must be between 0 and 1")
        if rs.get('block', 0) <= rs.get('review', 0):
            errors.append("risk_scoring.block must be > review")
        if rs.get('review', 0) <= rs.get('allow', 0):
            errors.append("risk_scoring.review must be > allow")
    
    # Behavioral biometrics
    if 'behavioral_biometrics' in thresholds:
        bb = thresholds['behavioral_biometrics']
        if not (0 <= bb.get('stress_threshold', 1) <= 1):
            errors.append("behavioral_biometrics.stress_threshold must be 0-1")
        if bb.get('max_depth', 0) < 1:
            errors.append("behavioral_biometrics.max_depth must be >= 1")
    
    # Voice stress
    if 'voice_stress' in thresholds:
        vs = thresholds['voice_stress']
        if not (0 <= vs.get('stress_threshold', 100) <= 100):
            errors.append("voice_stress.stress_threshold must be 0-100")
        if not (0 <= vs.get('coercion_threshold', 100) <= 100):
            errors.append("voice_stress.coercion_threshold must be 0-100")
        if vs.get('coercion_threshold', 0) <= vs.get('stress_threshold', 0):
            errors.append("voice_stress.coercion_threshold must be > stress_threshold")
    
    # Predictive mule
    if 'predictive_mule' in thresholds:
        pm = thresholds['predictive_mule']
        if not (0 <= pm.get('risk_threshold', 100) <= 100):
            errors.append("predictive_mule.risk_threshold must be 0-100")
    
    # Honeypot escrow
    if 'honeypot_escrow' in thresholds:
        he = thresholds['honeypot_escrow']
        if not (0 <= he.get('activation_threshold', 1) <= 1):
            errors.append("honeypot_escrow.activation_threshold must be 0-1")
        if not (0 <= he.get('critical_indicator_threshold', 1) <= 1):
            errors.append("honeypot_escrow.critical_indicator_threshold must be 0-1")
        if he.get('escrow_duration_seconds', 0) < 60:
            errors.append("honeypot_escrow.escrow_duration_seconds must be >= 60")
    
    # Graph analysis
    if 'graph_analysis' in thresholds:
        ga = thresholds['graph_analysis']
        if ga.get('max_chain_depth', 0) < 2:
            errors.append("graph_analysis.max_chain_depth must be >= 2")
        if ga.get('lateral_movement_threshold_multiplier', 0) < 1:
            errors.append("graph_analysis.lateral_movement_threshold_multiplier must be >= 1")
    
    return errors


@functools.lru_cache(maxsize=1)
def load_thresholds(config_path: str = "config/thresholds.yaml", 
                    validate: bool = True) -> dict:
    """
    Load detection thresholds from YAML configuration file
    
    Args:
        config_path: Path to thresholds.yaml file
        validate: Whether to validate thresholds on load
    
    Returns:
        Threshold configuration dictionary
    
    Raises:
        FileNotFoundError: If config file not found
        ThresholdValidationError: If validation fails
    """
    path = Path(config_path)
    if not path.exists():
        raise FileNotFoundError(f"Thresholds config not found: {config_path}")
    
    with open(path, 'r') as f:
        thresholds = yaml.safe_load(f)
    
    if validate:
        errors = validate_thresholds(thresholds)
        if errors:
            raise ThresholdValidationError(
                f"Threshold validation failed:\n" + "\n".join(f"  - {e}" for e in errors)
            )
    
    logging.getLogger(__name__).info(f"Loaded thresholds from {config_path}")
    return thresholds


def get_threshold(path: str, default: Any = None) -> Any:
    """
    Get a specific threshold value using dot notation
    
    Args:
        path: Dot-separated path (e.g., 'risk_scoring.block')
        default: Default value if path not found
    
    Returns:
        Threshold value or default
    
    Example:
        >>> get_threshold('risk_scoring.block')
        0.90
        >>> get_threshold('voice_stress.stress_threshold', 50.0)
        50.0
    """
    thresholds = load_thresholds()
    keys = path.split('.')
    
    value = thresholds
    for key in keys:
        if isinstance(value, dict) and key in value:
            value = value[key]
        else:
            return default
    
    return value
