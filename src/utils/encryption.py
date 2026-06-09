"""Model weight encryption utilities for protecting intellectual property.

This module provides secure encryption and decryption of model checkpoints
using AES-256-GCM with authenticated encryption. Encryption keys are managed
via environment variables to prevent credentials from being stored in code.
"""

import os
from pathlib import Path
from typing import Optional
import json
import io

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
import secrets
import torch


class ModelEncryption:
    """Encrypt and decrypt model checkpoints using AES-256-GCM.

    This class provides secure encryption of PyTorch model checkpoints to protect
    intellectual property and sensitive model weights from unauthorized access.

    The encryption scheme uses:
    - AES-256-GCM for authenticated encryption
    - PBKDF2 for key derivation from master secrets
    - Random nonces for each encryption operation
    - Authentication tags to detect tampering

    Environment Variables:
        MODEL_ENCRYPTION_KEY: Base64-encoded 32-byte AES-256 key (recommended)
        MODEL_ENCRYPTION_PASSWORD: Password for key derivation (less secure fallback)
    """

    KEY_SIZE = 32  # 256 bits for AES-256
    NONCE_SIZE = 12  # 96 bits recommended for GCM
    TAG_SIZE = 16  # 128 bits authentication tag
    ITERATIONS = 100000  # PBKDF2 iterations

    def __init__(self, encryption_key: Optional[bytes] = None):
        """Initialize encryption handler with a key.

        Args:
            encryption_key: 32-byte AES-256 key. If None, derives from environment.

        Raises:
            ValueError: If no encryption key is configured or key is invalid.
        """
        if encryption_key is not None:
            self._validate_key(encryption_key)
            self.key = encryption_key
        else:
            self.key = self._load_key_from_environment()

    @staticmethod
    def _validate_key(key: bytes) -> None:
        """Validate that the key is the correct size.

        Args:
            key: The encryption key to validate.

        Raises:
            ValueError: If key is not exactly 32 bytes.
        """
        if len(key) != ModelEncryption.KEY_SIZE:
            raise ValueError(
                f"Encryption key must be {ModelEncryption.KEY_SIZE} bytes, "
                f"got {len(key)} bytes"
            )

    @staticmethod
    def _load_key_from_environment() -> bytes:
        """Load and validate encryption key from environment.

        Tries two approaches:
        1. MODEL_ENCRYPTION_KEY: Base64-encoded 32-byte key (recommended)
        2. MODEL_ENCRYPTION_PASSWORD: Password for PBKDF2 derivation

        Returns:
            32-byte encryption key.

        Raises:
            ValueError: If no valid encryption configuration is found.
        """
        # Try direct key first (most secure - pre-generated, high entropy)
        direct_key = os.environ.get("MODEL_ENCRYPTION_KEY")
        if direct_key:
            try:
                import base64
                key = base64.b64decode(direct_key)
                ModelEncryption._validate_key(key)
                return key
            except Exception as e:
                raise ValueError(
                    f"MODEL_ENCRYPTION_KEY is invalid: {e}. "
                    f"Must be base64-encoded 32-byte key."
                )

        # Fallback: derive from password (less secure but better than plaintext)
        password = os.environ.get("MODEL_ENCRYPTION_PASSWORD")
        if password:
            salt = os.environ.get(
                "MODEL_ENCRYPTION_SALT",
                "aegisgraph-model-protection"
            ).encode()
            kdf = PBKDF2(
                algorithm=hashes.SHA256(),
                length=ModelEncryption.KEY_SIZE,
                salt=salt,
                iterations=ModelEncryption.ITERATIONS,
            )
            key = kdf.derive(password.encode())
            return key

        raise ValueError(
            "No encryption key configured. Set either:\n"
            "  - MODEL_ENCRYPTION_KEY=<base64-encoded-32-byte-key>\n"
            "  - MODEL_ENCRYPTION_PASSWORD=<password>"
        )

    def encrypt_checkpoint(self, checkpoint_dict: dict) -> bytes:
        """Encrypt a checkpoint dictionary to ciphertext.

        Args:
            checkpoint_dict: PyTorch checkpoint dict containing model weights.

        Returns:
            Encrypted checkpoint as bytes (nonce + ciphertext + tag).
        """
        # Serialize checkpoint to bytes
        buffer = io.BytesIO()
        torch.save(checkpoint_dict, buffer)
        plaintext = buffer.getvalue()

        # Generate random nonce and encrypt
        nonce = secrets.token_bytes(self.NONCE_SIZE)
        cipher = AESGCM(self.key)
        ciphertext = cipher.encrypt(nonce, plaintext, associated_data=None)

        # Prepend nonce to ciphertext (standard format)
        return nonce + ciphertext

    def decrypt_checkpoint(self, encrypted_data: bytes) -> dict:
        """Decrypt ciphertext to checkpoint dictionary.

        Args:
            encrypted_data: Encrypted checkpoint (nonce + ciphertext).

        Returns:
            Decrypted PyTorch checkpoint dict.

        Raises:
            cryptography.exceptions.InvalidTag: If authentication fails.
        """
        # Extract nonce and ciphertext
        nonce = encrypted_data[:self.NONCE_SIZE]
        ciphertext = encrypted_data[self.NONCE_SIZE:]

        # Decrypt and authenticate
        cipher = AESGCM(self.key)
        plaintext = cipher.decrypt(nonce, ciphertext, associated_data=None)

        # Deserialize checkpoint
        buffer = io.BytesIO(plaintext)
        checkpoint_dict = torch.load(buffer, map_location="cpu", weights_only=False)

        return checkpoint_dict


def get_encryption_handler() -> ModelEncryption:
    """Get a configured encryption handler.

    Returns:
        ModelEncryption instance with keys loaded from environment.
    """
    return ModelEncryption()
