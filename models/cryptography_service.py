# models/cryptography_service.py
# Copyright (C) 2025 Frédéric Levi Mazloum
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""
CryptographyService - Low-level cryptographic primitives.

Responsibility: Provide raw cryptographic operations (signing, verification,
hashing, file assembly) as a collection of static utility methods. This class
contains NO state and depends only on the cryptography library and standard
library modules.

All methods are static for stateless operation. This is a pure utility layer
that handles the "how" of cryptography, not the "what" of business logic.

No Dependencies:
- Does not depend on keystore, file I/O beyond hashing, or any managers
- Only depends on: cryptography, base58, json, hashlib, struct, logging
"""

import base58
import hashlib
import json
import logging
import struct
from pathlib import Path
from typing import Union
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from models.exceptions import HashCalculationError
from models.config import HASH_BUFFER_SIZE


class CryptographyService:
    """
    Static utility class for cryptographic operations.

    All methods are static. No state or configuration required.
    Focuses on the low-level cryptographic primitives used by higher layers.
    """

    # ========================================================================
    # HASHING OPERATIONS
    # ========================================================================

    @staticmethod
    def calculate_file_hash(filepath_or_buffer) -> Union[str, None]:
        """
        Calculate SHA-256 hash of a file path OR in-memory buffer.

        This is the canonical hash function used throughout the application
        for certificate integrity verification.

        Args:
            filepath_or_buffer: Either a Path object or file-like object

        Returns:
            Hex string (first 32 chars of SHA-256) or None on error

        Raises:
            HashCalculationError: If hashing fails
        """
        hasher = hashlib.sha256()
        try:
            if isinstance(filepath_or_buffer, Path):
                if not filepath_or_buffer.exists():
                    logging.error(f"Hash calculation failed: Path does not exist at '{filepath_or_buffer}'")
                    return None
                with filepath_or_buffer.open("rb") as f:
                    while chunk := f.read(HASH_BUFFER_SIZE):
                        hasher.update(chunk)
            elif hasattr(filepath_or_buffer, 'read'):
                filepath_or_buffer.seek(0)
                while chunk := filepath_or_buffer.read(HASH_BUFFER_SIZE):
                    hasher.update(chunk)
                filepath_or_buffer.seek(0)
            else:
                raise HashCalculationError(f"Invalid input type for hash calculation: {type(filepath_or_buffer)}")

            return hasher.hexdigest()[:32]

        except Exception as e:
            raise HashCalculationError(f"An error occurred during hash calculation: {e}") from e

    @staticmethod
    def _hash_string(data: str) -> str:
        """
        Hash a string using SHA-256.

        Internal helper for audit log chaining.

        Args:
            data: String to hash

        Returns:
            Hex digest of SHA-256
        """
        return hashlib.sha256(data.encode("utf-8")).hexdigest()

    # ========================================================================
    # SIGNING & VERIFICATION
    # ========================================================================

    @staticmethod
    def sign_raw_bytes(private_key_pem: str, data_bytes: bytes) -> str:
        """
        Sign raw bytes with Ed25519 private key.

        Returns Base58-encoded signature for compact representation
        suitable for embedding in QR codes and URLs.

        Args:
            private_key_pem: Private key in PEM format
            data_bytes: Raw bytes to sign

        Returns:
            Base58-encoded signature string
        """
        priv_key = serialization.load_pem_private_key(
            private_key_pem.encode("utf-8"),
            password=None
        )
        signature = priv_key.sign(data_bytes)
        return base58.b58encode(signature).decode("utf-8")

    @staticmethod
    def sign_payload(private_key_pem: str, payload_dict: dict) -> str:
        """
        Sign a dictionary payload with Ed25519 private key.

        JSON-encodes the payload, signs it, and returns Base58 signature.
        Used for certificate signing and audit log entries.

        Args:
            private_key_pem: Private key in PEM format
            payload_dict: Dictionary to sign

        Returns:
            Base58-encoded signature string
        """
        priv_key = serialization.load_pem_private_key(
            private_key_pem.encode("utf-8"),
            password=None
        )
        payload_json = json.dumps(payload_dict, separators=(",", ":")).encode("utf-8")
        signature = priv_key.sign(payload_json)
        return base58.b58encode(signature).decode("utf-8")

    @staticmethod
    def verify_signature(public_key_pem: str, signature_b58: str, payload_dict: dict) -> bool:
        """
        Verify a signature against a public key and payload.

        Uses Ed25519 for verification. Returns False for any verification error
        rather than raising exceptions to allow graceful failure handling.

        Args:
            public_key_pem: Public key in PEM format
            signature_b58: Base58-encoded signature
            payload_dict: Dictionary to verify against

        Returns:
            True if signature is valid, False otherwise
        """
        try:
            pub_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
            payload_json = json.dumps(payload_dict, separators=(",", ":")).encode("utf-8")
            signature = base58.b58decode(signature_b58.encode("utf-8"))

            if not isinstance(pub_key, ed25519.Ed25519PublicKey):
                raise TypeError("Public key is not a valid Ed25519 key for verification.")

            pub_key.verify(signature, payload_json)
            return True

        except (InvalidSignature, ValueError, TypeError, Exception):
            return False

    # ========================================================================
    # KEY OPERATIONS
    # ========================================================================

    @staticmethod
    def generate_id_from_name(name: str) -> str:
        """
        Generate a deterministic 12-character ID from a name.

        Uses SHA-256 hash of lowercase stripped name. Deterministic so the
        same name always generates the same ID.

        Args:
            name: Issuer name

        Returns:
            12-character hex string ID
        """
        return hashlib.sha256(name.lower().strip().encode("utf-8")).hexdigest()[:12]

    @staticmethod
    def derive_public_key(private_key_pem: str) -> Union[str, None]:
        """
        Derive the public key from a private key.

        Args:
            private_key_pem: Private key in PEM format

        Returns:
            Public key in PEM format or None on error
        """
        try:
            priv_key = serialization.load_pem_private_key(
                private_key_pem.encode("utf-8"),
                password=None
            )

            return priv_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode("utf-8")

        except Exception as e:
            logging.error(f"Failed to derive public key: {e}", exc_info=True)
            return None

    # ========================================================================
    # FILE ASSEMBLY
    # ========================================================================

    @staticmethod
    def assemble_lky_file(image_bytes: bytes, payload_dict: dict, manifest_dict: dict) -> bytes:
        """
        Assemble the final .lky file from constituent parts.

        The .lky format is a polyglot file: JPEG image + JSON payload + JSON manifest
        + 4-byte manifest length. The manifest length is stored at the end for easy
        parsing of the manifest from the back of the file.

        Args:
            image_bytes: JPEG image data (must start with FF D8)
            payload_dict: Document metadata dictionary
            manifest_dict: Signing manifest (signature, issuer ID, lengths)

        Returns:
            Complete .lky file bytes
        """
        is_jpeg = image_bytes.startswith(b'\xff\xd8')
        if not is_jpeg:
            logging.warning("POLYGLOT WARNING: Image data does not start with JPEG magic bytes.")

        try:
            payload_json_bytes = json.dumps(payload_dict, separators=(",", ":")).encode("utf-8")
            manifest_json_bytes = json.dumps(manifest_dict, separators=(",", ":")).encode("utf-8")
            manifest_length = len(manifest_json_bytes)
            manifest_length_bytes = struct.pack('>I', manifest_length)

            return image_bytes + payload_json_bytes + manifest_json_bytes + manifest_length_bytes

        except Exception as e:
            logging.error(f"Failed during LKY file assembly: {e}", exc_info=True)
            return None
