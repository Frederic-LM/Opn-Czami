# secure_storage.py
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
# along with this program.  If not, see
# <https://www.gnu.org/licenses/>.
#
# Responsibility: SecureStorage - Manage secure storage of cryptographic secrets.
# Handles OS keystore (with chunking for Windows compatibility) and file-based
# private key storage. Also provides audit log management with cryptographic chaining.
# Cryptographic operations (signing, hashing, verification) are delegated to
# CryptographyService for separation of concerns.

import base64
import base58
import cbor2
import datetime
import hashlib
import json
import keyring
import logging
import os
import struct
import zlib
from enum import Enum
from functools import lru_cache
from pathlib import Path
from typing import Union
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

# Corrected Imports
from models.exceptions import KeystoreError, FileAccessError, HashCalculationError, AuditLogError
from models.config import KEY_CHUNK_SIZE, AUDIT_LOG_FILENAME_TEMPLATE, HASH_BUFFER_SIZE
from models.cryptography_service import CryptographyService

class KeyStorage(Enum):
    """Enumeration for where a private key is stored."""
    KEYSTORE = "STORED_IN_KEYSTORE"
    FILE = "STORED_IN_FILE"

class SecureStorage:
    """Manages all cryptographic operations and secure storage."""

    def get_public_key_pem(self, key_location: str, issuer_id: str, key_path: Path = None) -> Union[str, None]:
        """
        Retrieves the private key and derives its corresponding public key 
        """
        try:
            private_key_pem = self.get_private_key(key_location, issuer_id, key_path)
            if not private_key_pem:
                return None
            
            priv_key = serialization.load_pem_private_key(private_key_pem.encode("utf-8"), password=None)
            
            return priv_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode("utf-8")

        except Exception as e:
            logging.error(f"Failed to derive public key for issuer {issuer_id}: {e}", exc_info=True)
            return None

    def __init__(self, service_name: str, app_data_dir: Path):
        self.service_name = service_name
        self.app_data_dir = app_data_dir
        self.log_dir = self.app_data_dir / "logs"
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self._keystore_available = None  # Lazy-loaded cache (None = not checked, True/False = result)

    def is_keystore_available(self) -> bool:
        """
        Check if OS keystore is available and functional.
        Uses lightweight ping test and caches result to avoid repeated checks.
        This is the standard method for checking keystore availability in the main workflow.
        """
        if self._keystore_available is not None:
            return self._keystore_available

        try:
            # Lightweight ping test - single small value without chunking
            test_key = "__opnczami_ping__"
            test_value = "ping"

            keyring.set_password(self.service_name, test_key, test_value)
            result = keyring.get_password(self.service_name, test_key)
            keyring.delete_password(self.service_name, test_key)

            self._keystore_available = (result == test_value)
            if self._keystore_available:
                logging.info("OS Keystore is available")
            else:
                logging.warning("OS Keystore test failed (read/write mismatch)")
            return self._keystore_available
        except KeyError:
            # Keyring doesn't have the entry - expected if first run
            logging.debug("OS Keystore test key not found (expected on first run)")
            self._keystore_available = False
            return False
        except (OSError, RuntimeError) as e:
            # Common keyring errors (permissions, unavailable backend)
            logging.warning(f"OS Keystore not available (falling back to file storage): {e}")
            self._keystore_available = False
            return False
        except Exception as e:
            # Unexpected error - log it and fall back safely
            logging.error(f"Unexpected keystore error (falling back to file storage): {e}", exc_info=True)
            self._keystore_available = False
            return False

    def _save_to_keystore(self, key_name: str, secret_value: str):
        """Saves a secret to the OS keystore, chunking if necessary."""
        try:
            b64_secret = base64.b64encode(secret_value.encode("utf-8")).decode("utf-8")
            chunks = [b64_secret[i: i + KEY_CHUNK_SIZE] for i in range(0, len(b64_secret), KEY_CHUNK_SIZE)]
            metadata = {"chunks": len(chunks)}
            keyring.set_password(self.service_name, f"{key_name}_meta", json.dumps(metadata))
            for i, chunk in enumerate(chunks):
                keyring.set_password(self.service_name, f"{key_name}_chunk_{i}", chunk)
        except Exception as e:
            raise KeystoreError(f"Could not save secret to OS keystore: {e}") from e

    def _load_from_keystore(self, key_name: str) -> Union[str, None]:
        """Loads a secret from the OS keystore, reassembling chunks."""
        try:
            metadata_str = keyring.get_password(self.service_name, f"{key_name}_meta")
            if not metadata_str:
                return None
            num_chunks = json.loads(metadata_str).get("chunks", 0)
            chunks = [keyring.get_password(self.service_name, f"{key_name}_chunk_{i}") for i in range(num_chunks)]
            if any(c is None for c in chunks):
                raise ValueError(f"Missing chunks for '{key_name}' in keystore.")
            return base64.b64decode("".join(chunks)).decode("utf-8")
        except Exception as e:
            raise KeystoreError(f"Could not load secret from OS keystore: {e}") from e

    def _delete_from_keystore(self, key_name: str):
        """Deletes a secret and its metadata from the OS keystore."""
        try:
            metadata_str = keyring.get_password(self.service_name, f"{key_name}_meta")
            if metadata_str:
                num_chunks = json.loads(metadata_str).get("chunks", 0)
                for i in range(num_chunks):
                    try:
                        keyring.delete_password(self.service_name, f"{key_name}_chunk_{i}")
                    except Exception:
                        pass # Ignore if a chunk is already gone
                keyring.delete_password(self.service_name, f"{key_name}_meta")
        except Exception as e:
            logging.warning(f"Could not fully delete '{key_name}' from keystore: {e}", exc_info=True)

    def save_private_key_to_keystore(self, issuer_id: str, private_key_pem: str):
        self._save_to_keystore(issuer_id, private_key_pem)

    def load_private_key_from_keystore(self, issuer_id: str) -> Union[str, None]:
        return self._load_from_keystore(issuer_id)

    def delete_private_key_from_keystore(self, issuer_id: str):
        self._delete_from_keystore(issuer_id)

    def save_ftp_password(self, issuer_id: str, password: str):
        self._save_to_keystore(f"{issuer_id}_ftp", password)

    def load_ftp_password(self, issuer_id: str) -> Union[str, None]:
        return self._load_from_keystore(f"{issuer_id}_ftp")

    def delete_ftp_password(self, issuer_id: str):
        self._delete_from_keystore(f"{issuer_id}_ftp")
        
    @lru_cache(maxsize=2)
    def get_private_key(self, key_location: str, issuer_id: str, key_path: Path = None) -> Union[str, None]:
        """
        Loads the private key from its source (keystore or file) and caches the result.
        """
        logging.info(f"Loading private key for {issuer_id} from {key_location}...")
        if key_location == KeyStorage.KEYSTORE.value:
            return self.load_private_key_from_keystore(issuer_id)
        elif key_location == KeyStorage.FILE.value and key_path:
            try:
                return key_path.read_text(encoding="utf-8")
            except FileNotFoundError as e:
                raise FileAccessError(f"Private key file missing: {key_path}. The identity is unusable.") from e
        return None
    
    @staticmethod
    def sign_raw_bytes(private_key_pem: str, data_bytes: bytes) -> str:
        """
        Signs a raw byte payload with an Ed25519 private key and returns Base58.

        DEPRECATED: Delegates to CryptographyService for actual implementation.
        Kept for backward compatibility.
        """
        return CryptographyService.sign_raw_bytes(private_key_pem, data_bytes)

    @staticmethod
    def assemble_lky_file(image_bytes: bytes, payload_dict: dict, manifest_dict: dict) -> bytes:
        """
        Assembles the final .lky file from its constituent parts.

        DEPRECATED: Delegates to CryptographyService for actual implementation.
        Kept for backward compatibility.
        """
        return CryptographyService.assemble_lky_file(image_bytes, payload_dict, manifest_dict)

    @staticmethod
    def generate_id_from_name(name: str) -> str:
        """
        Generates a deterministic 12-char ID from a name string.

        DEPRECATED: Delegates to CryptographyService for actual implementation.
        Kept for backward compatibility.
        """
        return CryptographyService.generate_id_from_name(name)

    @staticmethod
    def calculate_file_hash(filepath_or_buffer) -> Union[str, None]:
        """
        Calculates the SHA-256 hash of a file path OR an in-memory buffer.

        DEPRECATED: Delegates to CryptographyService for actual implementation.
        Kept for backward compatibility.
        """
        return CryptographyService.calculate_file_hash(filepath_or_buffer)

    @staticmethod
    def sign_payload(private_key_pem: str, payload_dict: dict) -> str:
        """
        Signs a dictionary payload with a private key and returns a Base58 signature.

        DEPRECATED: Delegates to CryptographyService for actual implementation.
        Kept for backward compatibility.
        """
        return CryptographyService.sign_payload(private_key_pem, payload_dict)

    @staticmethod
    def verify_signature(public_key_pem: str, signature_b58: str, payload_dict: dict) -> bool:
        """
        Verifies a signature against a public key and payload using Ed25519 and Base58.

        DEPRECATED: Delegates to CryptographyService for actual implementation.
        Kept for backward compatibility.
        """
        return CryptographyService.verify_signature(public_key_pem, signature_b58, payload_dict)

    def get_audit_log_path(self, issuer_id: str) -> Path:
        """Returns the path to the audit log for a given issuer."""
        return self.log_dir / AUDIT_LOG_FILENAME_TEMPLATE.format(issuer_id=issuer_id)

    def get_last_log_hash(self, log_path: Path) -> Union[str, None]:
        """
        Retrieves the hash of the last valid entry in the audit log for chaining.
        """
        if not log_path.exists() or log_path.stat().st_size == 0:
            return None
        
        try:
            with log_path.open("rb") as f:
                try:
                    # Seek to the end and back up 2 bytes (skip potential trailing newline)
                    f.seek(-2, os.SEEK_END)
                    # Back up until we find the newline of the previous line
                    while f.read(1) != b"\n":
                        f.seek(-2, os.SEEK_CUR)
                except (OSError, ValueError): 
                    # If file is too short or we hit start of file
                    f.seek(0)
                    
                last_line = f.readline().decode("utf-8").strip()

            if not last_line:
                return None

            if "::" not in last_line:
                logging.warning(f"Audit log '{log_path.name}' malformed. Last line invalid.")
                return None
            
            json_part, _ = last_line.split("::", 1)
            return hashlib.sha256(json_part.encode("utf-8")).hexdigest()

        except Exception as e:
            # FIX: Log the actual error for debugging
            logging.error(f"Failed to read last audit entry: {e}", exc_info=True)
            raise AuditLogError(f"Could not read last audit trail entry. Error: {e}") from e

    def log_event(self, issuer_id: str, private_key_pem: str, event_type: str, details: dict):
        """Creates and appends a cryptographically signed entry to the audit log."""
        log_path = self.get_audit_log_path(issuer_id)
        try:
            previous_hash = self.get_last_log_hash(log_path)

            log_entry = {
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "issuer_id": issuer_id,
                "event_type": event_type,
                "details": details,
                "previous_hash": previous_hash,
            }

            signature_b58 = self.sign_payload(private_key_pem, log_entry)
            log_line = f"{json.dumps(log_entry, separators=(',', ':'))}::{signature_b58}\n"

            # Write log entry and head file atomically to prevent corruption
            # if process crashes between writes
            head_hash_path = log_path.with_suffix(".head")
            entry_json = json.dumps(log_entry, separators=(",", ":")).encode("utf-8")
            current_entry_hash = hashlib.sha256(entry_json).hexdigest()

            # Write to temp files first
            log_tmp = log_path.with_suffix(".log.tmp")
            head_tmp = head_hash_path.with_suffix(".head.tmp")

            try:
                # Write log entry to temp file
                with log_tmp.open("w", encoding="utf-8") as f:
                    f.write(log_line)

                # Write head hash to temp file
                head_tmp.write_text(current_entry_hash, encoding="utf-8")

                # Atomic rename operations (both succeed or both fail)
                # Append to existing log (not replace)
                with log_path.open("a", encoding="utf-8") as f:
                    f.write(log_line)
                head_hash_path.write_text(current_entry_hash, encoding="utf-8")

                # Clean up temp files if they exist
                log_tmp.unlink(missing_ok=True)
                head_tmp.unlink(missing_ok=True)

                logging.info(f"Logged event '{event_type}' to audit trail.")
            except Exception as e:
                # Clean up temp files on error
                log_tmp.unlink(missing_ok=True)
                head_tmp.unlink(missing_ok=True)
                raise

        except AuditLogError as e:
            raise e
        except Exception as e:
            error_type = "update audit trail's head file" if 'head_hash_path' in locals() else "write log entry"
            raise AuditLogError(f"Could not {error_type}. Check permissions. Error: {e}") from e

     # Web3 secure storage manager for reworked Web3 module Filebase credentials
    def save_filebase_credentials(self, issuer_id: str, key: str, secret: str):
        """Saves Filebase credentials to the OS keystore."""
        self._save_to_keystore(f"{issuer_id}_filebase_key", key)
        self._save_to_keystore(f"{issuer_id}_filebase_secret", secret)

    def load_filebase_credentials(self, issuer_id: str) -> tuple[Union[str, None], Union[str, None]]:
        """Loads Filebase credentials from the OS keystore."""
        key = self._load_from_keystore(f"{issuer_id}_filebase_key")
        secret = self._load_from_keystore(f"{issuer_id}_filebase_secret")
        return key, secret

    def delete_filebase_credentials(self, issuer_id: str):
        """Deletes Filebase credentials from the OS keystore."""
        self._delete_from_keystore(f"{issuer_id}_filebase_key")
        self._delete_from_keystore(f"{issuer_id}_filebase_secret")