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
from functools import lru_cache
from pathlib import Path
from typing import Union

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

# Import from our new utils file
from models.utils import show_error, KeyStorage

# Constants moved from the main file
KEY_CHUNK_SIZE = 1000
AUDIT_LOG_FILENAME_TEMPLATE = "Audit-Trail-{issuer_id}.log"


class CryptoManager:
    """Manages all cryptographic operations and secure storage."""
    def __init__(self, service_name: str, app_data_dir: Path):
        self.service_name = service_name
        self.app_data_dir = app_data_dir
        self.log_dir = self.app_data_dir / "logs"
        self.log_dir.mkdir(parents=True, exist_ok=True)

    def _save_to_keystore(self, key_name: str, secret_value: str) -> bool:
        """Saves a secret to the OS keystore, chunking if necessary."""
        try:
            b64_secret = base64.b64encode(secret_value.encode("utf-8")).decode("utf-8")
            chunks = [b64_secret[i: i + KEY_CHUNK_SIZE] for i in range(0, len(b64_secret), KEY_CHUNK_SIZE)]
            metadata = {"chunks": len(chunks)}
            keyring.set_password(self.service_name, f"{key_name}_meta", json.dumps(metadata))
            for i, chunk in enumerate(chunks):
                keyring.set_password(self.service_name, f"{key_name}_chunk_{i}", chunk)
            return True
        except Exception as e:
            show_error("Keystore Error", f"Could not save secret to OS keystore: {e}")
            return False

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
            show_error("Keystore Error", f"Could not load secret from OS keystore: {e}")
            return None

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

    def save_private_key_to_keystore(self, issuer_id: str, private_key_pem: str) -> bool:
        return self._save_to_keystore(issuer_id, private_key_pem)

    def load_private_key_from_keystore(self, issuer_id: str) -> Union[str, None]:
        return self._load_from_keystore(issuer_id)

    def delete_private_key_from_keystore(self, issuer_id: str):
        self._delete_from_keystore(issuer_id)

    def save_ftp_password(self, issuer_id: str, password: str) -> bool:
        return self._save_to_keystore(f"{issuer_id}_ftp", password)

    def load_ftp_password(self, issuer_id: str) -> Union[str, None]:
        return self._load_from_keystore(f"{issuer_id}_ftp")

    def delete_ftp_password(self, issuer_id: str):
        self._delete_from_keystore(f"{issuer_id}_ftp")
        
    @lru_cache(maxsize=2) # Cache the last 2 keys, just in case
    def get_private_key(self, key_location: str, issuer_id: str, key_path: Path = None) -> Union[str, None]:
        """
        Loads the private key from its source (keystore or file) and caches the result.
        This method is the single point of entry for retrieving a private key.
        """
        logging.info(f"Loading private key for {issuer_id} from {key_location}...")
        if key_location == KeyStorage.KEYSTORE.value:
            return self.load_private_key_from_keystore(issuer_id)
        elif key_location == KeyStorage.FILE.value and key_path:
            try:
                return key_path.read_text(encoding="utf-8")
            except FileNotFoundError:
                show_error("Fatal Error", f"Private key file missing: {key_path}. The identity is unusable.")
                return None
        return None
    
    @staticmethod
    def sign_raw_bytes(private_key_pem: str, data_bytes: bytes) -> str:
        """Signs a raw byte payload with an Ed25519 private key and returns Base58."""
        priv_key = serialization.load_pem_private_key(private_key_pem.encode("utf-8"), password=None)
        signature = priv_key.sign(data_bytes)
        return base58.b58encode(signature).decode("utf-8")    
    
    @staticmethod
    def assemble_lky_file(image_bytes: bytes, payload_dict: dict, manifest_dict: dict) -> bytes:
        """Assembles the final .lky file from its constituent parts."""
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

    @staticmethod
    def generate_id_from_name(name: str) -> str:
        """Generates a deterministic 12-char ID from a name string."""
        return hashlib.sha256(name.lower().strip().encode("utf-8")).hexdigest()[:12]

    @staticmethod
    def calculate_file_hash(filepath_or_buffer) -> Union[str, None]:
        """
        Calculates the SHA-256 hash of a file path OR an in-memory buffer.
        Returns the first 32 chars of the hex digest.
        """
        hasher = hashlib.sha256()
        try:
            if isinstance(filepath_or_buffer, Path):
                if not filepath_or_buffer.exists(): 
                    logging.error(f"Hash calculation failed: Path does not exist at '{filepath_or_buffer}'")
                    return None
                with filepath_or_buffer.open("rb") as f:
                    while chunk := f.read(4096):
                        hasher.update(chunk)
            elif hasattr(filepath_or_buffer, 'read'):
                filepath_or_buffer.seek(0)
                while chunk := filepath_or_buffer.read(4096):
                    hasher.update(chunk)
                filepath_or_buffer.seek(0)
            else:
                show_error("Hash Error", f"Invalid input type for hash calculation: {type(filepath_or_buffer)}")
                return None
            return hasher.hexdigest()[:32]
        except Exception as e:
            show_error("File Hash Error", f"An error occurred during hash calculation: {e}")
            logging.error(f"Error in calculate_file_hash: {e}", exc_info=True)
            return None

    @staticmethod
    def sign_payload(private_key_pem: str, payload_dict: dict) -> str:
        """Signs a dictionary payload with a private key and returns a urlsafe base64 signature."""
        priv_key = serialization.load_pem_private_key(private_key_pem.encode("utf-8"), password=None)
        payload_json = json.dumps(payload_dict, separators=(",", ":")).encode("utf-8")
        signature = priv_key.sign(payload_json)
        return base58.b58encode(signature).decode("utf-8") 

    @staticmethod
    def verify_signature(public_key_pem: str, signature_b64: str, payload_dict: dict) -> bool:
        """Verifies a signature against a public key and payload using Ed25519 and Base64URL."""
        try:
            pub_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
            payload_json = json.dumps(payload_dict, separators=(",", ":")).encode("utf-8")
            signature = base64.urlsafe_b64decode(signature_b64)
            pub_key.verify(signature, payload_json)
            return True
        except (InvalidSignature, ValueError, Exception):
            return False

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
                    f.seek(-2, os.SEEK_END)
                    while f.read(1) != b"\n":
                        f.seek(-2, os.SEEK_CUR)
                except OSError: 
                    f.seek(0)
                last_line = f.readline().decode("utf-8").strip()
            if "::" not in last_line:
                logging.warning(f"Audit log '{log_path.name}' malformed. Last line invalid.")
                return None
            json_part, _ = last_line.split("::", 1)
            return hashlib.sha256(json_part.encode("utf-8")).hexdigest()
        except Exception as e:
            show_error(
                "Audit Log Warning",
                f"Could not read last audit trail entry. A new chain may start. Error: {e}",
            )
            return None

    def log_event(self, issuer_id: str, private_key_pem: str, event_type: str, details: dict):
        """Creates and appends a cryptographically signed entry to the audit log."""
        try:
            log_path = self.get_audit_log_path(issuer_id)
            previous_hash = self.get_last_log_hash(log_path)
            log_entry = {
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "issuer_id": issuer_id,
                "event_type": event_type,
                "details": details,
                "previous_hash": previous_hash,
            }
            signature_b64 = self.sign_payload(private_key_pem, log_entry)
            log_line = f"{json.dumps(log_entry, separators=(',', ':'))}::{signature_b64}\n"
            with log_path.open("a", encoding="utf-8") as f:
                f.write(log_line)
            logging.info(f"Logged event '{event_type}' to audit trail.")
            try:
                head_hash_path = log_path.with_suffix(".head")
                entry_json = json.dumps(log_entry, separators=(",", ":")).encode("utf-8")
                current_entry_hash = hashlib.sha256(entry_json).hexdigest()
                head_hash_path.write_text(current_entry_hash, encoding="utf-8")
            except Exception as e:
                show_error(
                    "Audit Log Critical Failure",
                    f"Could not update audit trail's head file. Log may be inconsistent. Error: {e}",
                )
        except Exception as e:
            show_error(
                "Audit Log Failure",
                f"Could not write log entry. Check permissions for '{log_path.name}'. Error: {e}",
            )
