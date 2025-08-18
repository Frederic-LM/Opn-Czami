# Op'n-Czami
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


# --- Standard Library Imports ---
import base64
import base45
import cbor2
import keyring
import base58
import datetime
import ftplib
import hashlib
import io
import json
import logging
import struct
import os
import random
import shutil
import string
import subprocess
import sys
import tempfile
import threading
import webbrowser
from dataclasses import dataclass, field
from enum import Enum
from functools import lru_cache
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Union
import zlib
import posixpath 
from urllib.parse import urlparse

#import extern
import math

# --- Third-Party Imports ---
import keyring
import qrcode
import requests
import ttkbootstrap as ttk
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils, ed25519 # For Ed25519 support
from PIL import Image, ImageDraw, ImageFont, ImageTk
from ttkbootstrap.constants import *
from ttkbootstrap.scrolled import ScrolledText
from ttkbootstrap.tableview import Tableview
from tkinter import filedialog, messagebox

try:
    import pyzipper
    PYZIPPER_AVAILABLE = True
except ImportError:
    PYZIPPER_AVAILABLE = False

# --- Local Application Imports ---
from license_manager import LicenseManager, get_app_data_path

# --- Application Constants ---
APP_VERSION = "2.0.0"
APP_NAME = "OpnCzami"
KEYRING_SERVICE_NAME = "OperatorIssuerApp"
KEY_CHUNK_SIZE = 1000  # For splitting secrets for keyring storage
MAX_SUMMARY_CHARS = 400
MAX_LOGO_SIZE_BYTES = 256 * 1024  # 256 KB
MAX_LOGO_PIXELS = 74000  # Approx. 400x185
STANDARDIZED_LOGO_BASENAME = "my-legato-link-logo"

# --- Path Definitions ---
APP_DATA_DIR = get_app_data_path(APP_NAME)
USER_DOCS_DIR = Path.home() / "Documents"
APP_DOCS_DIR = USER_DOCS_DIR / APP_NAME
SCRIPT_DIR = Path(sys.argv[0] if getattr(sys, "frozen", False) else __file__).parent
ISSUER_DB_FILE = APP_DATA_DIR / "opn_czami_settings.json"
KEY_FILENAME_TEMPLATE = "abracadabra-{issuer_id}.key"
INFO_FILENAME = "my-legato-link.json"
AUDIT_LOG_FILENAME_TEMPLATE = "Audit-Trail-{issuer_id}.log"
LOG_DIR = APP_DATA_DIR / "logs"
APP_LOG_FILE = LOG_DIR / "opn-czami-app.log"

# --- Directory Creation ---
(APP_DOCS_DIR / "Legato_Keys").mkdir(parents=True, exist_ok=True)
LOG_DIR.mkdir(parents=True, exist_ok=True)

# --- Application-Specific Enums & Data Structures ---

# Document and Item type definitions
DOC_TYPES = {
"2": "Valuation Letter", "3": "Report", "4": "Other"
}
ITEM_TYPES = {
    "1": "Violin", "2": "Viola", "3": "Cello", "4": "Double Bass",
    "5": "Violin bow", "6": "Viola bow", "7": "Cello bow", "8": "Double Bass bow",
    "9": "Custom", "10": "Custom bow"
}
DOC_TYPES_REVERSE = {v: k for k, v in DOC_TYPES.items()}
ITEM_TYPES_REVERSE = {v: k for k, v in ITEM_TYPES.items()}


# --- Pro Features Handling ---
try:
    from pro_features import ProFeatures
    PRO_FEATURES_AVAILABLE = True
except ImportError:
    PRO_FEATURES_AVAILABLE = False
    class ProFeatures:
        """A mock class for when pro features are not installed."""
        def __init__(self, app_instance, app_data_path=None):
            logging.warning("Pro features module not found. Pro functionality is disabled.")
        def load_data_file(self): pass
        def process_batch_threaded(self): pass
        def load_and_verify_audit_log(self, *args):
            return [], False, "Pro features are not available.", DANGER

try:
    import pandas as pd
    PANDAS_AVAILABLE = True
except ImportError:
    PANDAS_AVAILABLE = False


# --- Application-Specific Enums & Data Structures ---
class KeyStorage(Enum):
    """Enumeration for where a private key is stored."""
    KEYSTORE = "STORED_IN_KEYSTORE"
    FILE = "STORED_IN_FILE"

class FTPMode(Enum):
    """Enumeration for FTP upload mode."""
    MANUAL = "Manual"
    AUTOMATIC = "Automatic"

class UploadButtonState(Enum):
    """Enumeration for the states of the main upload button."""
    INITIAL = ("🚀 Upload LKey", SECONDARY, "disabled")
    READY = ("🚀 Upload LKey", PRIMARY, "normal")
    UPLOADING = ("Uploading...", WARNING, "disabled")
    SUCCESS = ("Upload Successful!", SUCCESS, "normal")
    FAILURE = ("Upload Failed! (Retry)", DANGER, "normal")

class FormState(Enum):
    """Represents the state of a form (e.g., has it been changed)."""
    PRISTINE = 1
    DIRTY = 2
    TESTING = 3

@dataclass
class AppConfig:
    """Holds the application's user-configurable settings."""
    randomize_lkey_name: bool = False
    apply_watermark: bool = False
    apply_logo_watermark: bool = False
    watermark_text: str = "SIGNED"
    legato_files_save_path: str = ""
    ftp_host: str = ""
    ftp_user: str = ""
    ftp_path: str = ""
    ftp_pass_b64: str = ""  # Base64 encoded, used only when not in hardened mode
    ftp_auto_upload: bool = False
    hardened_security: bool = False
    enable_audit_trail: bool = False

    def __post_init__(self):
        """Set default save path if it is not provided."""
        if not self.legato_files_save_path:
            self.legato_files_save_path = str(APP_DOCS_DIR / "Legato_Keys")


# --- Helper Functions ---
def resource_path(relative_path: str) -> Path:
    """ Get absolute path to resource, works for dev and for PyInstaller. """
    try:
        base_path = Path(sys._MEIPASS)
    except AttributeError:
        base_path = Path(__file__).parent.resolve()
    return base_path / "assets" / relative_path

def show_error(title: str, message: str, log_error: bool = True):
    """Convenience function for showing a messagebox error and logging it."""
    if log_error:
        logging.error(f"{title}: {message}")
    messagebox.showerror(title, message)

def show_info(title: str, message: str):
    """Convenience function for showing a messagebox info dialog."""
    logging.info(f"{title}: {message}")
    messagebox.showinfo(title, message)


# --- Core Application Logic Classes ---
class SettingsManager:
    """Handles loading and saving of the main application settings file."""
    def __init__(self, db_path: Path):
        self.db_path = db_path

    def load_app_data(self) -> tuple[Union[str, None], Union[dict, None]]:
        """
        Loads the issuer data from the JSON file.
        Returns the first issuer ID found and their data dictionary.
        """
        if not self.db_path.exists():
            return None, None
        try:
            issuers = json.loads(self.db_path.read_text(encoding="utf-8"))
            if not issuers:
                return None, None
            # The app is designed to handle only one identity at a time.
            issuer_id, issuer_data = list(issuers.items())[0]
            return issuer_id, issuer_data
        except (json.JSONDecodeError, IndexError, Exception) as e:
            show_error("DB Load Error", f"Could not load or parse issuer database: {e}")
            return None, None

    def save_app_data(self, all_data: dict):
        """Saves the provided data dictionary to the JSON settings file."""
        try:
            with self.db_path.open("w", encoding="utf-8") as f:
                json.dump(all_data, f, indent=4)
            logging.info("Application data saved successfully.")
        except Exception as e:
            show_error("DB Save Error", f"Could not save issuer database: {e}")

    def clear_identity_file(self):
        """Wipes the issuer database file, effectively deleting the identity."""
        self.save_app_data({})

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
            # Check if the input is a file path object from the 'pathlib' library
            if isinstance(filepath_or_buffer, Path):
                if not filepath_or_buffer.exists(): 
                    logging.error(f"Hash calculation failed: Path does not exist at '{filepath_or_buffer}'")
                    return None
                with filepath_or_buffer.open("rb") as f:
                    while chunk := f.read(4096):
                        hasher.update(chunk)
            
            # Check if the input is an in-memory, file-like object (like io.BytesIO)
            elif hasattr(filepath_or_buffer, 'read'):
                filepath_or_buffer.seek(0) # IMPORTANT: Rewind the buffer to the beginning
                while chunk := filepath_or_buffer.read(4096):
                    hasher.update(chunk)
                filepath_or_buffer.seek(0) # Rewind again for good measure in case it's reused
            
            # If it's neither, we can't process it
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
        

class FTPManager:
    """Handles all FTP/FTPS communications for the application."""
    def test_connection(self, host: str, user: str, password: str) -> str:
        """Tests the FTP connection with the given credentials."""
        if not all([host, user, password]):
            return "Host, User, and Password cannot be empty."
        try:
            with ftplib.FTP_TLS(timeout=10) as ftp:
                ftp.connect(host)
                ftp.login(user, password)
                ftp.prot_p()
                ftp.voidcmd("NOOP")
            return "Success"
        except ftplib.all_errors as e:
            return f"FTP Test Failed: {e}"
        except Exception as e:
            return f"An unexpected error occurred: {e}"

    def upload_file(self, local_path: Path, remote_dir: str, remote_filename: str, ftp_settings: dict) -> str:
        """Uploads a single file, creating the remote directory structure if it doesn't exist."""
        host, user, password = ftp_settings.get("host"), ftp_settings.get("user"), ftp_settings.get("password")
        if not all([host, user, password, remote_dir]):
            return "FTP settings are incomplete."
        
        logging.info(f"FTP: Attempting to upload '{local_path.name}' to remote dir '{remote_dir}'")
        try:
            with ftplib.FTP_TLS(timeout=15) as ftp:
                ftp.connect(host)
                ftp.login(user, password)
                ftp.prot_p()
                path_parts = Path(remote_dir.strip("/\\")).parts
                for part in path_parts:
                    if not part or part in ('/', '\\'): continue
                    try:
                        ftp.cwd(part)
                    except ftplib.error_perm:
                        logging.info(f"FTP: Directory '{part}' not found, attempting to create.")
                        try:
                            ftp.mkd(part)
                            ftp.cwd(part)
                        except ftplib.error_perm as mkd_e:
                            err_msg = f"FTP Error: Failed to create or access directory '{part}'. Check permissions. Error: {mkd_e}"
                            logging.error(err_msg)
                            return err_msg
                
                logging.info(f"FTP: Now in target directory. Uploading '{remote_filename}'...")
                with local_path.open("rb") as f:
                    ftp.storbinary(f"STOR {remote_filename}", f)

            success_msg = f"Successfully uploaded {remote_filename} to {remote_dir}."
            logging.info(success_msg)
            return success_msg
        except ftplib.all_errors as e:
            err_msg = f"FTP Upload Error: {e}"
            logging.error(err_msg, exc_info=True)
            return err_msg
        except Exception as e:
            err_msg = f"An unexpected error occurred during upload: {e}"
            logging.error(err_msg, exc_info=True)
            return err_msg
      
class ImageProcessor:
    """Handles all image manipulation tasks like watermarking and QR code generation."""
    def __init__(self, checkmark_icon_path: Union[Path, None]):
        self.resample_method = Image.Resampling.LANCZOS if hasattr(Image, "Resampling") else Image.LANCZOS
        self.checkmark_icon_pil = None
        if checkmark_icon_path and checkmark_icon_path.exists():
            try:
                self.checkmark_icon_pil = Image.open(checkmark_icon_path).convert("RGBA")
            except Exception as e:
                logging.warning(f"Could not load checkmark icon '{checkmark_icon_path}'. Error: {e}")

    def apply_text_watermark(self, image_pil: Image.Image, text: str, apply: bool) -> Image.Image:
        """Applies a centered text watermark to an image if 'apply' is True."""
        if not apply:
            return image_pil
        
        image = image_pil.copy().convert("RGBA")
        text_layer = Image.new("RGBA", image.size, (255, 255, 255, 0))
        draw = ImageDraw.Draw(text_layer)
        
        font_size = int(image.width / 10)
        try:
            font = ImageFont.truetype("arial.ttf", font_size)
        except IOError:
            font = ImageFont.load_default()

        text_bbox = draw.textbbox((0, 0), text, font=font)
        pos = (
            (image.width - (text_bbox[2] - text_bbox[0])) // 2,
            (image.height - (text_bbox[3] - text_bbox[1])) // 2,
        )
        draw.text(pos, text, font=font, fill=(255, 255, 255, 128))
        return Image.alpha_composite(image, text_layer)

    def apply_logo_watermark(self, image_pil: Image.Image, logo_pil: Union[Image.Image, None], apply: bool) -> Image.Image:
        """Applies a logo watermark to the bottom-right corner if 'apply' is True."""
        if not apply or not logo_pil:
            return image_pil

        image = image_pil.copy().convert("RGBA")
        logo = logo_pil.copy().convert("RGBA")
        
        # Make logo semi-transparent
        try:
            alpha = logo.getchannel('A')
            alpha = alpha.point(lambda p: p * 0.5)
            logo.putalpha(alpha)
        except (IndexError, ValueError): # No alpha channel or not RGBA
            pass
        
        logo.thumbnail((int(image.width * 0.25), image.height), self.resample_method)
        margin = int(image.width * 0.02)
        pos = (image.width - logo.width - margin, image.height - logo.height - margin)
        
        image.paste(logo, pos, mask=logo)
        return image

    def overlay_checkmark(self, background_pil: Image.Image, scale_ratio: float = 0.8) -> Image.Image:
        """Overlays the checkmark icon in the center of an image."""
        if not background_pil or not self.checkmark_icon_pil:
            return background_pil
        
        background = background_pil.copy().convert("RGBA")
        overlay = self.checkmark_icon_pil
        
        target_width = int(background.width * scale_ratio)
        target_height = int(target_width * (overlay.height / overlay.width))
        overlay_resized = overlay.resize((target_width, target_height), self.resample_method)
        
        offset = (
            (background.width - overlay_resized.width) // 2,
            (background.height - overlay_resized.height) // 2,
        )
        background.paste(overlay_resized, offset, mask=overlay_resized)
        return background

    def generate_qr_with_logo(
        self,
        data: str,
        logo_pil: Union[Image.Image, None],
        box_size: int = 10,
        sizing_ratio: float = 0.28
    ) -> Image.Image:
        """Generates a QR code with an optional logo embedded in the center."""
        qr = qrcode.QRCode(
            error_correction=qrcode.constants.ERROR_CORRECT_H,
            box_size=box_size,
            border=4,
        )
        qr.add_data(data)
        qr.make(fit=True)
        qr_img = qr.make_image(fill_color="black", back_color="white").convert("RGBA")

        if logo_pil:
            logo_resized = logo_pil.copy().convert("RGBA")
            logo_max_size = (
                int(qr_img.width * sizing_ratio),
                int(qr_img.height * sizing_ratio),
            )
            logo_resized.thumbnail(logo_max_size, self.resample_method)
            
            pos = (
                (qr_img.width - logo_resized.width) // 2,
                (qr_img.height - logo_resized.height) // 2,
            )
            qr_img.paste(logo_resized, pos, mask=logo_resized)
        
        return qr_img.convert("RGB")

class IssuerApp:
   
    def __init__(self, root: ttk.Window):
        self.root = root
        self._configure_root_window()
        self._init_managers_and_config()
        self._init_state_variables()
        self._init_ui()
        self._load_and_display_initial_data()
        self._bind_events()

    def _configure_root_window(self):
        """Sets up the main application window properties."""
        self.root.title("Op’n-Czami - Legato-Key Certification Authority Dashboard")
        self.root.geometry("1260x970")
        self.root.minsize(1260, 980)
        self.root.resizable(False, True)
        self._set_window_icon()

    def _init_managers_and_config(self):
        """Initializes all manager classes and the application configuration."""
        self._configure_logging()
        self.settings_manager = SettingsManager(ISSUER_DB_FILE)
        self.crypto_manager = CryptoManager(KEYRING_SERVICE_NAME, APP_DATA_DIR)
        self.image_processor = ImageProcessor(resource_path("checkmark.png"))
        self.ftp_manager = FTPManager()
        self.license_manager = LicenseManager(SCRIPT_DIR, APP_DATA_DIR)
        self.logging = logging
        self.pro_handler = ProFeatures(self, APP_DATA_DIR)
        self.config = AppConfig()
        
    def _init_state_variables(self):
        """Initializes all Tkinter variables and internal state flags."""
        self.active_issuer_id = None
        self.active_issuer_data = None
        self.active_issuer_contact_info = {}
        self.all_issuer_data = {}
        self.system_is_verified = False
        self.is_generating = False
        self.selected_image_file_path = None
        self.prepared_upload_path = None
        self.last_signed_payload = None
        self.upload_button_state = UploadButtonState.INITIAL
        self.qr_image_pil = None
        self.issuer_qr_image_pil = None
        self.lkey_image_pil = None
        self.lkey_image_tk = None
        self.original_status_logo_pil = None
        self.logo_path = None
        # --- Variables for Enhanced Signing ---
        self.include_doc_num_var = ttk.BooleanVar(value=False)
        self.auto_gen_doc_num_var = ttk.BooleanVar(value=False)
        self.doc_num_var = ttk.StringVar()
        self.use_mask_var = ttk.BooleanVar(value=False)     
        self.mask_string_var = ttk.StringVar(value="####-MM/YY") 
        # --- END OF NEW VARIABLES ---
        self.url_path_var = ttk.StringVar(value="https://")
        self.image_base_url_var = ttk.StringVar()
        self.ftp_host_var = ttk.StringVar()
        self.ftp_user_var = ttk.StringVar()
        self.ftp_pass_var = ttk.StringVar()
        self.ftp_path_var = ttk.StringVar()
        self.show_pass_var = ttk.BooleanVar(value=False)
        self.watermark_text_var = ttk.StringVar()
        self.legato_files_save_path_var = ttk.StringVar()
        self.hardened_security_var = ttk.BooleanVar()
        self.enable_audit_trail_var = ttk.BooleanVar()
        self.ftp_auto_upload_var = ttk.BooleanVar()
        self.apply_watermark_var = ttk.BooleanVar()
        self.apply_logo_watermark_var = ttk.BooleanVar()
        self.randomize_lkey_name_var = ttk.BooleanVar()
        self.ftp_form_state = FormState.PRISTINE

    def _init_ui(self):
        """Creates all the UI components of the application."""
        self.create_status_panel()
        self.create_main_ui()

    def _load_and_display_initial_data(self):
        """Loads issuer data from files and populates the UI accordingly."""
        self.populate_ui_from_config() # Set defaults first
        self.load_issuer_data()
        
        if self.active_issuer_id:
            self.notebook.select(1) # Go to signing tab if identity exists
            self.root.after(100, self.check_system_status)
        
        self.update_ui_state()

    def _bind_events(self):
        """Binds all application-level events."""
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.root.bind("<Configure>", self._apply_dpi_scaling)

        ftp_vars_to_trace = [self.ftp_host_var, self.ftp_user_var, self.ftp_pass_var, self.ftp_path_var]
        for var in ftp_vars_to_trace:
            var.trace_add("write", self.on_ftp_settings_change)
            var.trace_add("write", self._update_ftp_dependent_widgets_state)

    def _configure_logging(self):
        """Sets up a rotating file logger for the application."""
        log_formatter = logging.Formatter("%(asctime)s - %(levelname)s - [%(funcName)s] - %(message)s")
        log_handler = RotatingFileHandler(APP_LOG_FILE, maxBytes=5*1024*1024, backupCount=5, encoding='utf-8')
        log_handler.setFormatter(log_formatter)
        logger = logging.getLogger()
        logger.handlers.clear()
        logger.addHandler(log_handler)
        logger.setLevel(logging.INFO)
        logging.info("--- Application Logging Started ---")

    def on_close(self):
        """Handles application shutdown procedures."""
        temp_dir = APP_DATA_DIR / "temp_upload"
        if temp_dir.exists() and temp_dir.is_dir():
            try:
                # Securely delete all files within the temp directory
                for item in temp_dir.iterdir():
                    if item.is_file():
                        item.unlink()
                # Now that it's empty, remove the directory itself
                shutil.rmtree(temp_dir)
                logging.info(f"Securely cleared and removed temp directory: {temp_dir}")
            except OSError as e:
                logging.warning(f"Could not fully remove temp directory on exit: {e}")
        self.root.destroy()

    def _apply_dpi_scaling(self, event=None):
        """Dynamically adjusts font sizes based on screen DPI with more nuance."""
        try:
            last_scaling_factor = getattr(self, "_last_scaling_factor", 0)
            DESIGN_DPI = 96.0
            current_dpi = self.root.winfo_fpixels("1i")
            scaling_factor = current_dpi / DESIGN_DPI

            if abs(scaling_factor - last_scaling_factor) < 0.05:
                return  

            self._last_scaling_factor = scaling_factor
            logging.info(f"DPI change detected. Applying new scaling factor: {scaling_factor:.2f}")

            # Use different base sizes for different elements
            base_size = 6  # Adjusted for better default
            text_size = 6  # For text widgets
            tab_size = 5   # For notebook tabs

            scaled_default_size = max(8, int(base_size * scaling_factor))
            scaled_text_size = max(8, int(text_size * scaling_factor))
            scaled_tab_size = max(8, int(tab_size * scaling_factor))

            style = ttk.Style.get_instance()
            default_family = ttk.font.nametofont("TkDefaultFont").cget("family")

            # Configure specific widget styles
            style.configure("TLabel", font=(default_family, scaled_default_size))
            style.configure("TButton", font=(default_family, scaled_default_size))
            style.configure("TCheckbutton", font=(default_family, scaled_default_size))
            style.configure("TRadiobutton", font=(default_family, scaled_default_size))
            style.configure("TEntry", font=(default_family, scaled_text_size))
            style.configure("TCombobox", font=(default_family, scaled_text_size))
            style.configure("TLabelframe.Label", font=(default_family, scaled_default_size, "bold"))
            style.configure("TNotebook.Tab", font=(default_family, scaled_tab_size))
            
            # Configure the Text widget specifically
            self.root.option_add("*Text*Font", (default_family, scaled_text_size))

        except Exception as e:
            logging.error(f"Failed to apply DPI scaling: {e}", exc_info=True)

    def _set_window_icon(self):
        """Sets the application icon based on the operating system."""
        try:
            ico_path = resource_path("icon.ico")
            png_path = resource_path("icon.png")
            if sys.platform == "win32" and ico_path.exists():
                self.root.iconbitmap(ico_path)
            elif png_path.exists():
                photo = ttk.PhotoImage(file=png_path)
                self.root.iconphoto(True, photo)
        except Exception as e:
            logging.error(f"Could not set window icon: {e}", exc_info=True)



    def _on_custom_item_focus(self, *args):
        """When the user clicks into the custom item box, deselect radio buttons."""
        self.primary_item_type_var.set("") # Deselects all radio buttons
        self._on_item_selection_change()

    def _on_item_selection_change(self, *args):
        """Updates the item selection based on the primary instrument and bow modifier."""
        primary_selection = self.primary_item_type_var.get()
        is_bow = self.bow_modifier_var.get()
        
        # When a primary instrument is selected, the bow is always an option
        self.bow_toggle_button.config(state="normal")
        
        final_code = ""
        description = ""

        if primary_selection == "01": # Violin
            final_code = "05" if is_bow else "01"
            description = "Violin bow" if is_bow else "Violin"
        elif primary_selection == "02": # Viola
            final_code = "06" if is_bow else "02"
            description = "Viola bow" if is_bow else "Viola"
        elif primary_selection == "03": # Cello
            final_code = "04" if is_bow else "03"
            description = "Cello bow" if is_bow else "Cello"
        elif primary_selection == "07": # Custom Text
            final_code = "07" # Always use the "custom" code
            custom_text = self.custom_item_type_var.get().strip() or "[Custom Item]"
            description = f"{custom_text} bow" if is_bow else custom_text
        
        self.item_type_var.set(final_code)
        self.selected_item_label_var.set(f"Selected: {description}")
        self._update_bow_button_style()
    
    def _show_upgrade_prompt(self, feature_name: str):
        """Displays a standard dialog for Pro-only features."""
        show_info("Professional Feature", f"'{feature_name}' is a Professional feature.\n\nPlease purchase a license to unlock this functionality.")

    # --- Pro Feature Handlers ---
    def _handle_load_data_file(self):
        if self.license_manager.is_feature_enabled("batch"):
            self.pro_handler.load_data_file()
        else:
            self._show_upgrade_prompt("Batch Processing")

    def _handle_process_batch(self):
        if self.license_manager.is_feature_enabled("batch"):
            self.pro_handler.process_batch_threaded()
        else:
            self._show_upgrade_prompt("Batch Processing")

    def _handle_refresh_audit(self):
        if not self.active_issuer_id:
            if hasattr(self, "audit_status_label"):
                self.audit_status_label.config(text="Load an identity to view the audit trail.")
            return

        if self.license_manager.is_feature_enabled("audit"):
            self.audit_status_label.config(text="Verifying Audit Trail...", bootstyle=INFO)
            self.root.update_idletasks()
            row_data, is_valid, msg, style = self.pro_handler.load_and_verify_audit_log(self.active_issuer_id, self.active_issuer_data["priv_key_pem"])
            self.audit_tree.delete_rows()
            if row_data:
                self.audit_tree.insert_rows("end", row_data)
                self.audit_tree.load_table_data()
            self.audit_status_label.config(text=msg, bootstyle=style)
        else:
            self.audit_status_label.config(text="Audit Trail is a Professional Feature.", bootstyle=INFO)
            self._show_upgrade_prompt("Audit Trail")
    def _apply_number_mask(self) -> str:
        """Applies the user-defined mask to the next auto-increment number."""
        mask = self.mask_string_var.get()
        if not mask:
            return ""
        next_num = self.last_auto_inc_num + 1
        now = datetime.datetime.now()

        # Replace date components
        mask = mask.replace("YYYY", now.strftime("%Y"))
        mask = mask.replace("YY", now.strftime("%y"))
        mask = mask.replace("MM", now.strftime("%m"))
        mask = mask.replace("DD", now.strftime("%d"))

        # Replace number component
        if "#" in mask:
            num_placeholders = mask.count("#")
            num_str = f"{next_num:0{num_placeholders}d}"
            mask = mask.replace("#" * num_placeholders, num_str)
        
        return mask

    def _on_auto_toggle(self, *args):
        """Single handler for the 'Auto' checkbox which is now mask-aware."""
        self._update_doc_num_entry_state()        
             
    # --- Data Persistence and Identity Management ---
    def _sync_config_from_ui(self):
        self.config.ftp_host = self.ftp_host_var.get().strip()
        self.config.ftp_user = self.ftp_user_var.get().strip()
        self.config.ftp_path = self.ftp_path_var.get().strip()
        self.config.watermark_text = self.watermark_text_var.get().strip()
        self.config.legato_files_save_path = self.legato_files_save_path_var.get()
        if not self.hardened_security_var.get():
            password = self.ftp_pass_var.get().encode("utf-8")
            self.config.ftp_pass_b64 = base64.b64encode(password).decode("utf-8")
        self.config.hardened_security = self.hardened_security_var.get()
        self.config.enable_audit_trail = self.enable_audit_trail_var.get()
        self.config.ftp_auto_upload = self.ftp_auto_upload_var.get()
        self.config.apply_watermark = self.apply_watermark_var.get()
        self.config.apply_logo_watermark = self.apply_logo_watermark_var.get()
        self.config.randomize_lkey_name = self.randomize_lkey_name_var.get()

    def _gather_settings_data_for_db(self) -> dict:
        ftp_settings = {
            "host": self.config.ftp_host, "user": self.config.ftp_user, "path": self.config.ftp_path,
            "mode": FTPMode.AUTOMATIC.value if self.config.ftp_auto_upload else FTPMode.MANUAL.value,
        }
        if not self.config.hardened_security:
            ftp_settings["pass_b64"] = self.config.ftp_pass_b64
        return {
            "randomize_lkey_name": self.config.randomize_lkey_name,
            "apply_watermark": self.config.apply_watermark, "apply_logo_watermark": self.config.apply_logo_watermark,
            "watermark_text": self.config.watermark_text, "legato_files_save_path": self.config.legato_files_save_path,
            "ftp_settings": ftp_settings,
            "enable_audit_trail": self.config.enable_audit_trail,
            "auto_increment_last_num": self.last_auto_inc_num,
            "doc_num_mask": self.mask_string_var.get()
        }

    def save_settings(self):
        if not self.active_issuer_id: return
        self._sync_config_from_ui()
        if self.active_issuer_id in self.all_issuer_data:
            self.all_issuer_data[self.active_issuer_id]["settings"] = self._gather_settings_data_for_db()
            self.settings_manager.save_app_data(self.all_issuer_data)
        logging.info("Settings saved.")

    def save_issuer_identity(self):
        if not self.active_issuer_id: return
        is_enabling_security = self.hardened_security_var.get()
        action_text = "ENABLING" if is_enabling_security else "DISABLING"
        warning_text = ("This will move your Private Key and FTP Password into the secure OS Keychain." if is_enabling_security
            else "WARNING: This will move your secrets OUT of the secure OS Keychain and into local files. This is less secure.")
        if not messagebox.askokcancel(f"Confirm {action_text} Hardened Security", f"{warning_text}\n\nThis is a critical security operation. Proceed?",
            icon=INFO if is_enabling_security else WARNING):
            self.pro_security_checkbox.cget("variable").set(not is_enabling_security)
            return
        priv_key_pem = self.active_issuer_data.get("priv_key_pem")
        key_filepath = APP_DATA_DIR / KEY_FILENAME_TEMPLATE.format(issuer_id=self.active_issuer_id)
        try:
            if is_enabling_security:
                if not self.crypto_manager.save_private_key_to_keystore(self.active_issuer_id, priv_key_pem): raise ValueError("Failed to save private key to OS Keystore.")
                if not self.crypto_manager.save_ftp_password(self.active_issuer_id, self.ftp_pass_var.get()): raise ValueError("Failed to save FTP password to OS Keystore.")
                self.all_issuer_data[self.active_issuer_id]["priv_key_pem"] = KeyStorage.KEYSTORE.value
                if key_filepath.exists(): key_filepath.unlink()
            else:
                if ftp_password := self.crypto_manager.load_ftp_password(self.active_issuer_id):
                    self.ftp_pass_var.set(ftp_password)
                self.crypto_manager.delete_private_key_from_keystore(self.active_issuer_id)
                self.crypto_manager.delete_ftp_password(self.active_issuer_id)
                key_filepath.write_text(priv_key_pem, encoding="utf-8")
                self.all_issuer_data[self.active_issuer_id]["priv_key_pem"] = KeyStorage.FILE.value
            self.config.hardened_security = is_enabling_security
            self.save_settings()
            show_info("Success", "Security settings have been updated successfully.")
        except Exception as e:
            show_error("Security Operation Failed", f"Could not update security settings: {e}\n\nReverting the change.")
            self.pro_security_checkbox.cget("variable").set(not is_enabling_security)
            
    def delete_identity(self):
        if not messagebox.askyesno("CONFIRM DELETION", "Are you absolutely sure?\nThis is PERMANENT.", icon=WARNING): return
        audit_log_path = self.crypto_manager.get_audit_log_path(self.active_issuer_id)
        if audit_log_path.exists() and messagebox.askyesno("Delete Audit Trail?", f"Permanently delete '{audit_log_path.name}'?", icon=WARNING):
            try:
                audit_log_path.unlink()
                logging.info(f"Deleted audit trail: {audit_log_path.name}")
            except OSError as e:
                show_error("Deletion Error", f"Could not delete the audit trail log file: {e}")
        self.crypto_manager.delete_private_key_from_keystore(self.active_issuer_id)
        self.crypto_manager.delete_ftp_password(self.active_issuer_id)
        key_filepath = APP_DATA_DIR / KEY_FILENAME_TEMPLATE.format(issuer_id=self.active_issuer_id)
        if key_filepath.exists(): key_filepath.unlink()
        self.settings_manager.clear_identity_file()
        self.active_issuer_id = None
        self.active_issuer_data = None
        self.last_signed_payload = None
        self.issuer_qr_image_pil = None
        self.active_issuer_contact_info = {}
        self.all_issuer_data = {}
        self.clear_lkey_image_display()
        self.message_text.delete("1.0", "end")
        self.qr_display_label.config(image="")
        self.notebook.select(0)
        self.config = AppConfig()
        self.update_ui_state()
        logging.info("Active identity and all associated files have been deleted.")

    def _update_mask_sample_label(self, *args):
        """Updates the sample text below the mask entry in settings."""
        if hasattr(self, "mask_sample_label"):
            try:
                sample = self._apply_number_mask()
                self.mask_sample_label.config(text=f"Sample: {sample}")
            except Exception:
                self.mask_sample_label.config(text="Sample: Invalid Mask")
        
    def _toggle_doc_num_frame_visibility(self, *args):
        """Toggle visibility of document number frame."""
        if self.include_doc_num_var.get():
            self.doc_num_frame.grid(row=0, column=1, sticky="e", padx=(10, 5))
        else:
            self.doc_num_frame.grid_remove()

    def _update_doc_num_entry_state(self, *args):
        """Controls the document number entry field based on auto-gen/mask selection."""
        is_masking_licensed = self.license_manager.is_feature_enabled("masked_ids")
        mask_is_defined = self.mask_string_var.get().strip()

        if self.auto_gen_doc_num_var.get():
            self.doc_num_entry.config(state="readonly")
            if is_masking_licensed and mask_is_defined:
                self.doc_num_var.set(self._apply_number_mask())
            else:
                self.doc_num_var.set(self._get_next_auto_doc_num_str())
        else:
            self.doc_num_entry.config(state="normal")
            self.doc_num_var.set("")

    def _validate_doc_num_len(self, *args):
        """Enforces a 10-character limit on the document number field."""
        if not self.use_mask_var.get() and not self.auto_gen_doc_num_var.get():
            val = self.doc_num_var.get()
            if len(val) > 10:
                self.doc_num_var.set(val[:10])

    def _get_next_auto_doc_num_str(self) -> str:
        """Generates the next document number string for display."""
        next_num = self.last_auto_inc_num + 1
        return f"{datetime.datetime.now().year}-{next_num:04d}"

    def _apply_number_mask(self) -> str:
        """Applies the user-defined mask to the next auto-increment number."""
        mask = self.mask_string_var.get()
        if not mask: return ""
        next_num = self.last_auto_inc_num + 1
        now = datetime.datetime.now()
        mask = mask.replace("YYYY", now.strftime("%Y")).replace("YY", now.strftime("%y"))
        mask = mask.replace("MM", now.strftime("%m")).replace("DD", now.strftime("%d"))
        if "#" in mask:
            num_placeholders = mask.count("#")
            num_str = f"{next_num:0{num_placeholders}d}"
            mask = mask.replace("#" * num_placeholders, num_str)
        return mask

    def _update_mask_sample_label(self, *args):
        """Updates the sample text below the mask entry in settings."""
        if hasattr(self, "mask_sample_label"):
            try:
                sample = self._apply_number_mask()
                self.mask_sample_label.config(text=f"Sample: {sample}")
            except Exception:
                self.mask_sample_label.config(text="Sample: Invalid Mask")

    def _on_auto_toggle(self, *args):
        """Single handler for the 'Auto' checkbox which is now mask-aware."""
        self._update_doc_num_entry_state()

  

    def create_and_save_identity(self):
        name = self.name_entry.get().strip()
        url_path = self.url_path_var.get().strip()
        image_base_url = self.image_base_url_var.get().strip()
        errors = []
        if not name: errors.append("• Issuer Name is required.")
        if not url_path or url_path == "https://": errors.append("• Public ID URL is required.")
        if not image_base_url or image_base_url == "https://": errors.append("• Image Base URL is required.")
        if errors:
            show_error("Input Error", "Please correct the following errors:\n\n" + "\n".join(errors))
            return
        if not self.logo_path and not messagebox.askyesno("Confirm: No Logo", "You have not selected a logo. This decision is PERMANENT.\n\nAre you sure you want to continue?", icon=WARNING):
            return
        issuer_id = self.crypto_manager.generate_id_from_name(name)
        if not messagebox.askokcancel("Confirm Identity Creation", f"This will create the identity '{name}' with the permanent ID:\n\n{issuer_id}\n\nProceed?"):
            return
        try:
            priv_key = ed25519.Ed25519PrivateKey.generate()
            priv_key_pem = priv_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption()).decode("utf-8")
            pub_key_pem = priv_key.public_key().public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode("utf-8")
            url_path = url_path.removesuffix("/") + "/"
            image_base_url = image_base_url.removesuffix("/") + "/"
            try:
                parsed_url = urlparse(url_path)
                hostname = parsed_url.hostname
                if hostname:
                    base_domain = hostname[4:] if hostname.lower().startswith("www.") else hostname
                    final_ftp_guess = f"ftp.{base_domain}"

                    self.config.ftp_host = final_ftp_guess
                    self.ftp_host_var.set(final_ftp_guess)
                    logging.info(f"Intelligently guessed FTP host '{final_ftp_guess}' from URL '{url_path}'.")
                else:
                    logging.warning("Could not extract a valid hostname from the provided URL to guess FTP host.")
            except Exception as e:
                logging.error(f"Error parsing URL to guess FTP host: {e}", exc_info=True)
                self.config.ftp_host = ""
                self.ftp_host_var.set("")
            json_content = {"publicKeyPem": pub_key_pem, "imageBaseUrl": image_base_url, "issuerName": name}
            if self.logo_path:
                json_content["logoUrl"] = url_path + self.logo_path.name
            if contact_info := {k: v for k, v in {"email": self.email_entry.get().strip(), "phone": self.phone_entry.get().strip(), "address": self.address_entry.get().strip()}.items() if v}:
                json_content["contactInfo"] = contact_info
            (APP_DATA_DIR / INFO_FILENAME).write_text(json.dumps(json_content, indent=2), encoding="utf-8")
            (APP_DATA_DIR / KEY_FILENAME_TEMPLATE.format(issuer_id=issuer_id)).write_text(priv_key_pem, encoding="utf-8")
            new_issuer_data_for_db = {
                "name": name, "infoUrl": url_path + INFO_FILENAME, "imageBaseUrl": image_base_url,
                "priv_key_pem": KeyStorage.FILE.value, "settings": {},
            }
            self.all_issuer_data[issuer_id] = new_issuer_data_for_db
            self.active_issuer_id = issuer_id
            self.active_issuer_data = {**new_issuer_data_for_db, "priv_key_pem": priv_key_pem}
            self.config = AppConfig()
            self.config.hardened_security = False
            self.save_settings()
            key_file_name = KEY_FILENAME_TEMPLATE.format(issuer_id=issuer_id)
            show_info("Success & Next Steps",
                "IDENTITY CREATED SUCCESSFULLY!\n\n"
                "Your critical identity files have been generated. "
                "These files CANNOT be recovered if lost.\n\n"
                "**You MUST create a secure, offline backup of:**\n"
                f"  •  `{key_file_name}` (Your Private Key)\n"
                f"  •  `{ISSUER_DB_FILE.name}` (Your Settings)\n\n"
                "---------------------------------------------------\n"
                "**NEXT STEP: SERVER SETUP**\n\n"
                "You will now be taken to the 'Settings' tab to finalize your server configuration."
            )
            self.update_ui_state()
            self.root.after(100, self.check_system_status)
            self.notebook.select(2)
        except Exception as e:
            show_error("Identity Creation Error", f"Failed to create identity: {e}")

    # --- Document Signing ---
    def _generate_document_qr_threaded_worker(self, image_path: Path, details: dict):
        """
        Worker function for the 'Fingerprint, Sign & Save' process, run in a background thread.
        Handles UI updates by scheduling them back to the main thread.
        """
        try:
            self.root.after(0, self.upload_progress_bar.grid)
            self.root.after(0, self.upload_progress_bar.start)

            is_successful_signing, upload_performed_and_successful, result_message = self._sign_single_document(image_path, details)

            if is_successful_signing:
                self.root.after(0, lambda: self._update_ui_after_signing_success(upload_performed_and_successful))
            else:
                self.root.after(0, lambda msg=result_message: show_error("Signing Failed", msg))
                self.root.after(0, lambda: setattr(self, 'upload_button_state', UploadButtonState.FAILURE))
                self.root.after(0, self.update_upload_button_display)
                self.root.after(0, self.upload_progress_bar.stop)
                self.root.after(0, self.upload_progress_bar.grid_remove)

        except Exception as e:
            logging.error(f"Error in document generation worker: {e}", exc_info=True)
            self.root.after(0, lambda err=e: show_error("Process Error", f"An unexpected error occurred during document processing: {err}"))
            self.root.after(0, self.upload_progress_bar.stop)
            self.root.after(0, self.upload_progress_bar.grid_remove)
        finally:
            self.root.after(0, lambda: self.generate_qr_button.config(state=NORMAL))
            self.is_generating = False
        

        
    def _sign_single_document(self, image_path: Path, details: dict) -> tuple[bool, bool, str]:
        try:
            # --- (All the data prep and LKY file creation logic remains the same) ---
            apply_text_watermark = self.config.apply_watermark and self.license_manager.is_feature_enabled("watermark")
            apply_logo_watermark = self.config.apply_logo_watermark and self.license_manager.is_feature_enabled("watermark")
            source_image = Image.open(image_path)
            watermarked_img = self.image_processor.apply_text_watermark(source_image, self.config.watermark_text, apply_text_watermark)
            final_lkey_image = self.image_processor.apply_logo_watermark(watermarked_img, self.original_status_logo_pil, apply_logo_watermark).convert("RGB")
            temp_dir = APP_DATA_DIR / "temp_upload"
            temp_dir.mkdir(exist_ok=True, parents=True)
            sanitized_base = self.sanitize_filename(image_path.stem)
            suffix = f"-{''.join(random.choices(string.ascii_lowercase + string.digits, k=4))}" if self.config.randomize_lkey_name else ""
            upload_filename_stem = f"{sanitized_base}{suffix}"
            final_lkey_filename = f"{upload_filename_stem}.lky"
            image_buffer = io.BytesIO()
            final_lkey_image.save(image_buffer, format="JPEG", quality=95)
            image_bytes = image_buffer.getvalue()
            lky_payload_dict_verbose = {
                "imgId": final_lkey_filename,
                "message": details.get("m"), "docDate": datetime.date.today().isoformat(),
                "docNumber": details.get("n"),
            }
            lky_payload_dict_verbose = {k: v for k, v in lky_payload_dict_verbose.items() if v is not None}
            lky_payload_bytes = json.dumps(lky_payload_dict_verbose, separators=(",", ":")).encode("utf-8")
            data_to_sign_lky = image_bytes + lky_payload_bytes
            priv_key = serialization.load_pem_private_key(self.active_issuer_data["priv_key_pem"].encode("utf-8"), password=None)
            lky_signature = priv_key.sign(data_to_sign_lky)
            lky_signature_b64url = base64.urlsafe_b64encode(lky_signature).rstrip(b'=').decode('utf-8')
            manifest_dict = {
                "signature": lky_signature_b64url,
                "signatureEncoding": "base64url", # Self-describing format is a best practice
                "issuerId": self.active_issuer_id,
                "imageLength": len(image_bytes),
                "payloadLength": len(lky_payload_bytes),
                "imageMimeType": "image/jpeg"
            }
            lky_file_bytes = self.crypto_manager.assemble_lky_file(image_bytes, lky_payload_dict_verbose, manifest_dict)
            if not lky_file_bytes: return False, False, "Failed to assemble .lky file."
            prepared_upload_path = temp_dir / final_lkey_filename
            prepared_upload_path.write_bytes(lky_file_bytes)
            full_file_hash_hex = self.crypto_manager.calculate_file_hash(prepared_upload_path)
            if not full_file_hash_hex: return False, False, "Could not calculate final file hash."
            hash_bytes = bytes.fromhex(full_file_hash_hex)
            qr_payload_dict_compact = {"i": upload_filename_stem, "h": hash_bytes, **details}
            qr_payload_dict_compact = {k: v for k, v in qr_payload_dict_compact.items() if v is not None}
            qr_payload_bytes = cbor2.dumps(qr_payload_dict_compact)
            compressor = zlib.compressobj(level=9, wbits=-15)
            qr_compressed_bytes = compressor.compress(qr_payload_bytes) + compressor.flush()
            qr_signature = priv_key.sign(qr_compressed_bytes)

            binary_to_encode = qr_compressed_bytes + qr_signature
            payload_b45 = base45.b45encode(binary_to_encode).decode('ascii')
            issuer_id_upper = self.active_issuer_id.upper()
            final_qr_data_for_lib = f"{issuer_id_upper}:{payload_b45}"

            if self.config.enable_audit_trail and self.license_manager.is_feature_enabled("audit"):
                log_details = {"filename": final_lkey_filename, "details": lky_payload_dict_verbose, "file_hash": full_file_hash_hex}
                self.crypto_manager.log_event(self.active_issuer_id, self.active_issuer_data["priv_key_pem"], "SIGN_UNIFIED_SUCCESS", log_details)
            doc_logo_path = resource_path("legatokey.png")
            document_logo_pil = Image.open(doc_logo_path) if doc_logo_path.exists() else None
            qr_image_pil = self.image_processor.generate_qr_with_logo(final_qr_data_for_lib, document_logo_pil, sizing_ratio=0.39)
            now = datetime.datetime.now()
            local_save_dir = Path(self.config.legato_files_save_path) / f"{now.year}" / f"{now.month:02d}"
            local_save_dir.mkdir(parents=True, exist_ok=True)
            qr_save_path = local_save_dir / f"{upload_filename_stem}-QR.png"
            qr_image_pil.save(qr_save_path)
            shutil.copy(prepared_upload_path, local_save_dir / final_lkey_filename)
            self.qr_image_pil = qr_image_pil
            self.prepared_upload_path = prepared_upload_path
            self.last_signed_payload = f"{final_lkey_filename}|{details.get('m','')}|{full_file_hash_hex}"
            is_auto_upload_successful = False
            if self.config.ftp_auto_upload:
                is_auto_upload_successful, upload_result_msg = self._upload_single_file(prepared_upload_path)
                if not is_auto_upload_successful: return False, False, f"Auto-upload failed: {upload_result_msg}"
            return True, is_auto_upload_successful, "LKey signed and processed successfully."
        except Exception as e:
            logging.error(f"Error during document signing: {e}", exc_info=True)
            return False, False, f"Signing failed due to an unexpected error: {e}"

        
    def generate_document_qr(self):
        if self.is_generating or not self.selected_image_file_path: return
        self.is_generating = True
        self.generate_qr_button.config(state=DISABLED)
        
        self.upload_button_state = UploadButtonState.INITIAL
        self.update_upload_button_display()
        self._hide_qr_action_buttons()

        details = { "m": self.message_text.get("1.0", "end-1c").strip() }
        
        if self.include_doc_num_var.get():
            doc_num = ""
            is_masking_licensed = self.license_manager.is_feature_enabled("masked_ids")
            mask_is_defined = self.mask_string_var.get().strip()

            if self.auto_gen_doc_num_var.get():
                if is_masking_licensed and mask_is_defined:
                    doc_num = self._apply_number_mask()
                else:
                    doc_num = self._get_next_auto_doc_num_str()
                self.last_auto_inc_num += 1
                self.save_settings()
            else:
                doc_num = self.doc_num_var.get().strip()

            if doc_num:
                details["n"] = doc_num

        threading.Thread(target=self._generate_document_qr_threaded_worker, 
                         args=(self.selected_image_file_path, details), 
                         daemon=True).start()

    # --- Data Loading and UI Configuration ---
    def load_issuer_data(self):
        self.active_issuer_id, data = self.settings_manager.load_app_data()
        if not self.active_issuer_id or not data:
            self.active_issuer_data = None
            logging.info("No active issuer found.")
            return
        logging.info(f"Loading data for issuer ID: {self.active_issuer_id}")
        try:
            self.all_issuer_data = json.loads(ISSUER_DB_FILE.read_text(encoding="utf-8")) if ISSUER_DB_FILE.exists() else {}
        except (IOError, json.JSONDecodeError):
            self.all_issuer_data = {}
            logging.warning("Could not load or parse issuer DB file. Starting with empty data.")
            
        self.active_issuer_data = self.all_issuer_data.get(self.active_issuer_id, data).copy()
        key_loc = self.active_issuer_data.get("priv_key_pem")
        
        # Determine hardened security state BEFORE populating the config object
        self.config.hardened_security = (key_loc == KeyStorage.KEYSTORE.value)
        
        key_path = APP_DATA_DIR / KEY_FILENAME_TEMPLATE.format(issuer_id=self.active_issuer_id)
        key = self.crypto_manager.get_private_key(key_loc, self.active_issuer_id, key_path)

        if not key:
            self.active_issuer_data = None
            return
        
        self.active_issuer_data["priv_key_pem"] = key
        
        # This is the correct, working sequence
        self.populate_config_from_issuer_data()
        self.populate_ui_from_config()

    def populate_config_from_issuer_data(self):
        s = self.active_issuer_data.get("settings", {})
        ftp_settings = s.get("ftp_settings", {})
        
        # Re-create the AppConfig object from the loaded file, as per the working version
        self.config = AppConfig(
            randomize_lkey_name=s.get("randomize_lkey_name", False),
            apply_watermark=s.get("apply_watermark", False),
            apply_logo_watermark=s.get("apply_logo_watermark", False),
            watermark_text=s.get("watermark_text", "SIGNED"),
            legato_files_save_path=s.get("legato_files_save_path", str(APP_DOCS_DIR / "Legato_Keys")),
            ftp_host=ftp_settings.get("host", ""),
            ftp_user=ftp_settings.get("user", ""),
            ftp_path=ftp_settings.get("path", ""),
            ftp_pass_b64=ftp_settings.get("pass_b64", ""),
            ftp_auto_upload=(ftp_settings.get("mode") == FTPMode.AUTOMATIC.value),
            hardened_security=self.config.hardened_security,
            enable_audit_trail=s.get("enable_audit_trail", False)
        )
        
        # Also load the non-AppConfig state from the settings dictionary 's'
        self.last_auto_inc_num = s.get("auto_increment_last_num", 0)
        self.mask_string_var.set(s.get("doc_num_mask", "####-MM/YY"))
        
        logging.info("Configuration object populated from issuer data.")

    def populate_ui_from_config(self):
        """Syncs the UI variables with the values in the self.config object."""
        self.ftp_host_var.set(self.config.ftp_host)
        self.ftp_user_var.set(self.config.ftp_user)
        self.ftp_path_var.set(self.config.ftp_path)
        
        password = ""
        if self.config.hardened_security and self.active_issuer_id:
             password = self.crypto_manager.load_ftp_password(self.active_issuer_id) or ""
        else:
            try:
                if self.config.ftp_pass_b64:
                    password = base64.b64decode(self.config.ftp_pass_b64).decode("utf-8")
            except Exception: pass
        self.ftp_pass_var.set(password)

        self.watermark_text_var.set(self.config.watermark_text)
        self.legato_files_save_path_var.set(self.config.legato_files_save_path)
        self.hardened_security_var.set(self.config.hardened_security)
        self.enable_audit_trail_var.set(self.config.enable_audit_trail)
        self.ftp_auto_upload_var.set(self.config.ftp_auto_upload)
        self.apply_watermark_var.set(self.config.apply_watermark)
        self.apply_logo_watermark_var.set(self.config.apply_logo_watermark)
        self.randomize_lkey_name_var.set(self.config.randomize_lkey_name)
        
        # Crucially, update the UI previews for the newly loaded mask and number state
        if hasattr(self, "mask_sample_label"):
            self._update_mask_sample_label()
        if hasattr(self, "doc_num_entry"):
            self._update_doc_num_entry_state()
        
        self.ftp_form_state = FormState.PRISTINE
        if hasattr(self, "save_and_upload_button"):
            self.save_and_upload_button.config(state=DISABLED)
        logging.info("UI elements synced from configuration object.")

    # --- UI Helpers & Event Handlers ---
    def handle_create_backup(self):
        if not self.active_issuer_id:
            show_info("No Identity", "You must have an active identity to create a backup.")
            return

        password = self.backup_pass_var.get()
        if not password:
            show_error("Password Required", "You must enter a password to encrypt the backup file.")
            return
        if len(password) < 10 and not messagebox.askyesno("Weak Password", "Password is short. Are you sure?"):
            return

        key_filepath = APP_DATA_DIR / KEY_FILENAME_TEMPLATE.format(issuer_id=self.active_issuer_id)
        settings_file_path = ISSUER_DB_FILE

        is_hardened = self.config.hardened_security
        original_priv_key_pem = self.active_issuer_data.get("priv_key_pem")

        if is_hardened:
            if not messagebox.askokcancel("Hardened Security Active",
                                    "Hardened Security is ON.\n\nTo create a complete backup, the private key will be temporarily moved from the OS Keychain to a file. It will be moved back and the file securely deleted when the backup is finished.\n\nProceed?"):
                return

        # A robust try/finally block to ensure security is always restored
        try:
            # --- Temporarily Disable Hardened Security if needed ---
            if is_hardened:
                logging.info("Temporarily disabling hardened security for backup.")
                key_from_keystore = self.crypto_manager.load_private_key_from_keystore(self.active_issuer_id)
                if not key_from_keystore:
                    show_error("Keystore Error", "Could not retrieve private key from OS Keystore. Backup aborted.")
                    return
                key_filepath.write_text(key_from_keystore, encoding="utf-8")
            
            if not key_filepath.exists() or not settings_file_path.exists():
                show_error("Files Missing", "Could not find the necessary key or settings file to back up.")
                return

            # --- Perform the Backup ---
            default_filename = f"opn-czami-backup-{self.active_issuer_id}-{datetime.date.today()}.zip"
            save_path_str = filedialog.asksaveasfilename(
                title="Save Secure Backup As...",
                defaultextension=".zip",
                initialfile=default_filename,
                filetypes=[("ZIP Archives", "*.zip")]
            )
            if not save_path_str:
                # User cancelled save dialog
                return

            save_path = Path(save_path_str)
            try:
                with pyzipper.AESZipFile(save_path, "w", compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES) as zf:
                    zf.setpassword(password.encode("utf-8"))
                    zf.write(key_filepath, arcname=key_filepath.name)
                    zf.write(settings_file_path, arcname=settings_file_path.name)
                self.backup_pass_var.set("")
                show_info("Backup Successful", f"Secure backup created successfully at:\n\n{save_path}")
                webbrowser.open(f"file:///{save_path.parent}")
            except Exception as e:
                show_error("Backup Failed", f"An error occurred while creating the backup file:\n\n{e}")

        finally:
            # --- ALWAYS restore hardened security if it was on ---
            if is_hardened:
                logging.info("Restoring hardened security after backup.")
                if self.crypto_manager.save_private_key_to_keystore(self.active_issuer_id, original_priv_key_pem):
                    if key_filepath.exists():
                        key_filepath.unlink()
                        logging.info(f"Deleted temporary key file: {key_filepath.name}")
                    logging.info("Hardened security has been successfully re-enabled.")
                else:
                    show_error("CRITICAL SECURITY FAILURE",
                            "Failed to move the private key back to the OS Keychain. The key is currently stored insecurely on disk. Please re-enable Hardened Security manually from the Backup & Security tab immediately.")

    def browse_for_legato_files_save_path(self):
        if new_path := filedialog.askdirectory(title="Select Folder for Local File Saving"):
            self.legato_files_save_path_var.set(new_path)
            self.save_settings()

    def on_auto_upload_toggle(self):
        self.config.ftp_auto_upload = self.ftp_auto_upload_var.get()
        self.save_settings()
        self.update_upload_button_display()
        self.update_auto_upload_indicator()

    def _update_ftp_dependent_widgets_state(self, *args):
        if not hasattr(self, "auto_upload_check"): return
        settings_are_valid = all([self.ftp_host_var.get(), self.ftp_user_var.get(), self.ftp_pass_var.get(), self.ftp_path_var.get()])
        self.auto_upload_check.config(state=NORMAL if settings_are_valid else DISABLED)
        if not settings_are_valid and self.ftp_auto_upload_var.get():
            self.ftp_auto_upload_var.set(False)
            self.on_auto_upload_toggle()

    def toggle_watermark_state(self):
        is_licensed = self.license_manager.is_feature_enabled("watermark")
        state = NORMAL if self.apply_watermark_var.get() and is_licensed else DISABLED
        if hasattr(self, "watermark_entry"): self.watermark_entry.config(state=state)

    def update_auto_upload_indicator(self):
        if hasattr(self, "auto_upload_indicator_label"):
            text, style = ("✓ Auto-Upload: ON", SUCCESS) if self.config.ftp_auto_upload else ("✗ Auto-Upload: OFF", SECONDARY)
            self.auto_upload_indicator_label.config(text=text, bootstyle=style)

    def update_manage_frame_display(self):
        if not self.active_issuer_data: return
        self.id_label.config(text=self.active_issuer_id)
        self.name_label.config(text=self.active_issuer_data.get("name", "N/A"))
        self.url_label.config(text=self.active_issuer_data.get("infoUrl", "N/A"))
        contact = self.active_issuer_contact_info
        self.email_label_val.config(text=contact.get("email", "N/A"))
        self.phone_label_val.config(text=contact.get("phone", "N/A"))
        self.address_label_val.config(text=contact.get("address", "N/A"))

    def update_qr_display(self, pil_image: Image.Image):
        display_qr = pil_image.copy()
        display_qr.thumbnail((300, 300), self.image_processor.resample_method)
        qr_tk = ImageTk.PhotoImage(display_qr)
        self.qr_display_label.config(image=qr_tk)
        self.qr_display_label.image = qr_tk

    def update_lkey_display(self, pil_image: Image.Image):
        display_lkey = pil_image.copy()
        display_lkey.thumbnail((600, 480), self.image_processor.resample_method)
        self.lkey_image_tk = ImageTk.PhotoImage(display_lkey.convert("RGB"))
        self.lkey_image_display_label.config(image=self.lkey_image_tk)
        self.lkey_image_display_label.image = self.lkey_image_tk

    def clear_lkey_image_display(self):
        if hasattr(self, 'lkey_image_display_label'):
            self.lkey_image_display_label.config(image="")
            self.lkey_image_pil = None
            self.lkey_image_tk = None

    def update_issuer_qr_display(self):
        if not self.active_issuer_id:
            if hasattr(self, "issuer_qr_display_label"):
                self.issuer_qr_display_label.config(image="")
            self.issuer_qr_image_pil = None
            return
        
        payload = {
            "qr_type": "issuer_info_v1",
            "id": self.active_issuer_id,
            "issuername": self.active_issuer_data["name"],   
            "infoUrl": self.active_issuer_data["infoUrl"]
             }
            
        # 1. Convert to JSON string (compact format)
        json_string = json.dumps(payload, separators=(',', ':'))
    
        # 2. Compress with deflate
        compressed_data = zlib.compress(json_string.encode('utf-8'), level=9)
    
        # 3. Encode as base45
        qr_data = base45.b45encode(compressed_data).decode('ascii')
    
        # Generate QR with the compact data
        self.issuer_qr_image_pil = self.image_processor.generate_qr_with_logo(
            qr_data,
            self.original_status_logo_pil,
            sizing_ratio=0.85
        )
    
        display_img = self.issuer_qr_image_pil.copy()
        display_img.thumbnail((250, 250), self.image_processor.resample_method)
        img_tk = ImageTk.PhotoImage(display_img)
        self.issuer_qr_display_label.config(image=img_tk)
        self.issuer_qr_display_label.image = img_tk
      
        
    def browse_and_set_image_file(self):
        if not self.reset_upload_button_state(): return
        if not (filepath_str := filedialog.askopenfilename(title="Select image file", filetypes=[("Image Files", "*.jpg *.jpeg *.png *.bmp"), ("All files", "*.*")])):
            self.clear_lkey_image_display()
            self.doc_id_helper_label.config(text="File selection cancelled.")
            self.generate_qr_button.config(state=DISABLED)
            self.selected_image_file_path = None
            return
        self.selected_image_file_path = Path(filepath_str)
        self.doc_id_helper_label.config(text=f"Selected: {self.selected_image_file_path.name}")
        try:
            self.lkey_image_pil = Image.open(self.selected_image_file_path)
            self.update_lkey_display(self.lkey_image_pil)
            self.generate_qr_button.config(state=NORMAL)
        except Exception as e:
            show_error("Image Load Error", f"Could not load image: {e}")
            self.clear_lkey_image_display()

    
    def get_full_remote_path(self) -> Union[str, None]:
        """
        Safely constructs the full remote path for FTP uploads, preventing path traversal.
        This version uses posixpath to correctly handle URL-like paths regardless of the host OS.
        """
        if not self.active_issuer_data: return None
        try:
            # Get the configured root directory for FTP.
            ftp_root = self.config.ftp_path.strip()
            if not ftp_root:
                show_error("Configuration Error", "FTP Web Root Path is not set in Settings.")
                return None

            # Get the path component from the Image Base URL.
            image_base_url_path = urlparse(self.active_issuer_data.get("imageBaseUrl", "")).path

            # Safely join the paths using posixpath, which always uses forward slashes.
            # lstrip removes any leading slashes from the second part to ensure a clean join.
            full_path = posixpath.join(ftp_root, image_base_url_path.lstrip('/\\'))

            # Normalize the path to resolve components like '..' (e.g., /a/b/../c -> /a/c)
            # This is crucial for the security check.
            normalized_path = posixpath.normpath(full_path)
            normalized_root = posixpath.normpath(ftp_root)

            # Security Check: Ensure the final, normalized path is still inside the intended root directory.
            # This prevents traversal attacks (e.g., `../../etc/passwd`).
            if not normalized_path.startswith(normalized_root):
                err_msg = "Path traversal detected: The Image Base URL attempts to go outside the FTP Web Root."
                logging.error(err_msg)
                show_error("Security Error", err_msg)
                return None
            
            # Return the safe, clean, POSIX-style path for the FTP server.
            return normalized_path

        except Exception as e:
            logging.error(f"Error calculating full remote path: {e}", exc_info=True)
            show_error("Configuration Error", "The Image Base URL or FTP Path is invalid.")
            return None
    

    def _upload_single_file(self, local_path: Path):
        remote_dir = self.get_full_remote_path()
        if not remote_dir:
            return False, "Could not determine FTP remote path. Check settings and error logs."
            
        ftp_settings = self._get_active_ftp_settings()
        if not ftp_settings:
            return False, "Could not get FTP settings."

        result = self.ftp_manager.upload_file(local_path, remote_dir, local_path.name, ftp_settings)
        
        is_success = "successful" in result.lower()
        if self.config.enable_audit_trail and self.license_manager.is_feature_enabled("audit"):
            event_type = "UPLOAD_SUCCESS" if is_success else "UPLOAD_FAILURE"
            self.crypto_manager.log_event(self.active_issuer_id, self.active_issuer_data["priv_key_pem"], event_type, {"filename": local_path.name, "result_message": result})
        
        return is_success, result

    def _get_active_ftp_settings(self) -> Union[dict, None]:
        if not self.active_issuer_id: return None
        password = ""
        if self.config.hardened_security:
            password = self.crypto_manager.load_ftp_password(self.active_issuer_id)
            if password is None:
                show_error("FTP Error", "Hardened Security is ON, but FTP password not found in OS storage.")
                return None
        else:
            try: password = base64.b64decode(self.config.ftp_pass_b64).decode("utf-8")
            except Exception: pass
        return {"host": self.config.ftp_host, "user": self.config.ftp_user, "password": password}

    def handle_save_and_upload_threaded(self):
        self._sync_config_from_ui()
        self.save_and_upload_button.config(state=DISABLED, text="Working...")
        threading.Thread(target=self._save_and_upload_worker, daemon=True).start()

    def _save_and_upload_worker(self):
        ftp_settings = self._get_active_ftp_settings()
        if not ftp_settings:
            self.root.after(0, self.save_and_upload_button.config, {'state': NORMAL, 'text': "✔️ Save Settings & Upload Public Files"})
            return
        test_result = self.ftp_manager.test_connection(ftp_settings['host'], ftp_settings['user'], ftp_settings['password'])
        if test_result != "Success":
            self.root.after(0, lambda: show_error("Connection Failed", f"Could not connect to FTP. Please check settings.\n\nError: {test_result}"))
            self.root.after(0, self.save_and_upload_button.config, {'state': NORMAL, 'text': "✔️ Save Settings & Upload Public Files"})
            return
        self.save_settings()
        self._upload_public_files_worker()
        self.root.after(0, self.save_and_upload_button.config, {'state': DISABLED, 'text': "✔️ Saved & Uploaded!"})

    def _upload_public_files_worker(self):
        try:
            ftp_root = self.config.ftp_path.strip()
            public_info_url_path = urlparse(self.active_issuer_data["infoUrl"]).path
            remote_dir_suffix = Path(public_info_url_path).parent
            full_remote_dir = (Path(ftp_root) / remote_dir_suffix.as_posix().lstrip('/\\')).as_posix()

            ftp_settings = self._get_active_ftp_settings()
            if not ftp_settings: return

            json_filepath = APP_DATA_DIR / INFO_FILENAME
            if not json_filepath.exists():
                self.root.after(0, lambda: show_error("File Not Found", f"Could not find required file: {json_filepath.name}"))
                return

            json_result = self.ftp_manager.upload_file(json_filepath, full_remote_dir, json_filepath.name, ftp_settings)
            if "successful" not in json_result.lower():
                self.root.after(0, lambda: show_error("FTP Error (JSON)", json_result))
                return

            if logo_filepath := (self.logo_path if self.logo_path and self.logo_path.exists() else None):
                logo_result = self.ftp_manager.upload_file(logo_filepath, full_remote_dir, logo_filepath.name, ftp_settings)
                if "successful" not in logo_result.lower():
                    self.root.after(0, lambda: show_error("FTP Error (Logo)", logo_result))
                    return
                self.root.after(0, lambda: show_info("Upload Complete", f"Successfully uploaded:\n\n- {json_filepath.name}\n- {logo_filepath.name}"))
            else:
                self.root.after(0, lambda: show_info("Upload Complete", f"Successfully uploaded:\n\n- {json_filepath.name}"))
            
            self.root.after(100, self.check_system_status)
        except Exception as e:
            self.root.after(0, lambda err=e: show_error("Upload Error", f"An unexpected error occurred during public file upload: {err}"))
            
    def _upload_single_file(self, local_path: Path):

            remote_dir = self.get_full_remote_path()
            if not remote_dir:
                return False, "Could not determine FTP remote path. Check settings."
                
            ftp_settings = self._get_active_ftp_settings()
            if not ftp_settings:
                return False, "Could not get FTP settings."

            result = self.ftp_manager.upload_file(local_path, remote_dir, local_path.name, ftp_settings)
            
            is_success = "successful" in result.lower()
            if self.config.enable_audit_trail and self.license_manager.is_feature_enabled("audit"):
                event_type = "UPLOAD_SUCCESS" if is_success else "UPLOAD_FAILURE"
                self.crypto_manager.log_event(self.active_issuer_id, self.active_issuer_data["priv_key_pem"], event_type, {"filename": local_path.name, "result_message": result})
            
            return is_success, result

    def upload_lkey_file_threaded(self):
        if not self.prepared_upload_path or self.upload_button_state == UploadButtonState.UPLOADING: return
        self.upload_button_state = UploadButtonState.UPLOADING
        self.update_upload_button_display()
        self.upload_progress_bar.grid()
        self.upload_progress_bar.start()
        threading.Thread(target=self._run_and_show_upload_result, args=(self.prepared_upload_path,), daemon=True).start()

    def _update_ui_for_successful_document_processing(self, was_auto_upload: bool):
        """
        Updates the UI elements after a document has been successfully signed
        and potentially auto-uploaded.
        """
        # Ensure QR and LKey displays are updated
        self.update_qr_display(self.qr_image_pil)
        final_lkey_image = Image.open(self.prepared_upload_path)
        lkey_with_overlay = self.image_processor.overlay_checkmark(final_lkey_image)
        self.update_lkey_display(lkey_with_overlay)

        # Show all action buttons initially (folder buttons are always useful)
        self._show_qr_action_buttons()
        self.lkey_folder_button.config(state=NORMAL)
        self.qr_folder_button.config(state=NORMAL)

        # Handle Print/Email buttons and main Upload button based on auto-upload status
        if was_auto_upload:
            self.upload_button_state = UploadButtonState.SUCCESS # Main upload button turns green
            self.qr_print_button.config(state=NORMAL)
            self.qr_email_button.config(state=NORMAL)
        else: # Manual upload flow: main button is ready, Print/Email still disabled
            self.upload_button_state = UploadButtonState.READY
            self.qr_print_button.config(state=DISABLED)
            self.qr_email_button.config(state=DISABLED)

        self.update_upload_button_display() # Refresh the main upload button's appearance
        logging.info(f"UI updated for successful document processing (Auto-upload: {was_auto_upload}).")

    def _update_ui_after_signing_success(self, was_auto_upload_successful: bool):
            """
            Updates the UI elements after a document has been successfully signed
            and potentially auto-uploaded, or prepared for manual upload.
            This runs on the main Tkinter thread.
            """
            # Ensure QR and LKey displays are updated
            self.update_qr_display(self.qr_image_pil)
            final_lkey_image = Image.open(self.prepared_upload_path)
            lkey_with_overlay = self.image_processor.overlay_checkmark(final_lkey_image)
            self.update_lkey_display(lkey_with_overlay)

            # Show all action buttons (folder buttons are always useful)
            self._show_qr_action_buttons()
            self.lkey_folder_button.config(state=NORMAL)
            self.qr_folder_button.config(state=NORMAL)

            # Determine state of main upload button and Print/Email buttons
            if was_auto_upload_successful:
                self.upload_button_state = UploadButtonState.SUCCESS # Main upload button turns green
                self.qr_print_button.config(state=NORMAL)
                self.qr_email_button.config(state=NORMAL)
            else: # Manual upload flow: main button is ready, Print/Email still disabled
                self.upload_button_state = UploadButtonState.READY
                self.qr_print_button.config(state=DISABLED)
                self.qr_email_button.config(state=DISABLED)

            self.update_upload_button_display() # Refresh the main upload button's appearance
            logging.info(f"UI updated after signing success (Auto-upload successful: {was_auto_upload_successful}).")
            
            # Stop and hide progress bar here as it's the final UI update after processing
            self.upload_progress_bar.stop()
            self.upload_progress_bar.grid_remove()

    def _update_ui_for_auto_upload_failure(self):
        """Updates the UI when auto-upload fails after signing."""
        self.upload_button_state = UploadButtonState.FAILURE # Main upload button turns red (retry)
        self.update_upload_button_display()
        # Keep Print/Email buttons disabled as auto-upload failed
        self.qr_print_button.config(state=DISABLED)
        self.qr_email_button.config(state=DISABLED)
        # Folder buttons should remain enabled if they were already
        if hasattr(self, "lkey_folder_button"):
            self.lkey_folder_button.config(state=NORMAL)
        if hasattr(self, "qr_folder_button"):
            self.qr_folder_button.config(state=NORMAL)
        logging.warning("UI updated for auto-upload failure.")

          
    def _run_and_show_upload_result(self, local_path: Path):
            """Worker function for manual upload, run in a background thread."""
            try:
                is_success, result = self._upload_single_file(local_path)
                self.upload_button_state = UploadButtonState.SUCCESS if is_success else UploadButtonState.FAILURE
                
                if not is_success:
                    self.root.after(0, lambda res=result: show_error("FTP Upload Error", res))
                else:
                    # Enable Print/Email buttons on manual upload success
                    self.root.after(0, lambda: self.qr_print_button.config(state=NORMAL))
                    self.root.after(0, lambda: self.qr_email_button.config(state=NORMAL))
                    
                    # Securely delete the temporary upload file
                    if self.prepared_upload_path and self.prepared_upload_path.exists():
                        self.prepared_upload_path.unlink() # Use standard, fast deletion
                        logging.info(f"Deleted temporary upload file: {self.prepared_upload_path.name}")
                        
            except Exception as e:
                logging.error(f"Error in manual upload worker: {e}", exc_info=True)
                self.root.after(0, lambda err=e: show_error("Upload Error", f"An unexpected error occurred during manual upload: {err}"))
                self.upload_button_state = UploadButtonState.FAILURE # Ensure UI reflects failure
            finally:
                # Always stop and hide progress bar after manual upload completes
                self.root.after(0, self.upload_progress_bar.stop)
                self.root.after(0, self.upload_progress_bar.grid_remove)
                self.root.after(0, self.update_upload_button_display) # Update main upload button's final state

    

    def handle_auto_sense_threaded(self):
        host, user, password = self.ftp_host_var.get(), self.ftp_user_var.get(), self.ftp_pass_var.get()
        if not all([host, user, password]):
            show_info("Missing Info", "Please fill in FTP Host, User, and Password before Auto-Sense.")
            return
        self.sense_button.config(state=DISABLED, text="Sensing...")
        self.ftp_path_entry.config(state=DISABLED)
        threading.Thread(target=self._sense_ftp_root_worker, args=(host, user, password), daemon=True).start()

    def _sense_ftp_root_worker(self, host, user, password):
        COMMON_WEB_ROOTS = ["public_html", "htdocs", "httpdocs", "www", "html"]
        try:
            with ftplib.FTP(host, timeout=15) as ftp:
                ftp.login(user, password)
                dir_list = ftp.nlst()
                if found_root := next((f"/{root}/" for root in COMMON_WEB_ROOTS if root in dir_list), None):
                    self.root.after(0, self.on_auto_sense_success, found_root)
                else:
                    self.root.after(0, self.on_auto_sense_failure, "Could not find a common web root. Please enter it manually.")
        except ftplib.all_errors as e:
            self.root.after(0, self.on_auto_sense_failure, f"FTP Error: {e}\nPlease check credentials.")
        except Exception as e:
            self.root.after(0, self.on_auto_sense_failure, f"An unexpected error occurred: {e}")

    def on_auto_sense_success(self, found_path):
        self.ftp_path_var.set(found_path)
        show_info("Path Found!", f"Successfully found web root: {found_path}\nSaving settings and uploading public files.")
        self.handle_save_and_upload_threaded()

    def on_auto_sense_failure(self, error_message):
        self.sense_button.config(state=NORMAL, text="🔎 Auto-Sense")
        self.ftp_path_entry.config(state=NORMAL)
        if hasattr(self, "save_and_upload_button"): self.save_and_upload_button.config(state=NORMAL)
        show_error("Auto-Sense Failed", error_message)

    def sanitize_filename(self, f: str) -> str:
        return "".join(c for c in f if c not in '<>:"/\\|?*').strip()

    def toggle_password_visibility(self):
        self.ftp_pass_entry.config(show="" if self.show_pass_var.get() else "*")

    def on_ftp_settings_change(self, *args):
        if hasattr(self, "save_and_upload_button"):
            self.save_and_upload_button.config(state=NORMAL)

    def set_status_logo(self, pil_image):
        self.original_status_logo_pil = pil_image
        display_logo = pil_image.resize((120, 64), self.image_processor.resample_method) if pil_image else Image.new("RGB", (120, 64), "lightgray")
        img_tk = ImageTk.PhotoImage(display_logo)
        self.status_logo_label.config(image=img_tk)
        self.status_logo_label.image = img_tk

    def _open_lkey_save_location(self):
        """Opens the folder where the signed LKey was saved."""
        lkey_path = Path(self.config.legato_files_save_path)
        if lkey_path.exists():
            webbrowser.open(f"file:///{lkey_path.resolve()}")
        else:
            show_error("Path Not Found", f"The directory '{lkey_path}' does not exist.")

    def _open_qr_save_location(self):
        """Opens the folder where the QR code image was saved."""
        # QR path is now the same as the LKey path
        qr_path = Path(self.config.legato_files_save_path)
        if qr_path.exists():
            webbrowser.open(f"file:///{qr_path.resolve()}")
        else:
            show_error("Path Not Found", f"The directory '{qr_path}' does not exist.")

    def _show_qr_action_buttons(self):
        """Places all overlay buttons on the LKey and QR frames."""
        # QR Frame Buttons (bottom-left and bottom-right)
        if hasattr(self, "qr_folder_button"):
            self.qr_folder_button.place(relx=0.0, rely=1.0, x=5, y=-5, anchor=SW)
            self.qr_email_button.place(relx=1.0, rely=1.0, x=-5, y=-5, anchor=SE)
            self.qr_print_button.place(relx=1.0, rely=1.0, x=-45, y=-5, anchor=SE)
        
        # LKey Frame Button (bottom-right)
        if hasattr(self, "lkey_folder_button"):
            self.lkey_folder_button.place(relx=1.0, rely=1.0, x=-5, y=-5, anchor=SE)

    def _hide_qr_action_buttons(self):
        """Removes all overlay action buttons."""
        if hasattr(self, "qr_print_button"):
            self.qr_print_button.place_forget()
            self.qr_email_button.place_forget()
        if hasattr(self, "qr_folder_button"):
            self.qr_folder_button.place_forget()
        if hasattr(self, "lkey_folder_button"):
            self.lkey_folder_button.place_forget()

    def print_document_qr(self):
        """Handles printing the generated document QR code."""
        if not self.qr_image_pil:
            show_error("Print Error", "No QR Code image is available to print.")
            return
        try:
            with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tf:
                self.qr_image_pil.save(tf.name)
                if sys.platform == "win32":
                    os.startfile(tf.name, "print")
                elif sys.platform == "darwin":
                    subprocess.call(["open", "-a", "Preview", tf.name])
                else:
                    subprocess.call(["xdg-open", tf.name])
        except Exception as e:
            show_error("Printing Error", f"Could not open image for printing: {e}")

    def email_document_qr(self):
        """Opens the default email client with the document QR attached."""
        if not self.qr_image_pil or not self.last_signed_payload:
            show_error("Email Error", "No QR Code or payload data is available to email.")
            return

        try:
            filename, summary, _ = self.last_signed_payload.split('|', 2)
        except (ValueError, AttributeError):
            filename = "signed_document"
            summary = "See attached."

        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tf:
            temp_path = Path(tf.name)
            self.qr_image_pil.save(temp_path)

        subject = f"LegatoKey for document: {filename}"
        body = (f"Hello,\n\nAttached is the LegatoKey for the following item:\n\n"
                f"Document: {filename}\n"
                f"Summary: {summary}\n\n"
                f"Best regards,\n{self.active_issuer_data.get('name', 'The Issuer')}")

        webbrowser.open(f"mailto:?subject={requests.utils.quote(subject)}&body={requests.utils.quote(body)}")
        show_info("Email Client Opened",
                  f"Your email client has been opened. Please attach the following file to your email:\n\n{temp_path}")

    def export_issuer_qr(self):
        if not self.issuer_qr_image_pil: return
        if file_path_str := filedialog.asksaveasfilename(defaultextension=".png", initialfile=f"issuer_{self.active_issuer_id}_qr.png", title="Save Issuer QR"):
            self.issuer_qr_image_pil.save(file_path_str)

    def email_issuer_qr(self):
        if not self.issuer_qr_image_pil: return
        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tf:
            temp_path = Path(tf.name)
            self.issuer_qr_image_pil.save(temp_path)
        name = self.active_issuer_data.get("name", "My Issuer")
        subject = f"LegatoLink Authority ID for {name}"
        body = f"Hello,\n\nAttached is my LegatoLink Authority ID.\n\nInfo URL: {self.active_issuer_data.get('infoUrl', 'N/A')}\n\nBest regards,\n{name}"
        webbrowser.open(f"mailto:?subject={requests.utils.quote(subject)}&body={requests.utils.quote(body)}")
        show_info("Email Client Opened", f"Please attach the following file to your email:\n\n{temp_path}")

    def print_issuer_qr(self):
        if not self.issuer_qr_image_pil: return
        try:
            with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tf:
                self.issuer_qr_image_pil.save(tf.name)
                if sys.platform == "win32": os.startfile(tf.name, "print")
                elif sys.platform == "darwin": subprocess.call(["open", "-a", "Preview", tf.name])
                else: subprocess.call(["xdg-open", tf.name])
        except Exception as e:
            show_error("Printing Error", f"Could not open image for printing: {e}")

    def update_image_base_url_proposal(self, *args):
        try:
            if parsed := urlparse(self.url_path_var.get()):
                if parsed.scheme and parsed.netloc:
                    root = f"{parsed.scheme}://{parsed.netloc}/"
                    self.image_base_url_var.set(root)
                    self.image_base_url_example_label.config(text=f"Example: {root}certificates/")
        except Exception: pass

    def _validate_https_prefix(self, v):
        return v.startswith("https://")

    def _validate_image_url_prefix(self, P):
        if hasattr(self, 'current_root_url'):
            return not self.current_root_url or P.startswith(self.current_root_url)
        return True

    def _validate_summary_length(self, event=None):
        current_text = self.message_text.get("1.0", "end-1c")
        char_len = len(current_text)
        if char_len > MAX_SUMMARY_CHARS:
            self.message_text.delete(f"1.0 + {MAX_SUMMARY_CHARS} chars", "end")
            char_len = MAX_SUMMARY_CHARS
        self.char_count_label.config(text=f"{char_len} / {MAX_SUMMARY_CHARS}", bootstyle=DANGER if char_len >= MAX_SUMMARY_CHARS else SECONDARY)

    def _clear_logo(self):
        self.logo_path = None
        self.logo_display_label.config(image=None)
        self.logo_display_label.image = None
        self.logo_display_label.grid_remove()
        self.logo_text_frame.grid(row=0, column=0, sticky="nsew")

    def _browse_for_logo(self):
        if not (filepath := filedialog.askopenfilename(title="Select Logo", filetypes=[("Image Files", "*.png *.jpg *.jpeg"), ("All files", "*.*")])): return
        source_path = Path(filepath)
        if source_path.stat().st_size > MAX_LOGO_SIZE_BYTES:
            show_error("File Too Large", f"Logo exceeds {MAX_LOGO_SIZE_BYTES / 1024:.0f}KB size limit.")
            return
        try:
            img = Image.open(source_path)
            if (img.width * img.height) > MAX_LOGO_PIXELS:
                ratio = (MAX_LOGO_PIXELS / (img.width * img.height)) ** 0.5
                new_size = (int(img.width * ratio), int(img.height * ratio))
                show_info("Logo Resized", f"Logo was resized to {new_size[0]}x{new_size[1]} for performance.")
                img = img.resize(new_size, Image.Resampling.LANCZOS)
            standardized_path = APP_DATA_DIR / f"{STANDARDIZED_LOGO_BASENAME}{source_path.suffix}"
            img_format = "jpeg" if source_path.suffix.lower() in [".jpg", ".jpeg"] else "png"
            if img.mode in ["RGBA", "P"] and img_format == "jpeg": img = img.convert("RGB")
            img.save(standardized_path, format=img_format, quality=95 if img_format == "jpeg" else None)
            self.logo_path = standardized_path
            display_img = img.copy()
            display_img.thumbnail((250, 250), Image.Resampling.LANCZOS)
            logo_photo = ImageTk.PhotoImage(display_img)
            self.logo_display_label.config(image=logo_photo)
            self.logo_display_label.image = logo_photo
            self.logo_text_frame.grid_remove()
            self.logo_display_label.grid(row=0, column=0, sticky="nsew")
        except Exception as e:
            show_error("File Error", f"Could not process logo file. Error: {e}")
            self._clear_logo()

    def _update_wraplength(self, event, label_widget):
        label_widget.config(wraplength=event.width - 20)

    # --- UI Creation and Management ---
    def create_status_panel(self):
        self.status_frame = ttk.LabelFrame(self.root, text="System Status", padding=10)
        self.status_frame.pack(fill=X, padx=10, pady=(10, 0))
        logo_frame = ttk.Frame(self.status_frame)
        logo_frame.pack(side=LEFT, padx=(0, 15))
        self.status_logo_label = ttk.Label(logo_frame)
        self.status_logo_label.pack()
        self.set_status_logo(None)
        info_frame = ttk.Frame(self.status_frame)
        info_frame.pack(side=LEFT, fill=X, expand=True)
        self.status_message_label = ttk.Label(info_frame, text="Starting up...", font="-weight bold", bootstyle=PRIMARY)
        self.status_message_label.pack(anchor=W)
        self.status_details_label = ttk.Label(info_frame, text="Load an identity or create one to begin.", wraplength=650)
        self.status_details_label.pack(anchor=W, pady=(5, 0))
        self.pro_status_label = ttk.Label(info_frame, text="Pro License: Not Active", bootstyle=WARNING)
        self.pro_status_label.pack(anchor=W, pady=(5, 0))
        self.update_pro_license_status_display()
        self.check_status_button = ttk.Button(self.status_frame, text="Check Status", command=self.check_system_status, state=DISABLED, bootstyle=SECONDARY)
        self.check_status_button.pack(side=RIGHT, anchor=S, padx=(10, 0))
        ttk.Separator(self.root, orient=HORIZONTAL).pack(fill=X, padx=10, pady=5)

    def create_main_ui(self):
        main_frame = ttk.Frame(self.root, padding=10)
        main_frame.pack(fill=BOTH, expand=True)
        self.notebook = ttk.Notebook(main_frame, bootstyle=PRIMARY)
        self.notebook.pack(fill=BOTH, expand=True)
        tabs_info = [
            (" 1. Issuer Identity ", self.create_identity_tab, None),
            (" 2. Sign Document ", self.create_signer_tab, None),
            (" 3. Settings ", self.create_settings_and_uploads_tab, None),
            (" 4. Backup & Security ", self.create_backup_and_security_tab, None),
            (" 5. Batch Processing ", self.create_batch_signing_tab, "batch"),
            (" 6. Audit Trail ", self.create_audit_viewer_tab, "audit"),
            (" 7. Guide ", self.create_guide_tab, None),
            (" 8. About ", self.create_about_tab, None),
        ]
        for text, creation_method, pro_feature in tabs_info:
            tab_frame = ttk.Frame(self.notebook, padding=10)
            is_pro = pro_feature is not None
            is_enabled = not is_pro or (self.license_manager.is_feature_enabled(pro_feature) and PRO_FEATURES_AVAILABLE)
            if is_pro and not is_enabled:
                tab_text = f"💎 {text}"
                self.notebook.add(tab_frame, text=tab_text, state=DISABLED)
                self._create_pro_placeholder(tab_frame, text.strip())
            else:
                self.notebook.add(tab_frame, text=text)
                creation_method(tab_frame)
    
    def _create_pro_placeholder(self, parent, feature_name):
        pro_frame = ttk.Frame(parent, padding=20)
        pro_frame.pack(fill=BOTH, expand=True, anchor=CENTER)
        ttk.Label(pro_frame, text=f"{feature_name} is a Professional Feature", font="-weight bold -size 14").pack(pady=20)
        ttk.Label(pro_frame, text="Please purchase a Pro license to enable this functionality.", bootstyle=SECONDARY).pack()
        ttk.Button(pro_frame, text="Visit Website to Upgrade", bootstyle=SUCCESS, command=lambda: webbrowser.open("https://www.example.com/pricing")).pack(pady=20)

    def update_ui_state(self):
        has_identity = bool(self.active_issuer_id)
        for i in range(1, self.notebook.index(END)):
            if "💎" not in self.notebook.tab(i, "text"):
                self.notebook.tab(i, state=NORMAL if has_identity else DISABLED)
        is_watermark_licensed = self.license_manager.is_feature_enabled("watermark")
        is_audit_licensed = self.license_manager.is_feature_enabled("audit")
        widget_states = {
            self.pro_security_checkbox: has_identity, self.randomize_lkey_name_checkbox: has_identity,
            self.apply_watermark_checkbox: has_identity and is_watermark_licensed,
            self.apply_logo_watermark_checkbox: has_identity and is_watermark_licensed,
            self.enable_audit_trail_checkbox: has_identity and is_audit_licensed,
        }
        for widget, enabled in widget_states.items():
            widget.config(state=NORMAL if enabled else DISABLED)
        self.toggle_watermark_state()
        if has_identity:
            self.setup_frame.pack_forget()
            self.manage_frame.pack(fill=X, pady=(0, 10))
            self.update_manage_frame_display()
            self.update_issuer_qr_display()
            self.check_status_button.config(state=NORMAL)
            if is_audit_licensed: self._handle_refresh_audit()
        else:
            self.manage_frame.pack_forget()
            self.setup_frame.pack(fill=X, pady=(0, 10))
            self.status_message_label.config(text="No identity. Create one to begin.", bootstyle=PRIMARY)
            self.status_details_label.config(text="Go to the 'Issuer Identity' tab.")
            self.set_status_logo(None)
            self.check_status_button.config(state=DISABLED)
        self.reset_upload_button_state()
        self._update_ftp_dependent_widgets_state()
        self.update_auto_upload_indicator()
    
    def create_identity_tab(self, parent_frame):
        self.setup_frame = ttk.LabelFrame(parent_frame, text="🔑 Create Your Issuer Identity", padding=15)
        self.setup_frame.pack(fill="x", pady=(0, 10))
        self.setup_frame.grid_columnconfigure(0, weight=0)
        self.setup_frame.grid_columnconfigure(1, weight=1)
        logo_panel = ttk.Frame(self.setup_frame)
        logo_panel.grid(row=0, column=0, sticky="n", padx=(0, 20))
        logo_container = ttk.LabelFrame(logo_panel, text="Your Logo (Optional)")
        logo_container.pack()
        self.logo_placeholder_frame = ttk.Frame(logo_container, width=250, height=250)
        self.logo_placeholder_frame.pack(padx=10, pady=10)
        self.logo_placeholder_frame.grid_propagate(False)
        self.logo_placeholder_frame.grid_rowconfigure(0, weight=1)
        self.logo_placeholder_frame.grid_columnconfigure(0, weight=1)
        self.logo_text_frame = ttk.Frame(self.logo_placeholder_frame)
        self.logo_text_frame.grid(row=0, column=0, sticky="nsew")
        self.logo_text_frame.grid_rowconfigure((0, 1), weight=1)
        self.logo_text_frame.grid_columnconfigure(0, weight=1)
        ttk.Label(self.logo_text_frame, text="No Logo Selected", bootstyle="secondary").pack(expand=True)
        ttk.Label(self.logo_text_frame, text="Recommended: 400x184 pixels", bootstyle="secondary").pack(expand=True)
        self.logo_display_label = ttk.Label(self.logo_placeholder_frame, anchor="center")
        logo_button_frame = ttk.Frame(logo_container)
        logo_button_frame.pack(pady=(0, 10), fill="x", padx=5)
        logo_button_frame.grid_columnconfigure((0, 1), weight=1)
        ttk.Button(logo_button_frame, text="🖼️ Browse...", command=self._browse_for_logo, bootstyle="outline").grid(row=0, column=0, sticky="ew", padx=(0, 2))
        ttk.Button(logo_button_frame, text="🗑️ Clear Logo", command=self._clear_logo, bootstyle="outline-danger").grid(row=0, column=1, sticky="ew", padx=(2, 0))
        right_panel = ttk.Frame(self.setup_frame)
        right_panel.grid(row=0, column=1, sticky="new")
        ttk.Label(right_panel, text="Enter your name or organisation", font="-weight bold").pack(anchor="w")
        ttk.Label(right_panel, text="(This generates your permanent ID and identifies you as the authority)", bootstyle="info").pack(anchor="w", pady=(0, 5))
        self.name_entry = ttk.Entry(right_panel)
        self.name_entry.pack(fill="x", pady=(0, 15))
        ttk.Label(right_panel, text="Enter the address of your web server", font="-weight bold").pack(anchor="w")
        ttk.Label(right_panel, text="(This is where your public Legato ID will be stored, e.g., https://your-site.com/)", bootstyle="info").pack(anchor="w", pady=(0, 5))
        vcmd_https = (self.root.register(self._validate_https_prefix), "%P")
        self.url_path_entry = ttk.Entry(right_panel, textvariable=self.url_path_var, validate="key", validatecommand=vcmd_https)
        self.url_path_var.set("https://")
        self.url_path_entry.pack(fill="x", pady=(0, 15))
        ttk.Label(right_panel, text="Choose the folder on your server for signed documents", font="-weight bold").pack(anchor="w")
        helper_text_frame = ttk.Frame(right_panel)
        helper_text_frame.pack(fill="x", pady=(0, 5))
        ttk.Label(helper_text_frame, text="(This will be used to store your signed documents)", bootstyle="info").pack(side="left")
        self.image_base_url_example_label = ttk.Label(helper_text_frame, text="e.g: [...]", bootstyle="secondary")
        self.image_base_url_example_label.pack(side="right")
        vcmd_img_prefix = (self.root.register(self._validate_image_url_prefix), "%P")
        self.image_base_url_entry = ttk.Entry(right_panel, textvariable=self.image_base_url_var, validate="key", validatecommand=vcmd_img_prefix)
        self.image_base_url_entry.pack(fill="x", pady=(0, 15))
        self.url_path_var.trace_add("write", self.update_image_base_url_proposal)
        optional_frame = ttk.LabelFrame(right_panel, text="Optional Public Contact Info", padding=10)
        optional_frame.pack(fill="x", pady=(5, 15))
        optional_frame.grid_columnconfigure(1, weight=1)
        ttk.Label(optional_frame, text="Email:").grid(row=0, column=0, sticky="w", padx=(0, 10), pady=2)
        self.email_entry = ttk.Entry(optional_frame)
        self.email_entry.grid(row=0, column=1, sticky="ew")
        ttk.Label(optional_frame, text="Phone:").grid(row=1, column=0, sticky="w", padx=(0, 10), pady=2)
        self.phone_entry = ttk.Entry(optional_frame)
        self.phone_entry.grid(row=1, column=1, sticky="ew")
        ttk.Label(optional_frame, text="Address:").grid(row=2, column=0, sticky="w", padx=(0, 10), pady=2)
        self.address_entry = ttk.Entry(optional_frame)
        self.address_entry.grid(row=2, column=1, sticky="ew")
        ttk.Separator(self.setup_frame).grid(row=1, column=0, columnspan=2, sticky="ew", pady=15)
        ttk.Button(self.setup_frame, text="Generate and Save Identity", command=self.create_and_save_identity, bootstyle=SUCCESS).grid(row=2, column=0, columnspan=2, sticky="ew", ipady=5)
        self.manage_frame = ttk.LabelFrame(parent_frame, text="🔑 Your Active Issuer Identity", padding="15")
        self.manage_frame.grid_columnconfigure(0, weight=0)
        self.manage_frame.grid_columnconfigure(1, weight=1)
        self.manage_frame.grid_rowconfigure(0, weight=0)
        self.issuer_qr_display_label = ttk.Label(self.manage_frame)
        self.issuer_qr_display_label.grid(row=0, column=0, sticky="n", padx=(0, 20))
        right_panel_manage = ttk.Frame(self.manage_frame)
        right_panel_manage.grid(row=0, column=1, sticky="new")
        info_box = ttk.Frame(right_panel_manage)
        info_box.pack(fill="x", pady=(0, 15), anchor="n")
        info_box.grid_columnconfigure(1, weight=1)
        ttk.Label(info_box, text="Issuer ID:").grid(row=0, column=0, sticky="w", pady=2)
        self.id_label = ttk.Label(info_box, text="N/A", font="-weight bold")
        self.id_label.grid(row=0, column=1, sticky="w", padx=5, pady=2)
        ttk.Label(info_box, text="Name:").grid(row=1, column=0, sticky="w", pady=2)
        self.name_label = ttk.Label(info_box, text="N/A", font="-weight bold")
        self.name_label.grid(row=1, column=1, sticky="w", padx=5, pady=2)
        ttk.Label(info_box, text="Info URL:").grid(row=2, column=0, sticky="nw", pady=2)
        self.url_label = ttk.Label(info_box, text="N/A", wraplength=450)
        self.url_label.grid(row=2, column=1, sticky="w", padx=5, pady=2)
        contact_box = ttk.LabelFrame(right_panel_manage, text="Public Contact Info (from server)", padding=10)
        contact_box.pack(fill="x", pady=(0, 15), anchor="n")
        contact_box.grid_columnconfigure(1, weight=1)
        ttk.Label(contact_box, text="Email:").grid(row=0, column=0, sticky="w", pady=2)
        self.email_label_val = ttk.Label(contact_box, text="N/A", wraplength=400)
        self.email_label_val.grid(row=0, column=1, sticky="w", padx=5, pady=2)
        ttk.Label(contact_box, text="Phone:").grid(row=1, column=0, sticky="w", pady=2)
        self.phone_label_val = ttk.Label(contact_box, text="N/A", wraplength=400)
        self.phone_label_val.grid(row=1, column=1, sticky="w", padx=5, pady=2)
        ttk.Label(contact_box, text="Address:").grid(row=2, column=0, sticky="nw", pady=2)
        self.address_label_val = ttk.Label(contact_box, text="N/A", wraplength=400)
        self.address_label_val.grid(row=2, column=1, sticky="w", padx=5, pady=2)
        btn_frame = ttk.Frame(right_panel_manage)
        btn_frame.pack(fill="x", pady=(5, 0), anchor="n")
        btn_frame.grid_columnconfigure(list(range(4)), weight=1)
        ttk.Button(btn_frame, text="📤 Export QR", command=self.export_issuer_qr, bootstyle=OUTLINE).grid(row=0, column=0, sticky="ew", padx=(0, 2))
        ttk.Button(btn_frame, text="✉️ Email QR", command=self.email_issuer_qr, bootstyle=OUTLINE).grid(row=0, column=1, sticky="ew", padx=(2, 2))
        ttk.Button(btn_frame, text="🖨️ Print QR", command=self.print_issuer_qr, bootstyle=OUTLINE).grid(row=0, column=2, sticky="ew", padx=(2, 2))
        ttk.Button(btn_frame, text="🗑️ Delete ID-entity", command=self.delete_identity, bootstyle=DANGER).grid(row=0, column=3, sticky="ew", padx=(2, 0))

    def create_signer_tab(self, parent_frame):
        # --- Main container ---
        main_container = ttk.Frame(parent_frame)
        main_container.pack(fill="both", expand=True)
        
        # --- Main Encoder Frame ---
        self.encoder_frame = ttk.LabelFrame(main_container, text="🖊️ Sign a New Document", padding="10")
        self.encoder_frame.pack(fill="both", expand=True)
        self.encoder_frame.grid_columnconfigure((0, 1), weight=1, uniform="signer_columns")
        self.encoder_frame.grid_rowconfigure(3, weight=1) # Set row 3 (display area) to expand

        # --- Top Section: Image Select and Summary ---
        input_area_frame = ttk.Frame(self.encoder_frame)
        input_area_frame.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 10))
        input_area_frame.grid_columnconfigure(1, weight=1)
        
        # Left side - Browse button
        self.browse_button = ttk.Button(input_area_frame, text="📄 Select Image...", command=self.browse_and_set_image_file, bootstyle="primary-outline")
        self.browse_button.grid(row=0, column=0, sticky="ns", padx=(0, 10))
        
        # Summary frame with inline document number option
        summary_frame = ttk.Frame(input_area_frame)
        summary_frame.grid(row=0, column=1, sticky="nsew")
        summary_frame.grid_columnconfigure(0, weight=1)
        summary_frame.grid_rowconfigure(1, weight=1)
        
        # Header with summary label and doc number controls
        header_frame = ttk.Frame(summary_frame)
        header_frame.grid(row=0, column=0, sticky="ew")
        header_frame.grid_columnconfigure(0, weight=1)
        
        ttk.Label(header_frame, text="Document Summary / Message:").grid(row=0, column=0, sticky="w")
 
        # Document number controls frame (appears on same line when toggled)
        self.doc_num_frame = ttk.Frame(header_frame)
        self.doc_num_frame.grid(row=0, column=1, sticky="e", padx=(10, 5))
        
        # Entry for the number preview/manual entry
        self.doc_num_entry = ttk.Entry(self.doc_num_frame, textvariable=self.doc_num_var, width=20, font=("TkDefaultFont", 9))
        self.doc_num_entry.grid(row=0, column=0, padx=(0, 5))
        self.doc_num_var.trace_add("write", self._validate_doc_num_len)
        
        # The single "Auto" checkbox that is now mask-aware
        self.auto_gen_check = ttk.Checkbutton(self.doc_num_frame, text="Auto", variable=self.auto_gen_doc_num_var, 
                                              command=self._on_auto_toggle)
        self.auto_gen_check.grid(row=0, column=1, padx=(0, 10))

        # Toggle button to show/hide the whole frame
        ttk.Checkbutton(header_frame, text="+ Doc #", 
                    variable=self.include_doc_num_var, 
                    bootstyle="round-toggle",
                    command=self._toggle_doc_num_frame_visibility).grid(row=0, column=2, sticky="e")
        
        self.doc_num_frame.grid_remove()  # Initially hidden
      
        # Text area
        self.message_text = ttk.Text(summary_frame, height=4, wrap="word")
        self.message_text.grid(row=1, column=0, sticky="nsew")
        
        # Status line frame
        status_line_frame = ttk.Frame(input_area_frame)
        status_line_frame.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(5, 0))
        self.char_count_label = ttk.Label(status_line_frame, text=f"0 / {MAX_SUMMARY_CHARS}", bootstyle="secondary")
        self.char_count_label.pack(side="right")
        self.doc_id_helper_label = ttk.Label(status_line_frame, text="No Image selected.", bootstyle="secondary", anchor="w")
        self.doc_id_helper_label.pack(side="left", fill="x", expand=True)
        self.message_text.bind("<KeyRelease>", self._validate_summary_length)

        # --- Main Action Buttons ---
        self.generate_qr_button = ttk.Button(self.encoder_frame, text="✨ Fingerprint, Sign & Save", command=self.generate_document_qr, bootstyle=PRIMARY, state="disabled")
        self.generate_qr_button.grid(row=2, column=0, sticky="ew", ipady=5, padx=(0, 5), pady=10)
        self.upload_button = ttk.Button(self.encoder_frame, text="🚀 Upload LKey", command=self.upload_lkey_file_threaded, state="disabled")
        self.upload_button.grid(row=2, column=1, sticky="ew", ipady=5, padx=(5, 0), pady=10)
        
        # --- Display Frames ---
        lkey_lf = ttk.LabelFrame(self.encoder_frame, text="Fingerprinted Legato Key Image")
        lkey_lf.grid(row=3, column=0, sticky="nsew", padx=(0, 5), pady=(10,0))
        lkey_lf.grid_columnconfigure(0, weight=1)
        lkey_lf.grid_rowconfigure(1, weight=1)
        top_status_bar_frame = ttk.Frame(lkey_lf)
        top_status_bar_frame.grid(row=0, column=0, sticky="ew", padx=5)
        top_status_bar_frame.grid_columnconfigure(0, weight=1)
        top_status_bar_frame.grid_columnconfigure(1, weight=1)
        self.auto_upload_indicator_label = ttk.Label(top_status_bar_frame, text="", bootstyle="success")
        self.auto_upload_indicator_label.grid(row=0, column=0, sticky="w", padx=(0, 5))
        self.upload_progress_bar = ttk.Progressbar(top_status_bar_frame, mode="indeterminate", length=150)
        self.upload_progress_bar.grid(row=0, column=1, sticky="ew")
        self.upload_progress_bar.grid_remove()
        self.lkey_image_display_label = ttk.Label(lkey_lf, relief="flat", anchor="center")
        self.lkey_image_display_label.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)
        self.lkey_folder_button = ttk.Button(lkey_lf, text="📁", command=self._open_lkey_save_location, bootstyle="secondary-outline", width=3)
        
        qr_lf = ttk.LabelFrame(self.encoder_frame, text="Generated LegatoKey QR")
        qr_lf.grid(row=3, column=1, sticky="nsew", padx=(5, 0), pady=(10,0))
        self.qr_display_label = ttk.Label(qr_lf, relief="flat", anchor="center")
        self.qr_display_label.pack(fill="both", expand=True, padx=5, pady=5)
        self.qr_print_button = ttk.Button(qr_lf, text="🖨️", command=self.print_document_qr, bootstyle="secondary-outline", width=3)
        self.qr_email_button = ttk.Button(qr_lf, text="✉️", command=self.email_document_qr, bootstyle="secondary-outline", width=3)
        self.qr_folder_button = ttk.Button(qr_lf, text="📁", command=self._open_qr_save_location, bootstyle="secondary-outline", width=3)
        
    def create_batch_signing_tab(self, parent_frame):
        parent_frame.grid_rowconfigure(1, weight=1)
        parent_frame.grid_columnconfigure(0, weight=1)
        control_frame = ttk.Frame(parent_frame)
        control_frame.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        ttk.Button(control_frame, text="📂 Load Data File...", command=self._handle_load_data_file, bootstyle=PRIMARY).pack(side="left", padx=(0, 10))
        self.batch_file_label = ttk.Label(control_frame, text="No file loaded.", bootstyle="secondary")
        self.batch_file_label.pack(side="left", anchor="w")
        coldata = [
            {"text": "Status", "stretch": False, "width": 150},
            {"text": "Image File Path", "stretch": True},
            {"text": "Certificate Summary", "stretch": True},
        ]
        self.batch_tree = Tableview(parent_frame, coldata=coldata, paginated=False, searchable=False, bootstyle=PRIMARY)
        self.batch_tree.grid(row=1, column=0, sticky="nsew")
        self.batch_tree.view.tag_configure("SOURCE_ERROR", background="lightcoral")
        self.batch_tree.view.tag_configure("SUCCESS", background="lightgreen")
        self.batch_tree.view.tag_configure("FAILURE", background="lightcoral")
        self.batch_tree.view.tag_configure("PROCESSING", background="lightyellow")
        action_frame = ttk.Frame(parent_frame)
        action_frame.grid(row=2, column=0, sticky="ew", pady=(10, 0))
        action_frame.grid_columnconfigure(0, weight=1)
        self.process_batch_button = ttk.Button(action_frame, text="▶️ Process Batch", command=self._handle_process_batch, state="disabled")
        self.process_batch_button.grid(row=0, column=1, sticky="e")
        self.batch_progress = ttk.Progressbar(action_frame, mode="determinate")
        self.batch_progress.grid(row=0, column=0, sticky="ew", padx=(0, 10))

    def create_audit_viewer_tab(self, parent_frame):
        parent_frame.grid_rowconfigure(1, weight=1)
        parent_frame.grid_columnconfigure(0, weight=1)
        control_frame = ttk.Frame(parent_frame)
        control_frame.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        ttk.Button(control_frame, text="🔄 Refresh Audit Trail", command=self._handle_refresh_audit, bootstyle=PRIMARY).pack(side="left", padx=(0, 10))
        self.audit_status_label = ttk.Label(control_frame, text="Load an identity to view the audit trail.", bootstyle="secondary")
        self.audit_status_label.pack(side="left", anchor="w")
        coldata = [
            {"text": "Chain ✓", "stretch": False, "width": 80},
            {"text": "Timestamp (UTC)", "stretch": False, "width": 200},
            {"text": "Event Type", "stretch": False, "width": 150},
            {"text": "Details", "stretch": True},
        ]
        self.audit_tree = Tableview(parent_frame, coldata=coldata, paginated=True, pagesize=50, searchable=True, bootstyle=INFO)
        self.audit_tree.grid(row=1, column=0, sticky="nsew")
        self.audit_tree.view.tag_configure("VALID", background="lightgreen")
        self.audit_tree.view.tag_configure("INVALID_SIG", background="lightcoral")
        self.audit_tree.view.tag_configure("BROKEN_CHAIN", background="orange")

    def create_settings_and_uploads_tab(self, parent_frame):
        parent_frame.grid_rowconfigure(1, weight=0)
        parent_frame.grid_columnconfigure(0, weight=1)
        top_columns_container = ttk.Frame(parent_frame)
        top_columns_container.grid(row=0, column=0, sticky="new")
        top_columns_container.grid_columnconfigure((0, 1), weight=1, uniform="settings_group")
        connection_frame = ttk.LabelFrame(top_columns_container, text="🚀 Connection & Uploads", padding=15)
        connection_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 5), pady=(0, 10))
        connection_frame.grid_columnconfigure(1, weight=1)
        ttk.Label(connection_frame, text="Step 1: Enter FTP Server Credentials", font="-weight bold").grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 10))
        ttk.Label(connection_frame, text="Username:").grid(row=1, column=0, sticky="w", padx=(0, 10), pady=4)
        self.ftp_user_entry = ttk.Entry(connection_frame, textvariable=self.ftp_user_var)
        self.ftp_user_entry.grid(row=1, column=1, columnspan=2, sticky="ew", pady=4, ipady=2)
        ttk.Label(connection_frame, text="Password:").grid(row=2, column=0, sticky="w", padx=(0, 10), pady=4)
        self.ftp_pass_entry = ttk.Entry(connection_frame, textvariable=self.ftp_pass_var, show="*")
        self.ftp_pass_entry.grid(row=2, column=1, sticky="ew", pady=4, ipady=2)
        ttk.Checkbutton(connection_frame, text="Show", variable=self.show_pass_var, command=self.toggle_password_visibility, bootstyle="toolbutton").grid(row=2, column=2, sticky="w", padx=5)
        ttk.Separator(connection_frame).grid(row=3, column=0, columnspan=3, sticky="ew", pady=15)
        ttk.Label(connection_frame, text="Step 2: Set FTP Address & Path", font="-weight bold").grid(row=4, column=0, columnspan=3, sticky="w", pady=(0, 10))
        ttk.Label(connection_frame, text="FTP Host:").grid(row=5, column=0, sticky="w", padx=(0, 10), pady=4)
        self.ftp_host_entry = ttk.Entry(connection_frame, textvariable=self.ftp_host_var)
        self.ftp_host_entry.grid(row=5, column=1, columnspan=2, sticky="ew", pady=4, ipady=2)
        ttk.Label(connection_frame, text="(Pre-filled from your URL. Please verify.)", bootstyle="secondary").grid(row=6, column=1, columnspan=2, sticky="w", padx=5)
        ttk.Label(connection_frame, text="Web Root Path:").grid(row=7, column=0, sticky="w", padx=(0, 10), pady=(15, 4))
        path_entry_frame = ttk.Frame(connection_frame)
        path_entry_frame.grid(row=7, column=1, columnspan=2, sticky="ew", pady=(15, 4))
        self.ftp_path_entry = ttk.Entry(path_entry_frame, textvariable=self.ftp_path_var)
        self.ftp_path_entry.pack(side="left", fill="x", expand=True, ipady=2, padx=(0, 5))
        self.sense_button = ttk.Button(path_entry_frame, text="🔎 Auto-Sense", command=self.handle_auto_sense_threaded, bootstyle="outline-info")
        self.sense_button.pack(side="left")
        ttk.Label(connection_frame, text="(e.g., /public_html/ or use Auto-Sense)", bootstyle="secondary").grid(row=8, column=1, columnspan=2, sticky="w", padx=5)
        ttk.Separator(connection_frame).grid(row=9, column=0, columnspan=3, sticky="ew", pady=15)
        ttk.Label(connection_frame, text="Step 3: Finalize Setup", font="-weight bold").grid(row=10, column=0, columnspan=3, sticky="w", pady=(0, 10))
        self.save_and_upload_button = ttk.Button(connection_frame, text="✔️ Save Settings & Upload Public Files", command=self.handle_save_and_upload_threaded, bootstyle=PRIMARY, state="disabled")
        self.save_and_upload_button.grid(row=11, column=0, columnspan=3, sticky="ew", ipady=5)
        right_container = ttk.Frame(top_columns_container)
        right_container.grid(row=0, column=1, sticky="nsew", padx=(5, 0))
        lkey_qr_frame = ttk.LabelFrame(right_container, text="⚙️ Signing & Saving Options", padding=15)
        lkey_qr_frame.pack(fill="x", expand=False, pady=(0, 10))
        self.auto_upload_check = ttk.Checkbutton(lkey_qr_frame, text="Automatically Upload LKeys After Signing", variable=self.ftp_auto_upload_var, bootstyle="success-round-toggle", command=self.on_auto_upload_toggle, state="disabled")
        self.auto_upload_check.pack(anchor="w", pady=(5, 10))
        self.randomize_lkey_name_checkbox = ttk.Checkbutton(lkey_qr_frame, text="Salt LKey File Name", variable=self.randomize_lkey_name_var, bootstyle="round-toggle", command=self.save_settings)
        self.randomize_lkey_name_checkbox.pack(anchor="w", pady=(5, 10))
        
        ttk.Label(lkey_qr_frame, text="Local Save Location for Signed Files (auto-organized by date):").pack(anchor="w", pady=(10, 2))
        lkey_path_frame = ttk.Frame(lkey_qr_frame)
        lkey_path_frame.pack(fill="x", expand=True)
        ttk.Entry(lkey_path_frame, textvariable=self.legato_files_save_path_var, state="readonly").pack(side="left", fill="x", expand=True, padx=(0, 5))
        ttk.Button(lkey_path_frame, text="...", width=3, command=self.browse_for_legato_files_save_path).pack(side="left")

        watermark_frame = ttk.LabelFrame(right_container, text="🖼️ Watermark Options (Pro Feature)", padding=15)
        watermark_frame.pack(fill="x", expand=False, pady=(10, 0))
        is_watermark_licensed = self.license_manager.is_feature_enabled("watermark")
        text_watermark_frame = ttk.Frame(watermark_frame)
        text_watermark_frame.pack(fill="x", pady=(5, 10))
        self.apply_watermark_checkbox = ttk.Checkbutton(text_watermark_frame, text="Apply Text Watermark:", variable=self.apply_watermark_var, bootstyle="round-toggle", command=lambda: (self.toggle_watermark_state(), self.save_settings()), state="disabled" if not is_watermark_licensed else "normal")
        self.apply_watermark_checkbox.pack(side="left", padx=(0, 10))
        self.watermark_entry = ttk.Entry(text_watermark_frame, textvariable=self.watermark_text_var, width=30)
        self.watermark_entry.pack(side="left", fill="x", expand=True)
        self.watermark_entry.bind("<FocusOut>", lambda e: self.save_settings())
        self.apply_logo_watermark_checkbox = ttk.Checkbutton(watermark_frame, text="Apply Your Logo as Watermark", variable=self.apply_logo_watermark_var, bootstyle="round-toggle", command=self.save_settings, state="disabled" if not is_watermark_licensed else "normal")
        self.apply_logo_watermark_checkbox.pack(anchor="w", pady=5)
        if not is_watermark_licensed:
            ttk.Label(watermark_frame, text="Purchase a Pro license to enable watermarking.", bootstyle="info").pack(anchor="w", pady=(5, 0))
        
        audit_frame = ttk.LabelFrame(right_container, text="💎 Secured Audit Trail (Pro Feature)", padding=15)
        audit_frame.pack(fill="x", expand=False, pady=(10, 0))
        is_audit_licensed = self.license_manager.is_feature_enabled("audit")
        self.enable_audit_trail_checkbox = ttk.Checkbutton(audit_frame, text="Enable Audit Trail", variable=self.enable_audit_trail_var, bootstyle="info-round-toggle", state="disabled" if not is_audit_licensed else "normal", command=self.save_settings)
        self.enable_audit_trail_checkbox.pack(anchor="w", fill="x", pady=(5, 5))
        ttk.Label(audit_frame, text="Creates a cryptographically signed log of all signing and upload events.", wraplength=400, bootstyle="secondary").pack(anchor="w")
        if not is_audit_licensed:
            ttk.Label(audit_frame, text="Purchase a Pro license to enable this.", bootstyle="info").pack(anchor="w", pady=(5, 0))      
        self._update_ftp_dependent_widgets_state()
            
    # --- NEW FRAME FOR DOCUMENT NUMBER SETTINGS ---
        doc_num_settings_frame = ttk.LabelFrame(right_container, text="💎 Document Number Mask (Pro Feature)", padding=15)
        doc_num_settings_frame.pack(fill="x", expand=False, pady=(10, 0))

        is_masking_licensed = self.license_manager.is_feature_enabled("masked_ids")

        ttk.Label(doc_num_settings_frame, text="Define a mask for the 'Auto' number generator:").pack(anchor="w")
        
        # This entry correctly links to mask_string_var. There are NO save bindings.
        mask_entry_settings = ttk.Entry(doc_num_settings_frame, textvariable=self.mask_string_var)
        mask_entry_settings.pack(fill="x", pady=(5, 2))

        self.mask_sample_label = ttk.Label(doc_num_settings_frame, text="Sample: ...", bootstyle="secondary")
        self.mask_sample_label.pack(anchor="w")

        ttk.Label(doc_num_settings_frame, text="Placeholders: YYYY, YY, MM, DD, #### (number)", bootstyle="info", font="-size 8").pack(anchor="w", pady=(5,0))
        
        # This trace ONLY updates the UI sample, it does NOT save anything. This is safe.
        self.mask_string_var.trace_add("write", self._update_mask_sample_label)
        self._update_mask_sample_label() # Set initial sample text

        # Handle the license check
        if not is_masking_licensed:
            mask_entry_settings.config(state=DISABLED)
            self.mask_string_var.set("") # Clear the var to prevent use
            self.mask_sample_label.config(text="Sample: Pro license required")
            
          
  

    def create_guide_tab(self, parent_frame):
        import textwrap
        parent_frame.grid_columnconfigure(0, weight=1)
        parent_frame.grid_rowconfigure(0, weight=1)
        guide_text = ScrolledText(parent_frame, padding=(20, 20, 0, 20), hbar=False, autohide=True, wrap="word")
        guide_text.pack(fill="both", expand=True)
        inner_text_widget = guide_text.text
        inner_text_widget.tag_configure("h1", font="-size 14 -weight bold", spacing3=15)
        inner_text_widget.tag_configure("h2", font="-size 11 -weight bold", spacing1=20, spacing3=5)
        inner_text_widget.tag_configure("p", font="-size 10", lmargin1=10, lmargin2=10, spacing3=10)
        guide_content = [
            ("Day-to-Day LegatoKey Workflow\n", "h1"),
            ("Once you've created your legacy document (certificate, valuation letter, photos, etc.), follow these steps:", "p"),
            ("Step 1: Select your source image\n", "h2"),
            ("Choose your supporting image (photo of the instrument, a scan of the certificate letter). Its fingerprint will be linked to the LegatoKey.", "p"),
            ("Step 2: Write a short summary of your document\n", "h2"),
            ("""For example:\n-"We [Your Name] certify that the violin examined and reproduced on our certificate and its digital counterpart is, in our opinion, an instrument by [Name of the Maker], authentic in all its major parts and  measuring 35.5 cm."\n-"Valuation issued to Count Ignazio Alessandro Cozio di Salabue etc..."\nThis summary will be securely encrypted and embedded in the LegatoKey and cannot be changed.""", "p"),
            ("Step 3: Click 'Fingerprint, Sign & Save'\n", "h2"),
            ("This creates your secure LegatoKey (.lky) file and its corresponding QR code. If 'Automatic Upload' is enabled in Settings, the .lky file will upload to your web server automatically. If not, click the 'Upload LKey' button to send it manually.", "p"),
            ("Step 4: Print the LegatoKey\n", "h2"),
            ("You can now print the generated LegatoKey (QR code) onto a label, an envelope, or directly onto the physical document.", "p"),
        ]
        for text, tag in guide_content:
            for i, line in enumerate(textwrap.dedent(text).strip().splitlines()):
                inner_text_widget.insert("end", " ".join(line.split()), tag)
                if i < len(textwrap.dedent(text).strip().splitlines()) - 1:
                    inner_text_widget.insert("end", "\n")
            inner_text_widget.insert("end", "\n")

    def create_backup_and_security_tab(self, parent_frame):
        parent_frame.grid_columnconfigure((0, 1), weight=1, uniform="backup_cols")
        parent_frame.grid_rowconfigure(0, weight=1)
        left_column = ttk.Frame(parent_frame)
        left_column.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        
        hardened_security_frame = ttk.LabelFrame(left_column, text="💎 Hardened Security", padding=15)
        hardened_security_frame.pack(fill="x", pady=(0, 15), anchor="n")

        self.pro_security_checkbox = ttk.Checkbutton(hardened_security_frame, text="Enable Hardened Security (OS Keychain)", variable=self.hardened_security_var, bootstyle="primary-round-toggle", state="disabled", command=self.save_issuer_identity)
        self.pro_security_checkbox.pack(anchor="w", fill="x", pady=(5, 5))
        ttk.Label(hardened_security_frame, text="RECOMMENDED. Moves private key and FTP password to your OS's secure keychain.", wraplength=400, bootstyle="secondary").pack(anchor="w")
                
        right_column = ttk.Frame(parent_frame)
        right_column.grid(row=0, column=1, sticky="nsew", padx=(10, 0))
        practices_frame = ttk.LabelFrame(left_column, text="🔐 Security Best Practices", padding=15)
        practices_frame.pack(fill="x", pady=(0, 15), anchor="n")
        ttk.Label(practices_frame, text="⚠️ IMPORTANT BACKUP NOTICE", bootstyle="warning", font="-weight bold").pack(anchor="w")
        notice_label = ttk.Label(practices_frame, text="Your private key file (abracadabra...key) and your settings file (opn_czami_settings.json) are your digital identity. If you lose them, you lose the ability to create new LegatoKeys. You MUST create a secure, offline backup. ", justify="left")
        notice_label.pack(fill="x", anchor="w", pady=(2, 10))
        ttk.Label(practices_frame, text="Essential Security Rules", font="-weight bold").pack(anchor="w", pady=(5, 2))
        ttk.Label(practices_frame, text="• Guard Your Private Key: Treat it like a master password.\n• Never Share Key Files: Do not email or upload your private key file.\n• Regular Backups: You are responsible for maintaining secure backups.\n• Use Strong Passwords: Protect backup files with strong, unique passwords.", justify="left").pack(anchor="w", pady=2)
        practices_frame.bind("<Configure>", lambda e: self._update_wraplength(e, notice_label))
        backup_frame = ttk.LabelFrame(practices_frame, text="Create Secure Encrypted Backup", padding=15)
        backup_frame.pack(fill="x", pady=(10, 20), anchor="n")
        backup_frame.grid_columnconfigure(1, weight=1)
        ttk.Label(backup_frame, text="Backup Password:").grid(row=0, column=0, sticky="w", padx=(0, 10), pady=1)
        self.backup_pass_var = ttk.StringVar()
        self.backup_pass_entry = ttk.Entry(backup_frame, textvariable=self.backup_pass_var, show="*")
        self.backup_pass_entry.grid(row=0, column=1, sticky="ew", pady=5)
        self.backup_show_pass_var = ttk.BooleanVar(value=False)
        ttk.Checkbutton(backup_frame, text="Show", variable=self.backup_show_pass_var, bootstyle="toolbutton", command=lambda: self.backup_pass_entry.config(show="" if self.backup_show_pass_var.get() else "*")).grid(row=0, column=2, padx=5)
        self.create_backup_button = ttk.Button(backup_frame, text="📦 Create Secure Backup...", command=self.handle_create_backup)
        self.create_backup_button.grid(row=1, column=0, columnspan=3, sticky="ew", pady=1)
        if not PYZIPPER_AVAILABLE:
            self.backup_pass_entry.config(state="disabled")
            self.create_backup_button.config(state="disabled")
            ttk.Label(backup_frame, text="Requires 'pyzipper'", bootstyle="danger", font="-size 8").grid(row=2, column=0, columnspan=3)

        tech_security_frame = ttk.LabelFrame(right_column, text="🛡️ Built-in Security Features", padding=15)
        tech_security_frame.pack(fill="x", expand=False, anchor="n")
        security_features = [
            ("Industry-Standard Encryption", "All server communications use robust Transport Layer Security (TLS 1.2+) to protect data in transit."),
            ("Secure Credential Storage", "Your private key and passwords can be stored in the OS Keychain, never in plain text files, when Hardened Security is enabled."),
            ("Modern Cryptography", "Utilizes NIST-approved algorithms, including Ed25519 for digital signatures and SHA-256 for data integrity."),
            ("Local Key Processing", "Your private key never leaves your computer. All signing operations happen locally."),
            ("Tamper Detection", "Each LegatoKey includes a cryptographic signature that detects any unauthorized changes to its content and source image."),
            ("Audit Trail (Pro)", "When enabled, a blockchain-like audit file is created, logging each key creation. Any attempt to tamper with this evidence is detected and reported."),
        ]
        for i, (title, description) in enumerate(security_features):
            padding_top = 15 if i > 0 else 0
            item_frame = ttk.Frame(tech_security_frame)
            item_frame.pack(fill="x", anchor="w", pady=(padding_top, 0))
            ttk.Label(item_frame, text=title, font="-weight bold").pack(anchor="w", pady=(0, 2))
            desc_label = ttk.Label(item_frame, text=description, justify="left")
            desc_label.pack(fill="x", anchor="w", padx=(10, 0))
            item_frame.bind("<Configure>", lambda e, w=desc_label: self._update_wraplength(e, w))

    def create_about_tab(self, parent_frame):
        parent_frame.drop_target_register("DND_Files")
        parent_frame.dnd_bind("<<Drop>>", self.handle_license_drop)
        outer_container = ttk.Frame(parent_frame)
        outer_container.pack(fill="both", expand=True, padx=20, pady=20)
        header_frame = ttk.Frame(outer_container)
        header_frame.pack(fill="x", pady=(0, 15), anchor="n")
        ttk.Label(header_frame, text="Op’n-Czami", font="-size 24 -weight bold").pack()
        ttk.Label(header_frame, text="Legato-Key Certification Authority Dashboard", font="-size 12", bootstyle="secondary").pack(pady=(5, 0))
        ttk.Label(header_frame, text=f"Version {APP_VERSION}", font="-size 10", bootstyle="info").pack(pady=(10, 0))
        ttk.Separator(outer_container, orient="horizontal").pack(fill="x", pady=15)
        info_frame = ttk.Frame(outer_container)
        info_frame.pack(fill="x", pady=(0, 15), anchor="n")
        info_frame.grid_columnconfigure((0, 1, 2), weight=1, uniform="info_cols")
        info_frame.grid_rowconfigure(0, weight=1)
        description_frame = ttk.LabelFrame(info_frame, text="About This Application", padding=15)
        description_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        description_text = "Op'n Cezami is a professional-grade, open-source signing tool for creating tamper-proof, cryptographically signed digital certificates. Crafted by a luthier expert with a computer science background, every design choice reflects the real-world needs. Part of the Legato Key ecosystem for issuing linked physical + digital certificates that anyone can verify."
        description_label = ttk.Label(description_frame, text=description_text, justify="left")
        description_label.pack(fill="x")
        description_frame.bind("<Configure>", lambda e, w=description_label: self._update_wraplength(e, w))
        license_frame = ttk.LabelFrame(info_frame, text="Our Open Core License", padding=15)
        license_frame.grid(row=0, column=1, sticky="nsew", padx=(5, 5))
        license_text = "The core application is free and open-source (licensed under the LGPL), including for commercial use. However, certain advanced features require a Professional license. This hybrid model allows us to provide a powerful free tool while maintaining a sustainable project."
        open_source_license_label = ttk.Label(license_frame, text=license_text, justify="left")
        open_source_license_label.pack(fill="x")
        license_frame.bind("<Configure>", lambda e, w=open_source_license_label: self._update_wraplength(e, w))
        drop_zone_frame = ttk.LabelFrame(info_frame, text="✨ Professional License Status", padding=15)
        drop_zone_frame.grid(row=0, column=2, sticky="nsew", padx=(10, 0))
        self.drop_zone_label = ttk.Label(drop_zone_frame, font="-size 11", justify="center", anchor="center")
        self.drop_zone_label.pack(fill="both", expand=True, pady=10)
        self.update_pro_license_status_display()
        drop_zone_frame.bind("<Configure>", lambda e, w=self.drop_zone_label: self._update_wraplength(e, w))
        support_frame = ttk.LabelFrame(outer_container, text="Support & Contact", padding=15)
        support_frame.pack(fill="x", pady=(0, 15), anchor="n")
        support_text = "For technical support, feature requests, or security inquiries, please contact legato@ruederome.com"
        support_label = ttk.Label(support_frame, text=support_text, justify="left", wraplength=850)
        support_label.pack(fill="x")
        tech_info_frame = ttk.LabelFrame(outer_container, text="Technical Information", padding=15)
        tech_info_frame.pack(fill="x", pady=(0, 15), anchor="n")
        ttk.Label(tech_info_frame, text="Platform Support: Windows 10+, macOS 10.14+, Linux (Ubuntu 18.04+) | Image File Formats: JPEG, PNG | Batch File Formats: CSV, XLSX", justify="left", bootstyle="secondary").pack(anchor="w")
        footer_frame = ttk.Frame(outer_container)
        footer_frame.pack(fill="x", pady=(25, 0), side="bottom")
        footer_label = ttk.Label(footer_frame, text="© 2025 Frédéric Levi Mazloum. All rights reserved.", font="-size 8", bootstyle="secondary")
        footer_label.pack()

    # --- Event Handlers and UI Helpers ---
    def handle_license_drop(self, event):
        """Handles dropping a license file onto the 'About' tab."""
        filepath_str = event.data.strip("{}")
        dropped_path = Path(filepath_str)
        if dropped_path.name.lower() != "license.key":
            show_error("Invalid File", "Please drop a valid 'license.key' file.")
            return
        try:
            success = self.license_manager.activate_from_path(dropped_path)
            if success:
                show_info("Success!", f"Pro license for '{self.license_manager.customer_info}' activated.\nPlease restart the app to enable all features.")
            else:
                show_error("Activation Failed", f"The license key is invalid: {self.license_manager.customer_info}")
        except Exception as e:
            show_error("License Error", f"An error occurred during activation: {e}")
        finally:
            self.update_pro_license_status_display()
            
    def update_pro_license_status_display(self, event=None):
        if hasattr(self, 'pro_status_label'):
            if self.license_manager.is_licensed:
                self.pro_status_label.config(text=f"Pro License: {self.license_manager.customer_info}", bootstyle=SUCCESS)
                if hasattr(self, "drop_zone_label"):
                    features = ", ".join(sorted(list(self.license_manager.enabled_features))).title()
                    about_text = f"Features Activated: {features}\n\nDrag a new license file here to upgrade."
                    self.drop_zone_label.config(text=about_text, bootstyle=SUCCESS)
            else:
                self.pro_status_label.config(text="Pro License: Not Active", bootstyle=WARNING)
                if hasattr(self, "drop_zone_label"):
                    about_text = "To activate, drag and drop your 'license.key' file anywhere on this page."
                    self.drop_zone_label.config(text=about_text, bootstyle=INFO)
    
    def reset_upload_button_state(self):
        """Resets the upload button to its initial state."""
        self.upload_button_state = UploadButtonState.INITIAL
        self.update_upload_button_display()
        self.last_signed_payload = None
        self._hide_qr_action_buttons()
        return True

    def update_upload_button_display(self):
        """Updates the text, style, and state of the upload button."""
        if not hasattr(self, "upload_button"): return
        text, style, state = self.upload_button_state.value
        if self.config.ftp_auto_upload and self.upload_button_state == UploadButtonState.INITIAL:
            style = "success-outline"
        self.upload_button.config(text=text, bootstyle=style, state=state)

    def check_system_status(self):
        if not self.active_issuer_id: return
        self.system_is_verified = False
        self.check_status_button.config(state=DISABLED)
        self.status_message_label.config(text="Checking...", bootstyle=WARNING)
        self.status_details_label.config(text=f"Fetching: {self.active_issuer_data['infoUrl']}")
        self.set_status_logo(None)
        self.active_issuer_contact_info = {}
        self.update_manage_frame_display()
        threading.Thread(target=self._check_status_worker, daemon=True).start()

    def _check_status_worker(self):
        info_url = self.active_issuer_data["infoUrl"]
        def update_ui(msg, style, details=""):
            self.status_message_label.config(text=msg, bootstyle=style)
            self.status_details_label.config(text=details)
        try:
            response = requests.get(info_url, timeout=10)
            response.raise_for_status()
            online_data = response.json()
            
            priv_key = serialization.load_pem_private_key(self.active_issuer_data["priv_key_pem"].encode("utf-8"), password=None)
            local_pub_key_pem = priv_key.public_key().public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode("utf-8")
            
            if online_data.get("publicKeyPem") != local_pub_key_pem:
                self.root.after(0, update_ui, "❌ PUBLIC KEY MISMATCH!", DANGER, "Key on server differs from local key.")
                return

            self.active_issuer_contact_info = online_data.get("contactInfo", {})
            logo_pil = None
            if logo_url := online_data.get("logoUrl"):
                logo_pil = self._fetch_logo(logo_url)
            
            self.root.after(0, self.set_status_logo, logo_pil)
            self.root.after(0, update_ui, "✅ System Online & Verified", SUCCESS, "Public key is accessible and correct.")
            self.system_is_verified = True

        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
            # Catches DNS errors (gibberish websites), timeouts, and other connection issues.
            logging.error(f"System status check failed due to a connection error: {e}", exc_info=True)
            details = "Connection failed. Please check your internet connection and verify the server URL in your settings."
            self.root.after(0, update_ui, "⚠️ OFFLINE OR CONFIG ERROR!", DANGER, details)
        except requests.exceptions.RequestException as e:
            # General catch-all for other HTTP errors (like 404 Not Found, 500 Server Error)
            logging.error(f"System status check failed with an HTTP error: {e}", exc_info=True)
            details = f"The server returned an error. Please ensure the URL is correct and the server is running."
            self.root.after(0, update_ui, "⚠️ OFFLINE OR CONFIG ERROR!", DANGER, details)
        except (json.JSONDecodeError, KeyError) as e:
            logging.error(f"Failed to parse server response: {e}", exc_info=True)
            details = f"The '{INFO_FILENAME}' on your server appears to be missing or corrupt."
            self.root.after(0, update_ui, "⚠️ INVALID PUBLIC FILE!", DANGER, details)
            
        finally:
            if self.active_issuer_id:
                self.root.after(0, self.check_status_button.config, {'state': NORMAL})
            self.root.after(0, self.update_issuer_qr_display)
            self.root.after(0, self.update_manage_frame_display)

    def _fetch_logo(self, url: str) -> Union[Image.Image, None]:
        try:
            with requests.get(url, timeout=5, stream=True) as r:
                r.raise_for_status()
                image_data = io.BytesIO()
                downloaded_size = 0
                for chunk in r.iter_content(chunk_size=8192):
                    downloaded_size += len(chunk)
                    if downloaded_size > MAX_LOGO_SIZE_BYTES:
                        raise ValueError(f"Logo file exceeds {MAX_LOGO_SIZE_BYTES / 1024}KB limit.")
                    image_data.write(chunk)
                image_data.seek(0)
                return Image.open(image_data)
        except Exception as e:
            logging.error(f"Failed to fetch logo from {url}: {e}", exc_info=True)
            return None

if __name__ == "__main__":
    # --- Platform-specific setup ---
    if sys.platform == "win32":
        import ctypes
        from ctypes import windll
        try:
            # Set DPI awareness. This is crucial for modern displays.
            windll.shcore.SetProcessDpiAwareness(2) # For Windows 8.1+
        except (AttributeError, OSError):
            try:
                windll.user32.SetProcessDPIAware() 
            except Exception as e:
                # This is not critical, so we just log the error.
                logging.error(f"Could not set DPI awareness: {e}")
        
        # This ID helps Windows group the app's windows under one taskbar icon.
        myappid = "com.mazloumlevif.opnczami.v4.4.2.final" # Make it unique
        windll.shell32.SetCurrentProcessExplicitAppUserModelID(myappid)

    from tkinterdnd2 import DND_FILES, TkinterDnD

    class DndTtkWindow(ttk.Window, TkinterDnD.DnDWrapper):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.TkdndVersion = TkinterDnD._require(self)

    logging.info("================ Application Starting ================")
 
    root = DndTtkWindow(themename="litera")
    root.withdraw() 
    app = IssuerApp(root)
    if sys.platform == "win32":
        icon_path = resource_path("icon.ico")
        if icon_path.exists():
            try:
                root.iconbitmap(default=str(icon_path))
                from ctypes import windll
                root.update_idletasks()
                hwnd = windll.user32.GetParent(root.winfo_id())
                if hwnd:
                    ICON_SMALL = 0
                    ICON_BIG = 1
                    WM_SETICON = 0x0080
                    LR_LOADFROMFILE = 0x0010
                    h_icon_big = windll.user32.LoadImageW(None, str(icon_path), 1, 32, 32, LR_LOADFROMFILE)
                    if h_icon_big:
                        windll.user32.SendMessageW(hwnd, WM_SETICON, ICON_BIG, h_icon_big)
                    
                    h_icon_small = windll.user32.LoadImageW(None, str(icon_path), 1, 16, 16, LR_LOADFROMFILE)
                    if h_icon_small:
                        windll.user32.SendMessageW(hwnd, WM_SETICON, ICON_SMALL, h_icon_small)
                else:
                    logging.warning("Could not find window handle (HWND) to set taskbar icon.")
            except Exception as e:
                logging.error(f"Failed to set Windows taskbar icon: {e}", exc_info=True)

    root.deiconify()
    root.mainloop()

    logging.info("================ Application Closed ================\n")
