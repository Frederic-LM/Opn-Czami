# opn_czami_logic.py
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

# --- Dependencies Imports ---
import base64
import base45
import base58
import binascii
import cbor2
import datetime
import io
import json
import logging
import random
import shutil
import string
import threading
import zlib
from dataclasses import dataclass, field, asdict
from enum import Enum
from functools import lru_cache
from pathlib import Path
from typing import Union, Dict, Any, Tuple
from urllib.parse import urlparse, quote
import traceback
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils, ed25519
from PIL import Image
import requests
import pyzipper
from PIL import Image, UnidentifiedImageError
from ttkbootstrap.constants import*
import boto3
from botocore.exceptions import ClientError
from botocore.client import Config
# --- Local Application  ---

from models.exceptions import SettingsError, KeystoreError, FileAccessError, HashCalculationError, AuditLogError
from models.config import (
    ISSUER_DB_FILE, KEYRING_SERVICE_NAME, APP_DATA_DIR,
    INFO_FILENAME, KEY_FILENAME_TEMPLATE, MAX_LOGO_SIZE_BYTES,
    SCRIPT_DIR, APP_DOCS_DIR, FEATURE_WATERMARK, FEATURE_AUDIT,
    FEATURE_MASKED_IDS, FEATURE_BATCH, HTTP_TIMEOUT_LONG
)
from models.utils import resource_path, show_error, show_info
from models.settings_manager import SettingsManager
from models.ftp_manager import FTPManager
from models.crypto_manager import CryptoManager, KeyStorage
from models.krypto_knight import KryptoKnight
from models.license_manager import LicenseManager
from models.image_processor import ImageProcessor
from models.identity_manager import IdentityManager



# --- Pro Features Configuration ---

try:
    from pro_features import ProFeatures
    PRO_FEATURES_AVAILABLE = True
except ImportError:
    PRO_FEATURES_AVAILABLE = False
            # ---  WHEN LAMBO? MOCKUP-METHODS ---
    class ProFeatures:
        def __init__(self, app_instance):
            logging.warning("Pro features module not found. Pro functionality is disabled.")
            self.app = app_instance
            from models.utils import show_error as global_show_error
            self.show_error = global_show_error
            self.image_processor = type('MockImageProcessor', (object,), {
                'apply_text_watermark': lambda self, *args, **kwargs: args[0],
                'apply_logo_watermark': lambda self, *args, **kwargs: args[0]
            })() 

        def load_data_file_threaded(self, *args, **kwargs): pass
        def process_batch_threaded(self, *args, **kwargs): pass
        def load_and_verify_audit_log(self, *args, **kwargs):
            DANGER = "danger"
            return [], False, "Pro features are not available.", DANGER
        def log_audit_event(self, event_type: str, details: dict):
            logging.warning(f"Mock ProFeatures: Ignoring audit event '{event_type}'")
            pass
        def check_blockchain_registration_threaded(self, *args, **kwargs): pass
        def check_ipfs_link_threaded(self, *args, **kwargs): pass
        def register_id_on_blockchain_threaded(self, *args, **kwargs): pass
        def mock_start_purchase_flow(self, ui_callback_for_progress):
            """Mock method for purchase when the license/module is missing."""
            self.show_error(
                "License Required", 
              
            )
            ui_callback_for_progress.on_polling_failure("License module missing or not enabled.")


class FTPMode(Enum):
    MANUAL = "Manual"
    AUTOMATIC = "Automatic"

class UploadButtonState(Enum):
    INITIAL = ("🚀 Upload LKey", SECONDARY, "disabled")
    READY = ("🚀 Upload LKey", PRIMARY, "normal")
    UPLOADING = ("Uploading...", WARNING, "disabled")
    SUCCESS = ("Upload Successful!", SUCCESS, "normal")
    FAILURE = ("Upload Failed! (Retry)", DANGER, "normal")

class FormState(Enum):

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
    doc_num_mask: str = "####-MM/YYYY"
    legato_files_save_path: str = ""
    ftp_host: str = ""
    ftp_user: str = ""
    ftp_path: str = ""
    ftp_pass_b64: str = ""
    ftp_auto_upload: bool = False
    hardened_security: bool = False
    enable_audit_trail: bool = False
    doc_num_mask: str = "####-MM/YY"
    web3_anchor_enabled: bool = False 
    last_auto_inc_num: int = 0
    check_for_updates: bool = True

    def __post_init__(self):
        """Set default save path if it is not provided."""
        if not self.legato_files_save_path:
            self.legato_files_save_path = str(APP_DOCS_DIR / "Legato_Keys")
    @classmethod
    def from_issuer_data(cls, data: dict, hardened_security: bool) -> 'AppConfig':
        s = data.get("settings", {})
        ftp = s.get("ftp_settings", {})
        
        return cls(
            randomize_lkey_name=s.get("randomize_lkey_name", False),
            apply_watermark=s.get("apply_watermark", False),
            apply_logo_watermark=s.get("apply_logo_watermark", False),
            watermark_text=s.get("watermark_text") or "SIGNED",
            doc_num_mask=s.get("doc_num_mask") or "####-MM/YYYY",
            legato_files_save_path=s.get("legato_files_save_path"), 
            ftp_host=ftp.get("host", ""),
            ftp_user=ftp.get("user", ""),
            ftp_path=ftp.get("path", ""),
            ftp_pass_b64=ftp.get("pass_b64", ""),
            ftp_auto_upload=(ftp.get("mode") == FTPMode.AUTOMATIC.value),
            hardened_security=hardened_security,
            enable_audit_trail=s.get("enable_audit_trail", False),
            web3_anchor_enabled=s.get("web3_anchor_enabled", False),
            last_auto_inc_num=s.get("auto_increment_last_num", 0),
            check_for_updates=s.get("check_for_updates", True) 
        )

    def to_db_dict(self) -> dict:
        """Converts AppConfig instance to the nested dictionary format for the DB."""
        ftp_settings = {
            "host": self.ftp_host,
            "user": self.ftp_user,
            "path": self.ftp_path,
            "mode": FTPMode.AUTOMATIC.value if self.ftp_auto_upload else FTPMode.MANUAL.value,
        }
        
        if not self.hardened_security:
            ftp_settings["pass_b64"] = self.ftp_pass_b64

        return {
            "randomize_lkey_name": self.randomize_lkey_name,
            "apply_watermark": self.apply_watermark,
            "apply_logo_watermark": self.apply_logo_watermark,
            "watermark_text": self.watermark_text,
            "legato_files_save_path": self.legato_files_save_path,
            "enable_audit_trail": self.enable_audit_trail,
            "auto_increment_last_num": self.last_auto_inc_num,
            "doc_num_mask": self.doc_num_mask,
            "web3_anchor_enabled": self.web3_anchor_enabled,
            "check_for_updates": self.check_for_updates,
            "ftp_settings": ftp_settings,
        }

class OpnCzamiLogic:
    """
    The GUI-agnostic core logic for OpnCzami.
    Single source of truth for state, crypto, and business rules..
    """
    
    def __init__(self, ui_callback_interface: object):
        self.ui_callback = ui_callback_interface 
        self.settings_manager = SettingsManager(ISSUER_DB_FILE)
        self.crypto_manager = CryptoManager(KEYRING_SERVICE_NAME, APP_DATA_DIR)
        self.identity_manager = IdentityManager(self.crypto_manager, self.settings_manager)
        self.image_processor = ImageProcessor(resource_path("checkmark.png"))
        self.ftp_manager = FTPManager()
        self.license_manager = LicenseManager(SCRIPT_DIR, APP_DATA_DIR)
        self.pro_handler = ProFeatures(self)
        self._temp_ftp_password: str = ""
        self.config: AppConfig = AppConfig()
        self.active_issuer_id: Union[str, None] = None
        self.active_issuer_data: Dict[str, Any] = {}
        self.all_issuer_data: Dict[str, Any] = {}
        self.system_is_verified: bool = False
        self.generation_lock = threading.Lock()
        self.prepared_upload_path: Union[Path, None] = None
        self.last_signed_payload: Union[str, None] = None
        self.lkey_image_pil: Union[Image.Image, None] = None
        self.qr_image_pil: Union[Image.Image, None] = None
        self.issuer_qr_image_pil: Union[Image.Image, None] = None
        self.original_status_logo_pil: Union[Image.Image, None] = None
        self.active_issuer_contact_info: Dict[str, str] = {}
        self._initial_status_check_fired: bool = False
        self._web3_status_checked_this_session: bool = False
        self.krypto_knight = KryptoKnight(self.crypto_manager)

    # --- Initialization ---
    # FTP
    def get_ftp_password_for_display(self) -> str:
        """Safe Decodes the FTP password for UI display. Returns "" if missing or corrupt"""
        if self.config.hardened_security and self.active_issuer_id:
            return self._get_active_ftp_password_from_config() or ""

        if not self.config.ftp_pass_b64:
            return ""

        try:
            return base64.b64decode(self.config.ftp_pass_b64).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError) as e:
            logging.warning(f"Invalid base64 in FTP password: {e}")
            return ""
    
    def get_ftp_settings_for_connection(self) -> Union[dict, None]:
        password = self._temp_ftp_password
        
        if not password:
            password = self._get_active_ftp_password_from_config()

        if password is None:
            logging.error("Failed to retrieve FTP password for connection.")
            return None
            
        if not all([self.config.ftp_host, self.config.ftp_user, password]):
            logging.warning("FTP settings are incomplete.")
            return None

        return {"host": self.config.ftp_host, "user": self.config.ftp_user, "password": password}
        

    def load_initial_data(self):
        self._load_issuer_data()
        
        has_identity = bool(self.active_issuer_id)
        
        if has_identity:
            self.ui_callback.on_logic_data_loaded(True)

        else:
            self.ui_callback.on_logic_data_loaded(False)
            
        self.ui_callback.update_pro_license_status_display()


    def on_legacy_anchor_activation_failure(self, error_message: str):
        """
        Callback for when the ProFeatures handler fails to activate an anchor.
        """
        self.ui_callback.on_legacy_anchor_complete(False, error_message)

    def _legacy_anchor_activation_worker(self):
        """
        The background job that sends the license key to the backend, creating the anchor.
        """
        try:

            raw_license_key = self.license_manager.get_raw_license_key()
            if not raw_license_key:
                raise Exception("Could not read the local license.key file.")

            encoded_url = b'aHR0cHM6Ly9sZWdhdG8ucnVlZGVyb21lLmNvbS9hY3RpdmF0ZV9hbmNob3IucGhw'
            backend_url = base64.b64decode(encoded_url).decode('utf-8')
            payload = {'license_key': raw_license_key}

            response = requests.post(backend_url, data=payload, timeout=HTTP_TIMEOUT_LONG)
            response.raise_for_status() 
            
            data = response.json()
            ipfs_cid = data.get("ipfs_cid")

            if not ipfs_cid:
                error_msg = data.get("error", "The server did not return a valid IPFS CID.")
                raise Exception(error_msg)

            logging.info(f"Successfully received legacy anchor CID: {ipfs_cid}")
            self.active_issuer_data["ipfsCid"] = ipfs_cid
            
            local_public_file_path = APP_DATA_DIR / INFO_FILENAME
            if local_public_file_path.exists():
                local_data = json.loads(local_public_file_path.read_text(encoding="utf-8"))
                local_data["ipfsCid"] = ipfs_cid
                local_public_file_path.write_text(json.dumps(local_data, indent=2), encoding="utf-8")
            
            self.config.web3_anchor_enabled = True
            self._save_current_config_to_db()

            self.ui_callback.on_legacy_anchor_complete(True, "Anchor successfully activated!")

        except Exception as e:
            logging.error(f"Legacy anchor activation failed: {e}", exc_info=True)
            self.ui_callback.on_legacy_anchor_complete(False, f"Activation failed: {e}")
        
    def reload_data_and_update_ui(self):
        self._load_issuer_data()
        self.ui_callback.update_ui_state()

    def _load_issuer_data(self):
        try:
            self.active_issuer_id, data = self.settings_manager.load_app_data()
        except SettingsError as e:
            show_error("DB Load Error", str(e))
            self.active_issuer_data = None
            return

        if not self.active_issuer_id or not data:
            self.active_issuer_data = None
            logging.info("No active issuer found.")
            return

        logging.info(f"Loading data for issuer ID: {self.active_issuer_id}")
        try:
            self.all_issuer_data = json.loads(ISSUER_DB_FILE.read_text(encoding="utf-8")) if ISSUER_DB_FILE.exists() else {}
        except (IOError, json.JSONDecodeError):
            self.all_issuer_data = {}
            logging.warning("Could not load or parse issuer DB file.")
            
        self.active_issuer_data = self.all_issuer_data.get(self.active_issuer_id, data).copy()

        local_public_file_path = APP_DATA_DIR / INFO_FILENAME
        stored_cid = None
        try:
            if local_public_file_path.exists():
                local_public_data = json.loads(local_public_file_path.read_text(encoding="utf-8"))
                stored_cid = local_public_data.get("ipfsCid")
                if stored_cid:
                    self.active_issuer_data["ipfsCid"] = stored_cid
                    logging.info(f"Found local IPFS anchor '{stored_cid}'. Loading for UI state.")
        except (IOError, json.JSONDecodeError) as e:
            logging.warning(f"Could not read local public file for IPFS anchor: {e}")

        # --- Sync IPFS CID from the license file (aka "Option C") ---
        if self.license_manager.is_feature_enabled("web3"):
            license_cid = self.license_manager.ipfs_cid
            
            # If the license provides a CID and it's different from what's stored locally, update it.
            if license_cid and license_cid != stored_cid:
                logging.info(f"Found new IPFS CID '{license_cid}' in license file. Syncing local state.")
                self.active_issuer_data["ipfsCid"] = license_cid
                
                try:
                    if local_public_file_path.exists():
                        local_data = json.loads(local_public_file_path.read_text(encoding="utf-8"))
                        local_data["ipfsCid"] = license_cid
                        local_public_file_path.write_text(json.dumps(local_data, indent=2), encoding="utf-8")
                    
                    self.config.web3_anchor_enabled = True
                    self._save_current_config_to_db()
                except Exception as e:
                    logging.error(f"Failed to persist synced IPFS CID: {e}")

  
        key_loc = self.active_issuer_data.get("priv_key_pem")
        hardened_security = (key_loc == KeyStorage.KEYSTORE.value)
        key_path = APP_DATA_DIR / KEY_FILENAME_TEMPLATE.format(issuer_id=self.active_issuer_id)
    
        try:
            key = self.crypto_manager.get_private_key(key_loc, self.active_issuer_id, key_path)
        except (KeystoreError, FileAccessError) as e:
            show_error("Fatal Identity Error", str(e))
            self.active_issuer_data = None
            return

        if not key:
            self.active_issuer_data = None
            return
        key_loc = self.active_issuer_data.get("priv_key_pem")
        hardened_security = (key_loc == KeyStorage.KEYSTORE.value)
        self.config = AppConfig.from_issuer_data(self.active_issuer_data, hardened_security)
        self.ui_callback.sync_ui_from_config(self.config, None)
        if self.active_issuer_id and not self._initial_status_check_fired:
            self._initial_status_check_fired = True # Set the flag
            self.check_system_status_threaded()
        if self.active_issuer_id:
            self.check_system_status_threaded()
                
    def _save_current_config_to_db(self):
        """Internal helper to save just the current config state to the database."""
        if self.active_issuer_id in self.all_issuer_data:
            db_settings = self.config.to_db_dict()
            self.all_issuer_data[self.active_issuer_id]["settings"] = db_settings
            try:
                self.settings_manager.save_app_data(self.all_issuer_data)
                logging.info("Current configuration saved to database.")
            except SettingsError as e:
                show_error("DB Save Error", str(e))   
                   
    # --- Config and Persistence ---
    
    def sync_and_save_settings(self, ui_config_data: dict, ftp_password: str):
        """
        Updates the internal config from UI data and writes it to the database.
        """
        if not self.active_issuer_id:
            return

        self.config.ftp_host = ui_config_data.get("ftp_host", "").strip()
        self.config.ftp_user = ui_config_data.get("ftp_user", "").strip()
        ftp_path_from_ui = ui_config_data.get("ftp_path", "").strip()
        self.config.ftp_path = ftp_path_from_ui or "/"
        self.config.hardened_security = ui_config_data.get("hardened_security", False)
        self.config.watermark_text = ui_config_data.get("watermark_text", "").strip()
        self.config.legato_files_save_path = ui_config_data.get("legato_files_save_path", "")
        self.config.enable_audit_trail = ui_config_data.get("enable_audit_trail", False)
        self.config.ftp_auto_upload = ui_config_data.get("ftp_auto_upload", False)
        self.config.apply_watermark = ui_config_data.get("apply_watermark", False)
        self.config.apply_logo_watermark = ui_config_data.get("apply_logo_watermark", False)
        self.config.randomize_lkey_name = ui_config_data.get("randomize_lkey_name", False)
        self.config.doc_num_mask = ui_config_data.get("doc_num_mask", "")
        self.config.check_for_updates = ui_config_data.get("check_for_updates", True)

        if not self.config.hardened_security:

            if ftp_password:
                self.config.ftp_pass_b64 = base64.b64encode(ftp_password.encode("utf-8")).decode("utf-8")

        else:

            self.config.ftp_pass_b64 = ""

        filebase_creds = ui_config_data.pop("filebase_creds", {})
        if filebase_creds:
            self.crypto_manager.save_filebase_credentials(
                self.active_issuer_id,
                filebase_creds.get("key", ""),
                filebase_creds.get("secret", "")
            )
            # Also save the non-sensitive bucket name to the main settings DB
            if "settings" not in self.all_issuer_data.get(self.active_issuer_id, {}):
                self.all_issuer_data[self.active_issuer_id]["settings"] = {}
            self.all_issuer_data[self.active_issuer_id]["settings"]["filebase_bucket"] = filebase_creds.get("bucket", "")
        
        db_settings = self.config.to_db_dict()
        
        if self.active_issuer_id in self.all_issuer_data:
            self.all_issuer_data[self.active_issuer_id]["settings"].update(db_settings) # Use update to merge
            try:
                self.settings_manager.save_app_data(self.all_issuer_data)
                logging.info("Settings saved successfully to the database.")
            except SettingsError as e:
                show_error("Database Save Error", str(e))



    def handle_identity_creation(self, name: str, url_path: str, image_base_url: str, logo_path: Union[Path, None], contact_info: dict):
        """UI request to create a new identity."""
        success, result, new_data = self.identity_manager.create_and_save_identity(
            name, url_path, image_base_url, logo_path, contact_info
        )

        if not success:
            self.ui_callback.on_identity_creation_failed(result)
            return
        
        issuer_id = result
        real_key = new_data.pop('real_priv_key_pem') 
        
        self.all_issuer_data[issuer_id] = new_data
        self.active_issuer_id = issuer_id
        self.active_issuer_data = {**new_data, "priv_key_pem": real_key}
        
        # Guess FTP host and save initial config
        final_ftp_guess = ""
        try:
            parsed_url = urlparse(url_path)
            hostname = parsed_url.hostname
            if hostname:
                base_domain = hostname[4:] if hostname.lower().startswith("www.") else hostname
                final_ftp_guess = f"ftp.{base_domain}"
        except Exception: pass
        
        # Create a temporary config object to sync and save
        temp_config = AppConfig(ftp_host=final_ftp_guess, hardened_security=False)
        self.sync_and_save_settings(asdict(temp_config), "")
        self.config = temp_config # Update internal config
            
        self.ui_callback.on_identity_creation_success(issuer_id, self.config, final_ftp_guess)

    def handle_identity_deletion(self):
        """UI request to delete the active identity."""
        if not self.active_issuer_id: return
        
        success, message = self.identity_manager.delete_active_identity(self.active_issuer_id)
        
        if success:
            # Reset internal state
            self.active_issuer_id = None
            self.active_issuer_data = {}
            self.all_issuer_data = {}
            self.config = AppConfig()
            self.ui_callback.on_identity_deleted()
        else:
            show_error("Deletion Failed", message)

    def handle_toggle_hardened_security(self, enable_security: bool, ftp_password: str):
        """Moves the private data between DB And OS on hardened security."""
        success, result = self.identity_manager.toggle_hardened_security(
            enable_security,
            self.active_issuer_id,
            self.active_issuer_data.get("priv_key_pem"),
            ftp_password
        )
        
        if success:
            new_key_location = result
            self.all_issuer_data[self.active_issuer_id]["priv_key_pem"] = new_key_location
            self.config.hardened_security = enable_security
            # Retrieve latest UI data (excluding the password which is handled here)
            ui_config_data = self.ui_callback.get_ui_config_data()
            ui_config_data.pop("ftp_password", None)
            self.sync_and_save_settings(ui_config_data, ftp_password)
            show_info("Success", "Security settings updated successfully.")
            self.reload_data_and_update_ui()
        else:
            show_error("Security Operation Failed", f"{result}\n\nReverting the change.")
            # We must trigger a UI state update to revert the checkbox
            self.ui_callback.update_ui_state()
    

    # --- Document Signing ---

    def get_document_number(self, doc_num_manual: str, use_doc_num: bool, auto_gen: bool) -> Union[str, None]:
        """Returns the final document number from either user input or the auto-gen."""
        if not use_doc_num:
            return None
        
        doc_num = ""
        is_masking_licensed = self.license_manager.is_feature_enabled(FEATURE_MASKED_IDS)
        mask_is_defined = self.config.doc_num_mask.strip()

        if auto_gen:
            if is_masking_licensed and mask_is_defined:
                doc_num = self._apply_number_mask(self.config.doc_num_mask)
            else:
                doc_num = self._get_next_auto_doc_num_str()
            self.update_auto_inc_num() # Increment and save immediately
        else:
            doc_num = doc_num_manual.strip()

        return doc_num or None
        
    def generate_document_qr_threaded(self, image_path: Path, message: str, doc_num_manual: str, use_doc_num: bool, auto_gen: bool):
        """Lanch document signing job in a background thread."""
        if not image_path: return
        if not self.generation_lock.acquire(blocking=False):
            logging.warning("Generation process is already running. Ignoring new request.")
            return
        try:
            self.ui_callback.on_signing_start()

            details = { "m": message.strip() }
            doc_num = self.get_document_number(doc_num_manual, use_doc_num, auto_gen)
            if doc_num:
                details["n"] = doc_num
            threading.Thread(target=self._sign_single_document_worker, 
                            args=(image_path, details), 
                            daemon=True).start()
        except Exception as e:
            self.generation_lock.release()
            logging.error(f"Failed to start signing thread: {e}")

    def _sign_single_document_worker(self, image_path: Path, details: Dict[str, str]):
        """ 'Fingerprint, Sign & Save' process."""
        try:
   
            is_successful_signing, upload_performed_and_successful, result_message, final_image = self._sign_single_document(image_path, details)

            if is_successful_signing:
                image_with_overlay = self.image_processor.overlay_checkmark(final_image)

                self.ui_callback.on_signing_success(
                    self.prepared_upload_path,
                    self.qr_image_pil, 
                    self.last_signed_payload, 
                    upload_performed_and_successful,
                    image_with_overlay 
                )
            else:
                self.ui_callback.on_signing_failure(result_message)

        except Exception as e:
            logging.error(f"Error in document generation worker: {e}", exc_info=True)
            self.ui_callback.on_signing_failure(f"An unexpected error occurred: {e}")
        finally:
            self.generation_lock.release()

        
    def _sign_single_document(self, image_path: Path, details: dict) -> Tuple[bool, bool, str, Union[Image.Image, None]]:
            """
            Core logic for signing.
            Returns -> (signing_success, upload_success_if_attempted, message, final_PIL_image)
            """
            try:
                # --- 1. PREPARATION & VALIDATION ---
                self._ensure_active_issuer_and_key()
                final_lkey_image, image_bytes = self._prepare_image_for_signing(image_path)
                upload_filename_stem = self._generate_filename_stem(image_path)
                final_lkey_filename = f"{upload_filename_stem}.lky"

                # --- 2. LKY FILE ASSEMBLY (In Memory) ---
                data_to_sign_lky, lky_payload_dict, lky_payload_bytes = self._build_lky_data_to_sign(image_bytes, final_lkey_filename, details)
                lky_file_bytes = self._assemble_lky_binary(data_to_sign_lky, image_bytes, lky_payload_dict, lky_payload_bytes)

                # --- 3. SAVE LKY & CALCULATE HASH (Critical Order) ---
                temp_dir, prepared_upload_path = self._save_lky_to_temp_location(final_lkey_filename, lky_file_bytes)
                full_file_hash_hex = self.crypto_manager.calculate_file_hash(prepared_upload_path)
                
                # --- 4. CR8 QR CODE(Using the final hash) ---
                final_qr_data = self._build_and_sign_qr_payload(upload_filename_stem, full_file_hash_hex, details)
                self.qr_image_pil = self._generate_qr_image(final_qr_data)
                
                # --- 5. SAVE & STATE UPDATE ---
                self._finalize_local_save(prepared_upload_path, self.qr_image_pil)
                self._update_internal_state_after_signing(prepared_upload_path, full_file_hash_hex, details)
                
                # --- 6. AUDIT & AUTO-UPLOAD ---
                self._log_signing_event(final_lkey_filename, lky_payload_dict, full_file_hash_hex)
                upload_success, upload_msg = self._handle_auto_upload(prepared_upload_path)
                
                if self.config.ftp_auto_upload and not upload_success:
                    return False, False, f"Auto-upload failed: {upload_msg}", final_lkey_image
                    
                return True, upload_success, "LKey signed and processed successfully.", final_lkey_image

            except (ValueError, KeystoreError) as e:
                logging.error(f"Pre-signing validation failed: {e}", exc_info=True)
                return False, False, str(e), None
            except Exception as e:
                logging.error(f"Error during document signing: {e}", exc_info=True)
                return False, False, f"Signing failed due to an unexpected error: {e}", None
        
# --- Helpers for sign method ---

    def _ensure_active_issuer_and_key(self):
        """Preflight check for Issuer ID or its private key."""
        if not self.active_issuer_id:
            raise ValueError("No active issuer identity loaded.")
        if not self.active_issuer_data.get("priv_key_pem"):
            raise KeystoreError("Private key is unavailable for the active issuer.")

    def _prepare_image_for_signing(self, image_path: Path) -> Tuple[Image.Image, bytes]:
        """Loads, processes (watermarks), and returns the final image."""
        source_image = Image.open(image_path)
        processed_image = source_image
        
        if self.config.apply_watermark or self.config.apply_logo_watermark:
            if self.license_manager.is_feature_enabled(FEATURE_WATERMARK) and PRO_FEATURES_AVAILABLE:
                if self.config.apply_watermark:
                    processed_image = self.pro_handler.image_processor.apply_text_watermark(processed_image, self.config.watermark_text)
                if self.config.apply_logo_watermark:
                    processed_image = self.pro_handler.image_processor.apply_logo_watermark(processed_image, self.original_status_logo_pil)
    
        final_image = processed_image.convert("RGB")
        image_buffer = io.BytesIO()
        final_image.save(image_buffer, format="JPEG", quality=95)
        return final_image, image_buffer.getvalue()

    def _generate_filename_stem(self, image_path: Path) -> str:
        """Creates the base filename for the lky and QR"""
        sanitized_base = self._sanitize_filename(image_path.stem)
        suffix = f"-{''.join(random.choices(string.ascii_lowercase + string.digits, k=4))}" if self.config.randomize_lkey_name else ""
        return f"{sanitized_base}{suffix}"

    def _build_lky_data_to_sign(self, image_bytes: bytes, filename: str, details: dict) -> Tuple[bytes, dict, bytes]:
        """Builds the raw image and JSON payload to be signed for the LKY."""
        lky_payload_dict = {
            "imgId": filename, "message": details.get("m"),
            "docDate": datetime.date.today().isoformat(), "docNumber": details.get("n"),
        }
        lky_payload_dict = {k: v for k, v in lky_payload_dict.items() if v is not None}
        lky_payload_bytes = json.dumps(lky_payload_dict, separators=(",", ":")).encode("utf-8")
        data_to_sign = image_bytes + lky_payload_bytes
        return data_to_sign, lky_payload_dict, lky_payload_bytes


    def _assemble_lky_binary(self, data_to_sign: bytes, image_bytes: bytes, lky_payload_dict: dict, lky_payload_bytes: bytes) -> bytes:
        """Signs the payload and assembles the final binary LKY """
        key_location = self.active_issuer_data.get("priv_key_pem")
        # use the Knight, ask for Base58
        signature_b58 = self.krypto_knight.sign(
            self.active_issuer_id, key_location, data_to_sign, encode='b58'
            )
    
        manifest_dict = {
            "signature": signature_b58,
            "issuerId": self.active_issuer_id,
            "imageLength": len(image_bytes),
            "payloadLength": len(lky_payload_bytes),
            "imageMimeType": "image/jpeg",
        }
        return self.crypto_manager.assemble_lky_file(image_bytes, lky_payload_dict, manifest_dict)

    def _save_lky_to_temp_location(self, filename: str, lky_bytes: bytes) -> Tuple[Path, Path]:
        """Saves the LKY to a temporary directory for hashing."""
        temp_dir = APP_DATA_DIR / "temp_upload"
        temp_dir.mkdir(exist_ok=True, parents=True)
        temp_path = temp_dir / filename
        temp_path.write_bytes(lky_bytes)
        return temp_dir, temp_path

    def _build_and_sign_qr_payload(self, filename_stem: str, file_hash_hex: str, details: dict) -> str:
        """Builds and signs the QR payload using CBOR/ZLIB/B45"""
        hash_bytes = bytes.fromhex(file_hash_hex)
        qr_payload_dict = {"i": filename_stem, "h": hash_bytes, **details}
        qr_payload_bytes = cbor2.dumps(qr_payload_dict)
        compressor = zlib.compressobj(level=9, wbits=-15)
        qr_compressed_bytes = compressor.compress(qr_payload_bytes) + compressor.flush()
        key_location = self.active_issuer_data.get("priv_key_pem")
        qr_signature_bytes = self.krypto_knight.sign(
            self.active_issuer_id, key_location, qr_compressed_bytes, encode='raw'
        )
        binary_to_encode = qr_compressed_bytes + qr_signature_bytes
        payload_b45 = base45.b45encode(binary_to_encode).decode('ascii')
        return f"{self.active_issuer_id.upper()}:{payload_b45}"

    def _generate_qr_image(self, qr_data: str) -> Image.Image:
        doc_logo_path = resource_path("legatokey.png")
        document_logo_pil = Image.open(doc_logo_path) if doc_logo_path.exists() else None
        return self.image_processor.generate_qr_with_logo(qr_data, document_logo_pil, sizing_ratio=0.39)

    def _finalize_local_save(self, temp_lky_path: Path, qr_image: Image.Image):
        """Moves the temp LKY and saves the QR image to target folder."""
        now = datetime.datetime.now()
        local_save_dir = Path(self.config.legato_files_save_path) / f"{now.year}" / f"{now.month:02d}"
        local_save_dir.mkdir(parents=True, exist_ok=True)
        
        # Move LKY from temp to final destination
        shutil.copy(temp_lky_path, local_save_dir / temp_lky_path.name)
        
        # Save QR
        qr_save_path = local_save_dir / f"{temp_lky_path.stem}-QR.png"
        qr_image.save(qr_save_path)

    def _update_internal_state_after_signing(self, lky_path: Path, file_hash: str, details: dict):
        """Prepares the app state for post-signing actions like manual uploads."""
        self.prepared_upload_path = lky_path
        self.last_signed_payload = f"{lky_path.name}|{details.get('m','')}|{file_hash}"

    def _log_signing_event(self, filename: str, payload_dict: dict, file_hash: str):
        """Does audit trail logging if enabled."""
        if self.config.enable_audit_trail and self.license_manager.is_feature_enabled(FEATURE_AUDIT):
            log_details = {"filename": filename, "details": payload_dict, "file_hash": file_hash}
            self.pro_handler.log_audit_event("SIGN_UNIFIED_SUCCESS", log_details)

    def _handle_auto_upload(self, lky_path: Path) -> Tuple[bool, str]:
        if self.config.ftp_auto_upload:
            return self.upload_lkey_file(lky_path)
        return False, "Auto-upload not enabled."

        


    def upload_lkey_file(self, local_path: Path) -> tuple[bool, str]:
        """Uploads a single LKey file to the FTP server."""
        
        # 1. Get Settings (still needs to happen here as it involves credential retrieval)
        ftp_settings = self.get_ftp_settings_for_connection()
        if not ftp_settings:
            return False, "FTP settings are incomplete or password is missing."

        # 2. Delegate Path Calculation
        is_success, remote_dir, error_msg = self.ftp_manager.calculate_remote_path(
            ftp_root=self.config.ftp_path,
            image_base_url=self.active_issuer_data.get("imageBaseUrl", "")
        )
        if not is_success:
            show_error("Configuration Error", error_msg) # Displa security/config error to the user
            return False, error_msg
            
        # 3. Delegate File Upload
        is_success, result_msg = self.ftp_manager.upload_file(local_path, remote_dir, local_path.name, ftp_settings)

        # The audit trail logic (core state)
        if self.config.enable_audit_trail and self.license_manager.is_feature_enabled(FEATURE_AUDIT):
            event_type = "UPLOAD_SUCCESS" if is_success else "UPLOAD_FAILURE"
            details = {"filename": local_path.name, "result_message": result_msg}
            try:
                self.pro_handler.log_audit_event(event_type, details)
            except Exception as e:
                logging.error(f"Failed to log upload event to audit trail: {e}")
    
        return is_success, result_msg

        
    def upload_public_files(self) -> tuple[bool, str]:
        """Uploads the public `my-legato-link.json` and logo to issuer's server"""
        if not self.active_issuer_id:
            return False, "No active issuer."

        ftp_settings = self.get_ftp_settings_for_connection()
        if not ftp_settings:
            return False, "FTP settings are incomplete or missing credentials."

        try:
            # 1. Resolve remote directory
            remote_dir = self._resolve_remote_dir_from_info_url()
            if not remote_dir:
                return False, "Could not guess remote upload directory from infoUrl."

            # 2. Prepare local file paths
            json_path = APP_DATA_DIR / INFO_FILENAME
            logo_path = self._get_local_logo_path()

            # 3. Upload JSON (mandatory)
            ok, msg = self._upload_with_logging(json_path, remote_dir, ftp_settings)
            if not ok:
                return False, f"Public info upload failed: {msg}"

            # 4. Upload logo (optional)
            if logo_path:
                ok, msg = self._upload_with_logging(logo_path, remote_dir, ftp_settings)
                if not ok:
                    return False, f"Logo upload failed: {msg}"

            return True, "Public files uploaded successfully."

        except FileNotFoundError as e:
            logging.warning(f"Public file not found: {e}")
            return False, f"Missing required file: {e}"
        except PermissionError:
            msg = f"Permission denied while accessing files in {APP_DATA_DIR}."
            logging.error(msg)
            return False, msg
        except Exception as e:
            logging.error(f"Unexpected error during public file upload: {e}", exc_info=True)
            return False, f"Unexpected error during public file upload: {e}"


    # --- FTP Helpers ---

    def _resolve_remote_dir_from_info_url(self) -> Union[str, None]:
        """Calculates the correct remote FTP directory based on the issuer's public infoURL"""
        try:
            ftp_root = self.config.ftp_path.strip()
            info_url_path = urlparse(self.active_issuer_data["infoUrl"]).path
            remote_suffix = Path(info_url_path).parent.as_posix()
            return (Path(ftp_root) / remote_suffix.lstrip('/\\')).as_posix()
        except Exception as e:
            logging.error(f"Failed to resolve remote directory: {e}")
            return None


    def _get_local_logo_path(self) -> Union[Path, None]:

        logo_filename = Path(self.active_issuer_data.get("logoUrl", "")).name
        logo_path = APP_DATA_DIR / logo_filename
        return logo_path if logo_filename and logo_path.exists() else None


    def _upload_with_logging(self, local_path: Path, remote_dir: str, ftp_settings: dict) -> tuple[bool, str]:
        """Wraps FTP upload logs for audit trail."""
        try:
            ok, msg = self.ftp_manager.upload_file(local_path, remote_dir, local_path.name, ftp_settings)
            event_type = "UPLOAD_SUCCESS" if ok else "UPLOAD_FAILURE"

            if self.config.enable_audit_trail and self.license_manager.is_feature_enabled(FEATURE_AUDIT):
                details = {"filename": local_path.name, "result_message": msg}
                self.pro_handler.log_audit_event(event_type, details)

            if ok:
                logging.info(f"Uploaded {local_path.name} to {remote_dir}")
            else:
                logging.warning(f"Failed to upload {local_path.name}: {msg}")
            return ok, msg
        except Exception as e:
            logging.error(f"FTP upload failed for {local_path}: {e}", exc_info=True)
            return False, str(e)

    # --- Utilities ---
    
    def prepare_mailto_uri(self, subject: str, body: str, to: str = "") -> str:

        return f"mailto:{to}?subject={quote(subject)}&body={quote(body)}"

    def _get_active_ftp_password_from_config(self) -> Union[str, None]:
        """Retrieves the active FTP password based on hardened security status."""
        if not self.active_issuer_id: return None
        
        if self.config.hardened_security:
            password = self.crypto_manager.load_ftp_password(self.active_issuer_id)
            if password is None:
                logging.error("Hardened Security ON, but FTP password not found in OS storage.")
                return None
            return password
        else:
            try: 
                return base64.b64decode(self.config.ftp_pass_b64).decode("utf-8")
            except Exception: 
                return ""

    def _get_next_auto_doc_num_str(self) -> str:
        next_num = self.config.last_auto_inc_num + 1
        return f"{datetime.datetime.now().strftime('%y')}-{next_num:03d}"

    def update_auto_inc_num(self):
        self.config.last_auto_inc_num += 1
        self._save_current_config_to_db()

    def _apply_number_mask(self, mask_str: str) -> str:
        """Applies mask to the next auto-increment number."""
        if not mask_str:
            return ""
        
        next_num = self.config.last_auto_inc_num + 1
        now = datetime.datetime.now()
        
        mask = mask_str.replace("YYYY", now.strftime("%Y")).replace("YY", now.strftime("%y"))
        mask = mask.replace("MM", now.strftime("%m")).replace("DD", now.strftime("%d"))
        
        if "#" in mask:
            num_placeholders = mask.count("#")
            num_str = f"{next_num:0{num_placeholders}d}"
            # Only replace the first block of consecutive #'s, assuming a single number field
            try:
                start_index = mask.find("#")
                if start_index != -1:
                    end_index = start_index + num_placeholders
                    mask = mask[:start_index] + num_str + mask[end_index:]
            except Exception as e:
                logging.error(f"Error applying number mask: {e}")
                mask = f"MASK_ERROR_{next_num}" 
            
        return mask

    def _sanitize_filename(self, f: str) -> str:
        return "".join(c for c in f if c not in '<>:"/\\|?*').strip()

    # --- System Status and Verification ---

    def notify_auto_upload_changed(self):
        if self.ui_callback and hasattr(self.ui_callback, 'tabs'):
            core_tab = self.ui_callback.tabs.get("core")
            if core_tab:
                core_tab.update_auto_upload_indicator()

    def check_system_status_threaded(self):
        """verify the online public id files."""
        # Always run the check when this method is called.
        # The "run once on startup" logic is handled by how this is called.
        
        if not self.active_issuer_id:
            logging.warning("check_system_status_threaded called without an active issuer.")
            return
        # Reset the state before each check!
        self.system_is_verified = False
        self.active_issuer_contact_info = {}
        
        # Tell the UI that a new check is starting => clear the old message.
        self.ui_callback.on_status_check_start(self.active_issuer_data["infoUrl"])
        threading.Thread(target=self._check_status_worker, daemon=True).start()

    def _check_status_worker(self):
        """Function to Check public key accessibility and integrity."""
        info_url = self.active_issuer_data["infoUrl"]

        def safely_call_ui(success, msg, style, details, logo_pil=None):
            self.ui_callback.root.after(
                0,
                lambda: self.ui_callback.on_status_check_complete(
                    success, msg, style, details, logo_pil
                )
            )

        try:
            # 1. Fetch JSON from issuer server
            response = requests.get(info_url, timeout=10)
            response.raise_for_status()
            online_data = response.json()

            # 2. Securely get the local public key for comparison
            key_location = self.active_issuer_data.get("priv_key_pem")
            key_path = APP_DATA_DIR / KEY_FILENAME_TEMPLATE.format(issuer_id=self.active_issuer_id)
            local_pub_key_pem = self.crypto_manager.get_public_key_pem(key_location, self.active_issuer_id, key_path)

            if not local_pub_key_pem:
                safely_call_ui(False, "❌ LOCAL KEY ERROR!", DANGER, "Could not load local key to perform verification.")
                return

            if online_data.get("publicKeyPem") != local_pub_key_pem:
                safely_call_ui(False, "❌ PUBLIC KEY MISMATCH!", DANGER, "Key on server differs from local key.")
                return

            # 3. Fetch Logo (if one is specified in the public data)
            logo_pil = None
            if logo_url := online_data.get("logoUrl"):
                logo_pil = self._fetch_logo(logo_url)
            
            # 4. All checks passed. Update state and notify the UI of success.
            self.active_issuer_contact_info = online_data.get("contactInfo", {})
            self.original_status_logo_pil = logo_pil
            self.system_is_verified = True
            
            safely_call_ui(True, "✅ System Online & Verified", SUCCESS, "Public key is accessible and correct.", logo_pil)
       
        # ---  Error Handling ---
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
            logging.error(f"System status check failed Network error: {e}", exc_info=True)
            details = "Connection failed. Please check your internet connection and verify the server URL in your settings."
            safely_call_ui(False, "⚠️ OFFLINE OR CONFIG ERROR!", DANGER, details)
            
        except requests.exceptions.RequestException as e:
            logging.error(f"System status check failed HTTP error: {e}", exc_info=True)
            details = f"The server returned an error ({e.response.status_code if e.response else 'Unknown'}). Please ensure the URL is correct."
            safely_call_ui(False, "⚠️ OFFLINE OR CONFIG ERROR!", DANGER, details)
            
        except (json.JSONDecodeError, KeyError) as e:
            logging.error(f"Parsing error from server: {e}", exc_info=True)
            details = f"The '{INFO_FILENAME}' on your server appears to be missing or corrupt."
            safely_call_ui(False, "⚠️ INVALID PUBLIC FILE!", DANGER, details)
            
        except Exception as e:
            logging.error(f"System Status Check failed need investigation: {e}", exc_info=True)
            safely_call_ui(False, "❌ KEEP CALM ERROR!", DANGER, f"An unexpected error occurred: {e}")

    def _fetch_logo(self, url: str) -> Union[Image.Image, None]:
        """
        Fetches the logo from issuer's server with security validation.
        Returns a PIL Image or None on any failure.
        """
        try:
            with requests.get(url, timeout=10, stream=True) as r:
                r.raise_for_status()

                # Security check: Validate Content-Type header (warning only, non-blocking)
                content_type = r.headers.get('Content-Type', '').lower()
                if content_type and not content_type.startswith('image/'):
                    logging.warning(f"Suspicious Content-Type for logo: Expected image/*, got '{content_type}'. Proceeding with caution.")

                image_data = io.BytesIO()
                downloaded_size = 0

                for chunk in r.iter_content(chunk_size=8192):
                    downloaded_size += len(chunk)
                    if downloaded_size > MAX_LOGO_SIZE_BYTES:
                        raise ValueError(f"Logo file exceeds {MAX_LOGO_SIZE_BYTES / 1024:.0f}KB limit.")
                    image_data.write(chunk)

                image_data.seek(0)

                # Security check: Verify image integrity (non-blocking, optional)
                try:
                    img = Image.open(image_data)
                    img.verify()  # Detects corrupted or malicious image files
                    logging.debug(f"Logo integrity verified for {url}")
                except Exception as verify_error:
                    logging.warning(f"Logo verification warning (proceeding anyway): {verify_error}")

                # Re-open image for actual use (verify() consumes the image)
                image_data.seek(0)
                img = Image.open(image_data)

                logging.info(f"Successfully downloaded and validated logo from {url}")
                return img

        
        except requests.exceptions.RequestException as e:
            logging.warning(f"Failed to fetch logo from {url}: A network error occurred. Details: {e}")
            return None

        except UnidentifiedImageError:
            logging.warning(f"Failed to process logo from {url}: The downloaded file is not a valid image format.")
            return None
        except ValueError as e:
            logging.warning(f"Failed to fetch logo from {url}: {e}")
            return None
            
    # --- Public Information Generation ---
    
    def generate_issuer_qr(self) -> Image.Image:
        if not self.active_issuer_id: return None

        payload = {
            "qr_type": "issuer_info_v1",
            "id": self.active_issuer_id,
            "name": self.active_issuer_data["name"],   
            "infoUrl": self.active_issuer_data["infoUrl"]
            }

        json_string = json.dumps(payload, separators=(',', ':'))

        self.issuer_qr_image_pil = self.image_processor.generate_qr_with_logo(
            json_string,
            self.original_status_logo_pil,
            sizing_ratio=0.85
        )
        return self.issuer_qr_image_pil

    def get_lkey_with_overlay(self, lkey_pil_image: Image.Image) -> Image.Image:
        if not lkey_pil_image:
            return None
        try:
            # The ImageProcessor now handles the direct image object
            return self.image_processor.overlay_checkmark(lkey_pil_image)
        except Exception as e:
            logging.error(f"Failed to overlay checkmark on LKey image: {e}", exc_info=True)
            return lkey_pil_image # Return the original on failure

    # --- Backup and Persistence ---

    def create_secure_backup(self, password: str, save_path_str: str) -> tuple[bool, str, Union[Path, None]]:
        if not self.active_issuer_id:
            return False, "No active identity.", None

        key_filepath = APP_DATA_DIR / KEY_FILENAME_TEMPLATE.format(issuer_id=self.active_issuer_id)
        settings_file_path = ISSUER_DB_FILE
        is_hardened = self.config.hardened_security

        try:
            # 1. Retrieve key if stored in OS keystore
            if is_hardened:
                key_from_keystore = self.crypto_manager.load_private_key_from_keystore(self.active_issuer_id)
                if not key_from_keystore:
                    raise KeystoreError("Could not retrieve private key from OS Keystore.")
                key_filepath.write_text(key_from_keystore, encoding="utf-8")

            # 2. Validate files before backup
            if not key_filepath.exists() or not settings_file_path.exists():
                return False, "Missing key or settings file.", None

            save_path = Path(save_path_str)
            
            # 3. Create encrypted ZIP
            with pyzipper.AESZipFile(save_path, "w", compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES) as zf:
                zf.setpassword(password.encode("utf-8"))
                zf.write(key_filepath, arcname=key_filepath.name)
                zf.write(settings_file_path, arcname=settings_file_path.name)
            
            return True, "Secure backup created successfully.", save_path.parent

        except KeystoreError as e:
            msg = f"A security error occurred: {e}"
            logging.error(msg)
            return False, msg, None
        except PermissionError:
            msg = f"Permission denied. Cannot write backup to '{save_path_str}'. Check folder permissions."
            logging.error(msg)
            return False, msg, None
        except IOError as e:
            msg = f"File system error during backup: {e}"
            logging.error(msg, exc_info=True)
            return False, msg, None
        finally:
            if is_hardened and key_filepath.exists():
                key_filepath.unlink()

    ##################################            
    # --- Web3/IPFS/Blockchain Logic ---
    # 10% of the codebase for an ultra niche  
    # not my brightest but this is teh way..


    def handle_legacy_anchor_activation_threaded(self):
        """
        Kicks off the Pro feature job to activate a legacy Web3 anchor.
        """
        if hasattr(self.pro_handler, 'handle_legacy_anchor_activation_threaded'):
            self.pro_handler.handle_legacy_anchor_activation_threaded()
        else:
            # This handles the case where the pro_features.py file might be missing
            self.on_legacy_anchor_activation_failure("Pro features module not found.")

    def on_legacy_anchor_activation_success(self, ipfs_cid: str):
        """
        Callback that saves the new IPFS CID after a successful legacy anchor activation.
        """
        logging.info(f"Successfully received legacy anchor CID: {ipfs_cid}")
        self.active_issuer_data["ipfsCid"] = ipfs_cid
        
        # Save to local my-legato-link.json
        try:
            local_public_file_path = APP_DATA_DIR / INFO_FILENAME
            if local_public_file_path.exists():
                local_data = json.loads(local_public_file_path.read_text(encoding="utf-8"))
                local_data["ipfsCid"] = ipfs_cid
                local_public_file_path.write_text(json.dumps(local_data, indent=2), encoding="utf-8")
            self.config.web3_anchor_enabled = True
            self._save_current_config_to_db()
            self.ui_callback.on_legacy_anchor_complete(True, "Anchor successfully activated!")
        except Exception as e:
            self.on_legacy_anchor_activation_failure(f"Failed to save synced CID: {e}")

    def on_managed_anchor_operation_complete(self, success: bool, ipfs_cid: Union[str, None], message: str):
        """
        Callback from ProFeatures that commits anchor changes (add/remove) to the local state.
        """
        if success:
            try:
                # 1. Update the in-memory data dictionary. This is the critical part
                if ipfs_cid:
                    self.active_issuer_data["ipfsCid"] = ipfs_cid
                elif "ipfsCid" in self.active_issuer_data:
                    del self.active_issuer_data["ipfsCid"]

                # 2. Update the local my-legato-link.json file for persistence.
                local_public_file_path = APP_DATA_DIR / INFO_FILENAME
                if local_public_file_path.exists():
                    local_data = json.loads(local_public_file_path.read_text(encoding="utf-8"))
                    if ipfs_cid:
                        local_data["ipfsCid"] = ipfs_cid
                    elif "ipfsCid" in local_data:
                        del local_data["ipfsCid"]
                    local_public_file_path.write_text(json.dumps(local_data, indent=2), encoding="utf-8")

                # 3. Update the main config state.
                self.config.web3_anchor_enabled = ipfs_cid is not None
                self._save_current_config_to_db()

            except Exception as e:
                success = False
                message = f"Server operation succeeded, but failed to update local files: {e}"
                logging.error(message, exc_info=True)
        
        # 4. Now, with the state correctly updated, call the UI callback.
        self.ui_callback.on_managed_anchor_complete(success, message)
            
            

    def remove_ipfs_anchor_and_update(self):
        """
        Wipes the IPFS anchor from the local config and tells the UI to get ready for a server push
        """
        try:

            if "ipfsCid" in self.active_issuer_data:
                del self.active_issuer_data["ipfsCid"]
            
            local_identity_path = APP_DATA_DIR / INFO_FILENAME
            if local_identity_path.exists():
                local_data = json.loads(local_identity_path.read_text(encoding="utf-8"))
                if "ipfsCid" in local_data:
                    del local_data["ipfsCid"]
                    local_identity_path.write_text(json.dumps(local_data, indent=2), encoding="utf-8")
            
            self.config.web3_anchor_enabled = False
            self._save_current_config_to_db()

            success_message = "Local anchor removed. Click the button below to upload this change to your server."
            self.ui_callback.on_web3_anchor_complete(True, success_message)

        except Exception as e:
            logging.error(f"Failed to remove IPFS anchor: {e}", exc_info=True)
            # Also notify the UI on failure
            self.ui_callback.on_web3_anchor_complete(False, f"Error: {e}") 
    
    def delegate_purchase_flow_threaded(self, ui_callback_for_progress):

        if hasattr(self.pro_handler, 'start_purchase_flow_threaded'):
            self.pro_handler.start_purchase_flow_threaded(ui_callback_for_progress)
        else:
            from models.utils import show_error
            show_error(
                "Feature Not Available",
                "The license purchase module is not available in this version of the application."
            )
            ui_callback_for_progress.on_polling_failure("Purchase module not installed.")         
    
    # --- BYOK Handlers (for the free) ---

    def handle_byok_publish_threaded(self, creds: dict):
        """Hands off the custom IPFS anchor publishing job to the Pro handler."""
        if hasattr(self.pro_handler, 'handle_byok_publish_threaded'):
            self.pro_handler.handle_byok_publish_threaded(creds)
        else:
            self.on_byok_activation_failure("Pro features module not found.")

    def on_byok_activation_success(self, ipfs_cid: str):
        """Callback that saves the new CID after a custom IPFS anchor is successfully published."""
        logging.info(f"BYOK anchor successful. New active CID: {ipfs_cid}")
        
        # Save this new CID as the authoritative one.
        self.active_issuer_data["ipfsCid"] = ipfs_cid
        try:
            # 1. Update local my-legato-link.json
            local_public_file_path = APP_DATA_DIR / INFO_FILENAME
            if local_public_file_path.exists():
                local_data = json.loads(local_public_file_path.read_text(encoding="utf-8"))
                local_data["ipfsCid"] = ipfs_cid
                local_public_file_path.write_text(json.dumps(local_data, indent=2), encoding="utf-8")
            
            # 2. Update and save config
            self.config.web3_anchor_enabled = True
            if "settings" not in self.all_issuer_data[self.active_issuer_id]:
                self.all_issuer_data[self.active_issuer_id]["settings"] = {}
            self.all_issuer_data[self.active_issuer_id]["settings"]["anchor_source"] = "custom"
            self._save_current_config_to_db()

            self.ui_callback.on_byok_complete(True, "Custom anchor successfully published! Remember to click 'Save Settings & Upload Public Files' to publish this CID.")
        except Exception as e:
            self.on_byok_activation_failure(f"Failed to save custom CID: {e}")

    def on_byok_activation_failure(self, error_message: str):
        """Callback reports an error to the UI if the custom anchor publish fails."""
        self.ui_callback.on_byok_complete(False, error_message)