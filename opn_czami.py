# opn_czami.py
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

# How it started: a FAT Logic God Class
# HOW it Went: a FAT Controler (callabck etc are taking alost as much space as the logic)
# How it is: a Fat Controler DI coordinator Slim  from 2k3 to 1.7K
# Edit: Slim fat Controler with a venegence  manage to strip an othe 500 lines of code almost under 1K now

# opn_czami.py
# Copyright (C) 2025 Frédéric Levi Mazloum
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.

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
from PIL import Image, UnidentifiedImageError
import requests
import pyzipper

# FIX 1: Removed wildcard import and imported only used constants
from ttkbootstrap.constants import (
    PRIMARY, SECONDARY, SUCCESS, INFO, WARNING, DANGER,
    LIGHT, DARK, DISABLED, NORMAL, END
)

import boto3
from botocore.exceptions import ClientError
from botocore.client import Config

# --- Local Application  ---
from models.exceptions import SettingsError, KeystoreError, FileAccessError, HashCalculationError, AuditLogError
from models.config import (
    ISSUER_DB_FILE, KEYRING_SERVICE_NAME, APP_DATA_DIR,
    INFO_FILENAME, KEY_FILENAME_TEMPLATE, MAX_LOGO_SIZE_BYTES,
    SCRIPT_DIR, APP_DOCS_DIR, FEATURE_WATERMARK, FEATURE_AUDIT,
    FEATURE_MASKED_IDS, FEATURE_BATCH, HTTP_TIMEOUT_LONG, FTP_TIMEOUT_SECONDS
)
from models.utils import resource_path, show_error, show_info
from models.settings_manager import SettingsManager
from models.ftp_manager import FTPManager
from models.secure_storage import SecureStorage, KeyStorage
from models.license_manager import LicenseManager
from models.image_processor import ImageProcessor
from models.identity_manager import IdentityManager
from models.server_compatibility import ServerCompatibility
from models.server_setup import ServerSetup
from models.insights_db import InsightsDB
from models.local_insight import LocalInsight
from services.signing_service import SigningService
from services.certificate_service import CertificateService

# --- Pro Features Configuration ---

try:
    from pro_features import ProFeatures
    PRO_FEATURES_AVAILABLE = True
# FIX 2: Only catch import errors, not logic bugs (e.g. SyntaxError in pro module)
except (ImportError, ModuleNotFoundError) as e:
    logging.warning(f"Pro features module not found. Running in standard mode. Details: {e}")
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

            # Instantiate LocalInsight for free dashboard functionality
            self.local_insight = LocalInsight(app_instance)

        def load_data_file_threaded(self, *args, **kwargs): pass
        def process_batch_threaded(self, *args, **kwargs): pass
        def load_and_verify_audit_log(self, *args, **kwargs):
            DANGER = "danger"
            return [], False, "Pro features are not available.", DANGER
        def log_audit_event(self, event_type: str, details: dict):
            logging.warning(f"Mock ProFeatures: Ignoring audit event '{event_type}'")
            pass

        def load_cached_analytics(self):
            # Free dashboard - works without pro module
            if hasattr(self, 'local_insight') and self.local_insight:
                self.local_insight.load_cached_analytics()
            else:
                logging.warning("Mock ProFeatures: LocalInsight not available")

        def refresh_dashboard_analytics_threaded(self, *args, **kwargs):
            # pro-only
            logging.warning("Mock ProFeatures: FTP analytics refresh requires pro module")
            pass

        def open_world_map_window(self, *args, **kwargs):
            logging.warning("Mock ProFeatures: World map requires pro module")
            pass

        def load_certificate_details(self, *args, **kwargs):
            logging.warning("Mock ProFeatures: Certificate details require pro module")
            pass

        def mock_start_purchase_flow(self, ui_callback_for_progress):
            # mock method for missing license
            self.show_error(
                "License Required",
            )
            ui_callback_for_progress.on_polling_failure("License module missing or not enabled.")

except Exception as e:
    # If something ELSE goes wrong (like a SyntaxError inside the pro module), 
    # we want to know about it loudly, but not crash the whole app if possible.
    print("--- CRITICAL ERROR LOADING PRO MODULE ---")
    traceback.print_exc()
    PRO_FEATURES_AVAILABLE = False
    # Re-define mock class here too just in case
    class ProFeatures:
        def __init__(self, app_instance):
             pass 

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
    """App user-configurable settings"""
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
    enable_audit_trail: bool = False
    last_auto_inc_num: int = 0
    check_for_updates: bool = True
    enable_insights_logging: bool = False

    def __post_init__(self):
        # default save path
        if not self.legato_files_save_path:
            self.legato_files_save_path = str(APP_DOCS_DIR / "Legato_Keys")
    @classmethod
    def from_issuer_data(cls, data: dict) -> 'AppConfig':
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
            enable_audit_trail=s.get("enable_audit_trail", False),
            last_auto_inc_num=s.get("auto_increment_last_num", 0),
            check_for_updates=s.get("check_for_updates", True),
            enable_insights_logging=s.get("enable_insights_logging", False)
        )

    def to_db_dict(self) -> dict:
        """Convert to nested dict for DB storage"""
        ftp_settings = {
            "host": self.ftp_host,
            "user": self.ftp_user,
            "path": self.ftp_path,
            "mode": FTPMode.AUTOMATIC.value if self.ftp_auto_upload else FTPMode.MANUAL.value,
        }

        if self.ftp_pass_b64:
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
            "check_for_updates": self.check_for_updates,
            "enable_insights_logging": self.enable_insights_logging,
            "ftp_settings": ftp_settings,
        }

class OpnCzamiLogic:
    """
    GUI-agnostic core logic for OpnCzami
    """

    def __init__(self, ui_callback_interface: object, app_context, app_state):
        # Both app_context and app_state are REQUIRED
        self.ui_callback = ui_callback_interface

        # Use DI
        self.context = app_context
        self.state = app_state
        self.event_bus = app_context.event_bus
        self.logger = logging.getLogger(__name__)
        self.logger.info("[LOGIC] OpnCzamiLogic initialized with AppContext and AppState")

        # Expose services and managers from AppContext
        self.path_manager = app_context.path_manager
        self.settings_manager = app_context.settings_manager
        self.crypto_manager = app_context.secure_storage
        self.identity_manager = app_context.identity_manager
        self.image_processor = app_context.image_processor
        self.ftp_manager = app_context.ftp_manager
        self.license_manager = app_context.license_manager
        self.signing_service = app_context.signing_service
        self.certificate_service = app_context.certificate_service
        self.backup_service = app_context.backup_service
        self.verification_service = app_context.verification_service
        self.deployment_service = app_context.deployment_service
        self.identity_service = app_context.identity_service

        self.generation_lock = threading.Lock()
        self.pro_handler = ProFeatures(self)
        self.server_setup = ServerSetup(self)
        self.server_compatibility = ServerCompatibility(self.ftp_manager)
        self.insights_db = app_context.insights_db  # Will be initialized when issuer is loaded
        self._initial_status_check_fired = False
        self.system_is_verified: bool = False

        # Variables for signing/upload workflow
        self.prepared_upload_path: Union[Path, None] = None
        self.last_signed_payload: Union[str, None] = None
        self.lkey_image_pil: Union[Image.Image, None] = None
        self.qr_image_pil: Union[Image.Image, None] = None
        self.issuer_qr_image_pil: Union[Image.Image, None] = None
        self.original_status_logo_pil: Union[Image.Image, None] = None


    # === STATE PROPERTY DELEGATORS

    @property
    def config(self):
        """Access config through AppState."""
        return self.state.config

    @config.setter
    def config(self, value):
        """Update config through AppState."""
        self.state.config = value

    @property
    def active_issuer_id(self):
        """Access active issuer ID through AppState."""
        return self.state.active_issuer_id

    @active_issuer_id.setter
    def active_issuer_id(self, value):
        """Update active issuer ID through AppState."""
        self.state.active_issuer_id = value

    @property
    def active_issuer_data(self):
        """Access active issuer data through AppState."""
        return self.state.active_issuer_data

    @active_issuer_data.setter
    def active_issuer_data(self, value):
        """Update active issuer data through AppState."""
        self.state.active_issuer_data = value

    @property
    def all_issuer_data(self):
        """Access all issuer data through AppState."""
        return self.state.all_issuer_data

    @all_issuer_data.setter
    def all_issuer_data(self, value):
        """Update all issuer data through AppState."""
        self.state.all_issuer_data = value

    @property
    def active_issuer_contact_info(self):
        """Access contact info through AppState."""
        return self.state.active_issuer_contact_info

    @active_issuer_contact_info.setter
    def active_issuer_contact_info(self, value):
        """Update contact info through AppState."""
        self.state.active_issuer_contact_info = value

    # --- Initialization ---
    # FTP
    def _get_decrypted_ftp_password(self) -> Union[str, None]:
        # retrieve FTP password from keystore or config
        # priority: OS Keystore first, then base64 config fallback
        if not self.active_issuer_id:
            logging.debug("No active issuer ID, cannot retrieve FTP password")
            return None

        # Try OS keystore first (regardless of where private key is stored)
        try:
            password = self.crypto_manager.load_ftp_password(self.active_issuer_id)
            if password:
                logging.debug("FTP password retrieved from OS keystore")
                return password
        except Exception as e:
            logging.debug(f"Could not retrieve FTP password from keystore: {e}")

        # Fallback to base64-encoded password
        if self.config.ftp_pass_b64:
            try:
                decoded_password = base64.b64decode(self.config.ftp_pass_b64).decode("utf-8")
                logging.debug("FTP password decoded from base64 config")
                return decoded_password
            except (binascii.Error, UnicodeDecodeError) as e:
                logging.warning(f"Failed to decode FTP password from config: {e}")
                return None

        logging.debug("No FTP password found in any storage location")
        return None

    def get_ftp_password_for_display(self) -> str:
        # Safe retrieval of FTP password for UI display
        password = self._get_decrypted_ftp_password()
        return password or ""

    def get_ftp_settings_for_connection(self) -> Union[dict, None]:
        """Get validated FTP settings for connection"""
        password = self._get_decrypted_ftp_password()
        if not password:
            logging.error(f"Failed to retrieve FTP password. Config has pass_b64: {bool(self.config.ftp_pass_b64)}")
            return None

        if not self._validate_ftp_host_and_user():
            logging.warning(f"FTP settings incomplete. Host: {self.config.ftp_host}, User: {self.config.ftp_user}")
            return None

        ftp_settings = {
            "host": self.config.ftp_host,
            "user": self.config.ftp_user,
            "password": password,
            "ftp_root": self.config.ftp_path
        }
        logging.debug(f"FTP settings retrieved: host={ftp_settings['host']}, user={ftp_settings['user']}, ftp_root={ftp_settings['ftp_root']}")
        return ftp_settings

    def _validate_ftp_host_and_user(self) -> bool:
        # Check FTP host and user are configured
        return bool(self.config.ftp_host and self.config.ftp_user)


    def load_initial_data(self):
        """Load app data on startup and notify UI"""
        self._load_issuer_data()

        migrated_count, error_count, log_messages = self._attempt_backup_restore_migration()

        # if backup restore was successful, user will need to manually relaunch
        if migrated_count > 0:
            logging.info("[BOOTSTRAP] Backup restore successful. Keys migrated to secure storage.")
            logging.info("[BOOTSTRAP] Please restart the application to load the restored identity.")

        has_identity = bool(self.active_issuer_id)
        self.event_bus.publish("logic_data_loaded", has_identity)
        self.event_bus.publish("pro_license_status_update")


    def reload_data_and_update_ui(self):
        # Reload issuer data and update UI state
        self._load_issuer_data()
        if self.active_issuer_data:
            qr_insights_enabled = self.active_issuer_data.get("settings", {}).get("enable_insights_logging", False)
        else:
            qr_insights_enabled = False

        self.event_bus.publish("qr_insights_status_update", qr_insights_enabled)
        self.event_bus.publish("ui_state_update")

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

        issuer_data = self.all_issuer_data.get(self.active_issuer_id, data)
        self.active_issuer_data = issuer_data.copy() if issuer_data else {}

        local_public_file_path = APP_DATA_DIR / INFO_FILENAME
        stored_cid = None
        # Note: Web3/IPFS anchor functionality has been removed
        key_loc = self.active_issuer_data.get("priv_key_pem")
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
        self.config = AppConfig.from_issuer_data(self.active_issuer_data)
        self.event_bus.publish("sync_ui_from_config", self.config, None)
        try:
            insights_db_dir = APP_DATA_DIR / "insights"
            insights_db_dir.mkdir(parents=True, exist_ok=True)
            insights_db_path = insights_db_dir / f"insights-{self.active_issuer_id}.db"
            self.insights_db = InsightsDB(insights_db_path)
            logging.info(f"InsightsDB initialized for issuer {self.active_issuer_id}")
        except Exception as e:
            logging.error(f"Failed to initialize InsightsDB: {e}", exc_info=True)
            self.insights_db = None

        # === SERVICE LAYER INITIALIZATION
        try:
            logging.debug(f"[CONTROLLER] Reinitializing services for issuer {self.active_issuer_id}")

            self.context.reinitialize_services_for_issuer(
                insights_db=self.insights_db,
                pro_handler=self.pro_handler
            )

            # CRITICAL: Set analytics_db in pro_handler so analytics queries work
            self.pro_handler.analytics_db = self.insights_db
            logging.info(f"[CONTROLLER] Set pro_handler.analytics_db to insights_db")

            logging.info(f"[CONTROLLER] Services reinitialized for issuer {self.active_issuer_id}")
        except Exception as e:
            logging.error(f"Failed to initialize services: {e}", exc_info=True)

        if self.active_issuer_id and not self._initial_status_check_fired:
            self._initial_status_check_fired = True
            self.check_system_status_threaded()

    def _save_current_config_to_db(self):
        # Save config to DB
        if self.active_issuer_id in self.all_issuer_data:
            db_settings = self.config.to_db_dict()
            self.all_issuer_data[self.active_issuer_id]["settings"] = db_settings
            try:
                self.settings_manager.save_app_data(self.all_issuer_data)
                logging.info("Current configuration saved to database.")
            except SettingsError as e:
                show_error("DB Save Error", str(e))

    def _attempt_backup_restore_migration(self):
        # backup restore migration
        migrated_count, error_count, log_messages = self.backup_service.attempt_backup_restore_migration(
            all_issuer_data=self.all_issuer_data
        )

        # If any backups were migrated, reload issuer data from disk
        if migrated_count > 0:
            logging.info("[BACKUP_RESTORE] Reloading issuer data after successful migration")
            self._load_issuer_data()

        return migrated_count, error_count, log_messages


    def sync_and_save_settings(self, ui_config_data: dict, ftp_password: str):
        # Synchronize settings from UI
        if not self.active_issuer_id:
            return

        success = self.settings_manager.sync_and_save_settings(
            ui_config_data,
            ftp_password,
            self.config,
            self.active_issuer_id,
            self.active_issuer_data,
            self.all_issuer_data,
            self.crypto_manager
        )

        if not success:
            show_error("Database Save Error", "Failed to save settings to database")



    def handle_identity_creation(self, name: str, url_path: str, image_base_url: str, logo_path: Union[Path, None], contact_info: dict):
        # Identity creation
        success, issuer_id, updated_all_data, active_data, config, insights_db, ftp_guess = self.identity_service.handle_identity_creation(
            name=name,
            url_path=url_path,
            image_base_url=image_base_url,
            logo_path=logo_path,
            contact_info=contact_info,
            all_issuer_data=self.all_issuer_data,
            sync_and_save_settings_callback=self.sync_and_save_settings
        )

        if success:
            self.active_issuer_id = issuer_id
            self.active_issuer_data = active_data
            self.all_issuer_data = updated_all_data
            self.config = config
            self.insights_db = insights_db

            # Publish events AFTER state is updated to avoid race conditions
            self.event_bus.publish("sync_ui_from_config", self.config, None)
            self.event_bus.publish("identity_creation_success", issuer_id, self.config, ftp_guess)

    def handle_identity_deletion(self):
        # Delete identity
        success, updated_all_data, reset_config = self.identity_service.handle_identity_deletion(
            active_issuer_id=self.active_issuer_id,
            active_issuer_data=self.active_issuer_data,
            config=self.config,
            all_issuer_data=self.all_issuer_data
        )

        if success:
            self.active_issuer_id = None
            self.active_issuer_data = {}
            self.all_issuer_data = updated_all_data
            self.config = reset_config

            # Publish event AFTER state is updated
            self.event_bus.publish("identity_deleted")

    # --- Document Signing ---

    def get_document_number(self, doc_num_manual: str, use_doc_num: bool, auto_gen: bool) -> Union[str, None]:
        """get doc number from user input or auto-generation"""
        if not use_doc_num:
            return None

        if auto_gen:
            is_masking_licensed = self.license_manager.is_feature_enabled(FEATURE_MASKED_IDS)
            mask_is_defined = self.config.doc_num_mask.strip()

            if is_masking_licensed and mask_is_defined:
                doc_num = self._apply_number_mask(self.config.doc_num_mask)
            else:
                doc_num = self._get_next_auto_doc_num_str()

            self.update_auto_inc_num()
            doc_num = doc_num_manual.strip()

        return doc_num or None

    def generate_document_qr_threaded(self, image_path: Path, message: str, doc_num_manual: str, use_doc_num: bool, auto_gen: bool):
        # Launch doc signing in background thread
        if not image_path:
            return

        self.event_bus.publish("signing_start")

        details = {"m": message.strip()}
        doc_num = self.get_document_number(doc_num_manual, use_doc_num, auto_gen)
        if doc_num:
            details["n"] = doc_num

        threading.Thread(
            target=self._sign_document_using_service,
            args=(image_path, details),
            daemon=True
        ).start()

    def _sign_document_using_service(self, image_path: Path, details: Dict[str, str]):
        # signing worker thread
        # acquire lock to prevent concurrent signing
        lock_acquired = self.generation_lock.acquire(blocking=False)
        if not lock_acquired:
            logging.warning("Generation process is already running. Ignoring new request.")
            return
        try:
            logging.info(f"[CONTROLLER] Signing via SigningService: {image_path}")
            success, message, final_image, qr_image, lky_file_path = self.signing_service.sign_document(
                image_path,
                details,
                config=self.config,
                active_issuer_id=self.active_issuer_id,
                active_issuer_data=self.active_issuer_data,
                insights_db=self.insights_db,
                pro_handler=self.pro_handler,
                original_status_logo_pil=self.original_status_logo_pil
            )
            if success:
                image_with_overlay = self.image_processor.overlay_checkmark(final_image)
                self.qr_image_pil = qr_image
                self.prepared_upload_path = lky_file_path

                # Log certificate signing to audit trail
                logging.debug(f"[CONTROLLER] Checking audit: enable_audit_trail={self.config.enable_audit_trail}, is_licensed={self.license_manager.is_feature_enabled(FEATURE_AUDIT)}")
                if self.config.enable_audit_trail and self.license_manager.is_feature_enabled(FEATURE_AUDIT):
                    try:
                        logging.info(f"[CONTROLLER] Attempting to log CERTIFICATE_SIGNED event (issuer_id={self.active_issuer_id})")
                        audit_details = {
                            "filename": Path(lky_file_path).name,
                            "message": details.get("m", ""),
                            "document_number": details.get("n")
                        }
                        self.pro_handler.log_audit_event("CERTIFICATE_SIGNED", audit_details)
                        logging.info("[CONTROLLER] Certificate signing logged to audit trail")
                    except Exception as e:
                        logging.error(f"[CONTROLLER] Failed to log signing event: {e}", exc_info=True)
                else:
                    if not self.config.enable_audit_trail:
                        logging.debug("[CONTROLLER] Audit trail disabled in config")
                    if not self.license_manager.is_feature_enabled(FEATURE_AUDIT):
                        logging.debug("[CONTROLLER] FEATURE_AUDIT not licensed")

                # Attempt auto-upload if enabled
                was_auto_upload_successful = False
                if self.config.ftp_auto_upload:
                    logging.info("[CONTROLLER] Auto-upload enabled, attempting to upload LKey...")
                    try:
                        ftp_settings = self.get_ftp_settings_for_connection()
                        if not ftp_settings:
                            logging.warning("[CONTROLLER] Auto-upload failed: FTP settings are incomplete or password is missing")
                            was_auto_upload_successful = False
                        else:
                            upload_success, upload_message = self.certificate_service.upload_lkey_file(
                                local_path=lky_file_path,
                                config=self.config,
                                active_issuer_data=self.active_issuer_data,
                                insights_db=self.insights_db,
                                pro_handler=self.pro_handler,
                                ftp_settings=ftp_settings
                            )
                            was_auto_upload_successful = upload_success
                            if upload_success:
                                logging.info(f"[CONTROLLER] Auto-upload succeeded: {upload_message}")
                            else:
                                logging.warning(f"[CONTROLLER] Auto-upload failed: {upload_message}")
                    except Exception as e:
                        logging.error(f"[CONTROLLER] Auto-upload error: {e}", exc_info=True)
                        was_auto_upload_successful = False

                self.event_bus.publish("signing_success",
                    lky_file_path,
                    qr_image,
                    self.last_signed_payload,
                    was_auto_upload_successful,
                    image_with_overlay
                )
                logging.info(f"[CONTROLLER] Signing succeeded: {self._generate_filename_stem(image_path)}.lky")
            else:
                self.event_bus.publish("signing_failure", message)
                logging.error(f"[CONTROLLER] Signing failed: {message}")

        except Exception as e:
            logging.error(f"[CONTROLLER] Error in signing: {e}", exc_info=True)
            self.event_bus.publish("signing_failure", f"An unexpected error occurred: {e}")
        finally:
            if lock_acquired:
                self.generation_lock.release()

    def _generate_filename_stem(self, image_path: Path) -> str:
        # Creates the base filename for lky and QR
        sanitized_base = self._sanitize_filename(image_path.stem)
        suffix = f"-{''.join(random.choices(string.ascii_lowercase + string.digits, k=4))}" if self.config.randomize_lkey_name else ""
        return f"{sanitized_base}{suffix}"

    def upload_lkey_file(self, local_path: Path) -> tuple[bool, str]:
        # Upload single LKey file to FTP
        if not self.certificate_service:
            return False, "Certificate service not initialized. Please reload the application."
        logging.debug(f"[MANUAL_UPLOAD] Starting upload from signing workflow")
        logging.debug(f"  active_issuer_id: {self.active_issuer_id}")
        logging.debug(f"  has active_issuer_data: {bool(self.active_issuer_data)}")
        logging.debug(f"  config.ftp_host: {self.config.ftp_host}")
        logging.debug(f"  config.ftp_user: {self.config.ftp_user}")

        ftp_settings = self.get_ftp_settings_for_connection()
        if not ftp_settings:
            logging.error(f"[MANUAL_UPLOAD] FTP settings retrieval failed. active_issuer_id={self.active_issuer_id}")
            return False, "FTP settings are incomplete or password is missing."
        is_success, result_msg = self.certificate_service.upload_lkey_file(
            local_path,
            config=self.config,
            active_issuer_data=self.active_issuer_data,
            insights_db=self.insights_db,
            pro_handler=self.pro_handler,
            ftp_settings=ftp_settings
        )
        if self.config.enable_audit_trail and self.license_manager.is_feature_enabled(FEATURE_AUDIT):
            event_type = "UPLOAD_SUCCESS" if is_success else "UPLOAD_FAILURE"
            details = {"filename": local_path.name, "result_message": result_msg}
            try:
                self.pro_handler.log_audit_event(event_type, details)
            except Exception as e:
                logging.error(f"Failed to log upload event: {e}")

        return is_success, result_msg


    def upload_public_files(self) -> tuple[bool, str]:
        # upload public files to server
        ftp_settings = self.get_ftp_settings_for_connection()
        return self.deployment_service.upload_public_files(
            active_issuer_id=self.active_issuer_id,
            active_issuer_data=self.active_issuer_data,
            config=self.config,
            ftp_settings=ftp_settings,
            server_setup=self.server_setup
        )

    def update_server_insights_config(self, logging_enabled: bool) -> tuple[bool, str]:
        # update server insights config
        ftp_settings = self.get_ftp_settings_for_connection()
        return self.deployment_service.update_server_insights_config(
            logging_enabled=logging_enabled,
            active_issuer_id=self.active_issuer_id,
            active_issuer_data=self.active_issuer_data,
            config=self.config,
            ftp_settings=ftp_settings
        )

    # --- Utilities ---

    def prepare_mailto_uri(self, subject: str, body: str, to: str = "") -> str:

        return f"mailto:{to}?subject={quote(subject)}&body={quote(body)}"


    def _get_next_auto_doc_num_str(self) -> str:
        next_num = self.config.last_auto_inc_num + 1
        return f"{datetime.datetime.now().strftime('%y')}-{next_num:03d}"

    def update_auto_inc_num(self):
        self.config.last_auto_inc_num += 1
        self._save_current_config_to_db()

    def _apply_number_mask(self, mask_str: str) -> str:
        # applies mask to next auto-increment number
        if not mask_str:
            return ""

        next_num = self.config.last_auto_inc_num + 1
        now = datetime.datetime.now()

        mask = mask_str.replace("YYYY", now.strftime("%Y")).replace("YY", now.strftime("%y"))
        mask = mask.replace("MM", now.strftime("%m")).replace("DD", now.strftime("%d"))

        if "#" in mask:
            num_placeholders = mask.count("#")
            num_str = f"{next_num:0{num_placeholders}d}"
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
        # Notify UI tabs about auto-upload setting change
        if self.ui_callback and hasattr(self.ui_callback, 'tabs'):
            # Update core tab indicator
            core_tab = self.ui_callback.tabs.get("core")
            if core_tab:
                core_tab.update_auto_upload_indicator()
            # Update pro tabs batch indicator
            pro_tab = self.ui_callback.tabs.get("pro")
            if pro_tab and hasattr(pro_tab, '_update_batch_auto_upload_indicator'):
                pro_tab._update_batch_auto_upload_indicator()

    def check_system_status_threaded(self):
        # Check system status
        if not self.active_issuer_id:
            logging.warning("check_system_status_threaded called without an active issuer.")
            return
        self.verification_service.check_system_status_threaded(self.state, self.active_issuer_data)

    def check_server_compatibility_threaded(self):
        # Check server compatibility
        if not self.active_issuer_id:
            logging.warning("check_server_compatibility_threaded called without an active issuer.")
            return
        ftp_settings = self.get_ftp_settings_for_connection()
        image_base_url = self.active_issuer_data.get("imageBaseUrl", "").rstrip('/')
        self.verification_service.check_server_compatibility_threaded(
            self.state, ftp_settings, image_base_url, self.active_issuer_data
        )


    # --- Public Information Generation ---

    def generate_issuer_qr(self) -> Image.Image:
        # Generate QR code for issuer info
        if not self.active_issuer_id or not self.active_issuer_data:
            return None

        json_string = self._build_issuer_qr_payload()
        self.issuer_qr_image_pil = self.image_processor.generate_qr_with_logo(
            json_string,
            self.original_status_logo_pil,
            sizing_ratio=0.85
        )
        return self.issuer_qr_image_pil

    def _build_issuer_qr_payload(self) -> str:
        # JSON payload for issuer QR code
        payload = {
            "qr_type": "issuer_info_v1",
            "id": self.active_issuer_id,
            "name": self.active_issuer_data.get("name", "Unknown"),
            "infoUrl": self.active_issuer_data.get("infoUrl", "")
        }
        return json.dumps(payload, separators=(',', ':'))

    def get_lkey_with_overlay(self, lkey_pil_image: Image.Image) -> Image.Image:
        if not lkey_pil_image:
            return None
        try:
            return self.image_processor.overlay_checkmark(lkey_pil_image)
        except Exception as e:
            logging.error(f"Failed to overlay checkmark on LKey image: {e}", exc_info=True)
            return lkey_pil_image

    # --- Backup  ---

    def create_secure_backup(self, password: str, save_path_str: str) -> tuple[bool, str, Union[Path, None]]:
        # Create secure backup
        return self.backup_service.create_secure_backup(
            password=password,
            save_path_str=save_path_str,
            active_issuer_id=self.active_issuer_id,
            active_issuer_data=self.active_issuer_data
        )


    def delegate_purchase_flow_threaded(self, ui_callback_for_progress):
        # license purchase flow
        if hasattr(self.pro_handler, 'start_purchase_flow_threaded'):
            self.pro_handler.start_purchase_flow_threaded(ui_callback_for_progress)
        else:
            from models.utils import show_error
            show_error(
                "Feature Not Available",
                "The license purchase module is not available in this version of the application."
            )
            ui_callback_for_progress.on_polling_failure("Purchase module not installed.")


    #=== ANALYTICS (FREE OPEN-SOURCE FEATURE)

    def load_cached_analytics(self):
        # Load analytics - shows local data immediately
        # FREE dashboard - shows basic certificate stats
        # available to all users (free and pro)

        # Show local data immediately (FREE feature)
        if self.pro_handler and self.pro_handler.local_insight:
            self.pro_handler.local_insight.load_cached_analytics()
        else:
            logging.warning("[ANALYTICS] LocalInsight not available in pro_handler")

        # PRO enhancement: If user is licensed, trigger background server log import
        if self.license_manager.is_licensed and self.pro_handler:
            logging.info("[ANALYTICS] Pro user - triggering background import of server logs")
            # background import from pro_handler
            threading.Thread(
                target=self.pro_handler._import_server_logs_background,
                daemon=True
            ).start()


    #=== DASHBOARD CERTIFICATE MANAGEMENT (delegated from DashboardTab)

    def dashboard_upload_certificate(self, cert_data: dict):
        # cert_data: Dict with filename, status, date_created, date_uploaded, scans, city
        from models.utils import show_error, show_info
        from tkinter import messagebox

        filename = str(cert_data.get('filename'))  # Ensure filename is string
        status = cert_data.get('status')
        date_created = cert_data.get('date_created')

        # DEBUG: Log state
        logging.debug(f"[DASHBOARD_UPLOAD] Starting upload for: {filename}, status={status}")
        logging.debug(f"  active_issuer_id: {self.active_issuer_id}")
        logging.debug(f"  has active_issuer_data: {bool(self.active_issuer_data)}")
        logging.debug(f"  config.ftp_host: {self.config.ftp_host}")
        logging.debug(f"  config.ftp_user: {self.config.ftp_user}")
        logging.debug(f"  config.ftp_path: {self.config.ftp_path}")

        # Pre-flight UI validations
        ftp_settings = self.get_ftp_settings_for_connection()
        if not ftp_settings:
            logging.error(f"[DASHBOARD_UPLOAD] FTP settings retrieval failed. active_issuer_id={self.active_issuer_id}")
            show_error("FTP Not Configured", "FTP settings are not configured. Please set up FTP in settings.")
            return

        if not self.active_issuer_data or not self.active_issuer_data.get("imageBaseUrl"):
            show_error("Missing Configuration", "Active issuer does not have an image base URL configured.")
            return

        if status == "ONLINE" and not messagebox.askyesno(
            "Already Online",
            f"Certificate '{filename}' is already ONLINE.\n\nDo you want to re-upload?"
        ):
            return

        success, msg = self.certificate_service.upload_certificate(
            filename, date_created,
            config=self.config,
            active_issuer_data=self.active_issuer_data,
            insights_db=self.insights_db,
            pro_handler=self.pro_handler,
            ftp_settings=ftp_settings
        )

        if success:
            logging.info(f"[LOGIC] Certificate upload successful for {filename}, refreshing dashboard UI")
            show_info("Upload Successful", f"Certificate '{filename}' uploaded successfully.")
            if "pro" in self.ui_callback.tabs:
                pro_tab = self.ui_callback.tabs["pro"]
                # Refresh local data immediately (free feature)
                self.ui_callback.root.after(0, lambda: pro_tab._refresh_dashboard_with_local_data())
        else:
            show_error("Upload Failed", f"Failed to upload certificate:\n\n{msg}")

    def dashboard_remove_certificate(self, cert_data: dict):
        # cert_data: Dict with filename, status, date_created, date_uploaded, scans, city
        from models.utils import show_error, show_info
        from tkinter import messagebox

        filename = str(cert_data.get('filename'))  # Ensure filename is string
        status = cert_data.get('status')
        date_created = cert_data.get('date_created')

        logging.debug(f"[DASHBOARD_REMOVE] Starting removal for: {filename}, status={status}")

        ftp_settings = self.get_ftp_settings_for_connection()
        if not ftp_settings:
            logging.error(f"[DASHBOARD_REMOVE] FTP settings retrieval failed for {filename}")
            show_error("FTP Not Configured", "FTP settings are not configured.")
            return

        if not self.active_issuer_data or not self.active_issuer_data.get("imageBaseUrl"):
            logging.error(f"[DASHBOARD_REMOVE] Missing active_issuer_data or imageBaseUrl for {filename}")
            show_error("Missing Configuration", "Active issuer does not have an image base URL configured.")
            return

        logging.debug(f"[DASHBOARD_REMOVE] Calling service.remove_certificate for {filename} with FTP settings")
        success, msg = self.certificate_service.remove_certificate(
            filename, date_created,
            config=self.config,
            active_issuer_data=self.active_issuer_data,
            insights_db=self.insights_db,
            pro_handler=self.pro_handler,
            ftp_settings=ftp_settings
        )

        if success:
            logging.info(f"[LOGIC] Certificate removal successful for {filename}, refreshing dashboard UI")

            # log to audit trail
            if self.config.enable_audit_trail and self.license_manager.is_feature_enabled(FEATURE_AUDIT):
                try:
                    audit_details = {"filename": filename, "status": status}
                    self.pro_handler.log_audit_event("CERTIFICATE_REMOVED", audit_details)
                    logging.info("[LOGIC] Certificate removal logged to audit trail")
                except Exception as e:
                    logging.error(f"[LOGIC] Failed to log removal event: {e}")

            show_info("Removal Successful", f"Certificate '{filename}' removed from FTP and status changed to PENDING.")

            if "pro" in self.ui_callback.tabs:
                pro_tab = self.ui_callback.tabs["pro"]
                # Refresh local data immediately (free feature)
                self.ui_callback.root.after(0, lambda: pro_tab._refresh_dashboard_with_local_data())
        else:
            show_error("Removal Failed", f"Failed to remove certificate:\n\n{msg}")

    def dashboard_delete_certificate(self, cert_data: dict):
        # cert_data: Dict with filename, status, date_created, date_uploaded, scans, city
        from models.utils import show_error, show_info
        from tkinter import messagebox

        filename = str(cert_data.get('filename'))  # Ensure filename is string
        status = cert_data.get('status')
        date_created = cert_data.get('date_created')

        # Only allow deletion of PENDING certificates (local only, no FTP removal)
        if status != "PENDING":
            show_error("Cannot Delete", f"Can only delete PENDING certificates.\nThis certificate status is: {status}\n\nTo remove ONLINE certificates, use the Remove button first.")
            return

        logging.debug(f"[DASHBOARD_DELETE] Starting deletion for: {filename}, status={status}")
        if not messagebox.askokcancel(
            "Confirm Permanent Deletion",
            f"⚠️ PERMANENTLY DELETE local certificate '{filename}'?\n\nThis action CANNOT be undone.\n"
            f"Status: PENDING (local only)"
        ):
            return

        # Delete local file only (PENDING certificates haven't been uploaded to FTP)
        success, msg = self.certificate_service.delete_certificate(
            filename, date_created,
            config=self.config,
            active_issuer_data=self.active_issuer_data,
            insights_db=self.insights_db,
            pro_handler=self.pro_handler
        )

        if success:
            logging.info(f"[LOGIC] Certificate deletion successful for {filename}, refreshing dashboard UI")

            # log to audit trail
            if self.config.enable_audit_trail and self.license_manager.is_feature_enabled(FEATURE_AUDIT):
                try:
                    audit_details = {"filename": filename, "status": status}
                    self.pro_handler.log_audit_event("CERTIFICATE_DELETED", audit_details)
                    logging.info("[LOGIC] Certificate deletion logged to audit trail")
                except Exception as e:
                    logging.error(f"[LOGIC] Failed to log deletion event: {e}")

            show_info("Deletion Complete", f"Certificate '{filename}' has been permanently deleted.")

            if "pro" in self.ui_callback.tabs:
                pro_tab = self.ui_callback.tabs["pro"]
                # Refresh local data immediately (free feature)
                self.ui_callback.root.after(0, lambda: pro_tab._refresh_dashboard_with_local_data())
        else:
            show_error("Deletion Failed", f"Failed to delete certificate:\n\n{msg}")