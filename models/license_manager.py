# In models/license_manager.py
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


import base64
import json
import sys
import shutil
import threading
import time
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
from typing import Union, Tuple, Dict, Any
import logging

try:
    from models.utils import show_error
except ImportError:
    def show_error(title, message):
        logging.error(f"{title}: {message}")

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False


class LicenseManager:
    """Verification and updating of the pro license key."""

    def __init__(self, app_base_path: Path, app_data_path: Path):
        # Determine path for installed vs. dev or portable.
        if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
            self.app_base_path = Path(sys._MEIPASS)
        else:
            self.app_base_path = app_base_path
        
        self.app_data_path = app_data_path

        # Centralize path and filename management.
        self.license_filename = "license.key"
        self.public_key_filename = "license_public.pem"
        self.public_key_file = self.app_base_path / self.public_key_filename
        self.license_file_target_path = self.app_data_path / self.license_filename
        self.is_licensed = False
        self.enabled_features = set()
        self.customer_info = "Not Active"
        self.is_licensed_expired = False
        self.expiry_date = None
        self.ipfs_cid = None
        self.watcher_observer = None
        
        self.reload_license()

    def _get_license_path(self) -> Union[Path, None]:
        # Primary location: app data directory.
        if self.license_file_target_path.exists():
            return self.license_file_target_path
        # Fallback: next to the executable (for portable versions).
        exe_license = self.app_base_path / self.license_filename
        if exe_license.exists():
            return exe_license
        return None

    def start_watcher(self, activation_callback):

        if not WATCHDOG_AVAILABLE:
            # This error should never happen in a compiled binary if watchdog is in requirements.
            logging.error("FATAL: The 'watchdog' library was not included in the application binary. License watching is disabled.")
            return

        # High-performance, event-based watching.
        event_handler = self._LicenseChangeHandler(self, activation_callback)
        self.watcher_observer = Observer()
        self.watcher_observer.schedule(event_handler, path=str(self.app_data_path), recursive=False)
        self.watcher_observer.start()
        logging.info(f"Watchdog is monitoring '{self.app_data_path}' for license changes.")

    def stop_watcher(self):
        """Stops the file watcher if it's running."""
        if self.watcher_observer and self.watcher_observer.is_alive():
            self.watcher_observer.stop()
            self.watcher_observer.join()
            logging.info("License watcher stopped.")
            
    class _LicenseChangeHandler(FileSystemEventHandler if WATCHDOG_AVAILABLE else object):
        def __init__(self, manager_instance, activation_callback):
            self.manager = manager_instance
            self.callback = activation_callback

        def on_modified(self, event):
            if not event.is_directory and Path(event.src_path).name == self.manager.license_filename:
                logging.info(f"License file '{event.src_path}' changed, reloading.")
                self.manager.reload_license()
                if self.manager.is_licensed:
                    self.callback()
    

    def _parse_and_verify_license_file(self, license_path: Path) -> Tuple[bool, Dict[str, Any]]:
        """
        Parse and verify a license file.
        Returns (is_valid, payload_dictionary). Does not change instance state.
        """
        if not self.public_key_file.exists():
            return False, {"error": f"Public key '{self.public_key_filename}' not found"}
        if not license_path.exists():
            return False, {"error": f"License file '{license_path.name}' not found"}

        try:
            with open(self.public_key_file, "rb") as f:
                public_key = serialization.load_pem_public_key(f.read())
            
            license_key = license_path.read_text(encoding='utf-8').strip()
            payload_b64, signature_b64 = license_key.split('.', 1)
            payload_json = base64.urlsafe_b64decode(payload_b64 + '==') # Pad for robustness
            signature = base64.urlsafe_b64decode(signature_b64 + '==')

            public_key.verify(
                signature, payload_json,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
            payload = json.loads(payload_json)
            
            if "issuer_id" not in payload:
                return False, {"error": "License format is obsolete or missing Issuer ID field."}

            return True, payload
        except (InvalidSignature, ValueError, json.JSONDecodeError, TypeError) as e:
            logging.warning(f"License verification failed for {license_path.name}: {e}")
            return False, {"error": "Invalid/Tampered Key"}
        except Exception as e:
            logging.error(f"Unexpected error during license verification: {e}", exc_info=True)
            return False, {"error": "Verification Error"}

    def reload_license(self):
        """Reloads and applies the license from the primary license.key file."""
        # Reset state before attempting to load.
        self.is_licensed = False
        self.enabled_features = set()
        self.customer_info = "Not Active"
        self.expiry_date = None
        self.ipfs_cid = None
        self.is_licensed_expired = False

        license_path = self._get_license_path()
        if not license_path:
            return
        
        is_valid, payload = self._parse_and_verify_license_file(license_path)
        
        if is_valid:
            self.is_licensed = True
            self.enabled_features = set(payload.get("features", []))
            self.customer_info = payload.get("customer", "Licensed User")
            self.expiry_date = payload.get('expiry_date')
            self.ipfs_cid = payload.get('ipfs_cid')
        else:
            self.is_licensed_expired = True
            self.customer_info = payload.get("error", "Key Verification Failed")

    def activate_from_path(self, dropped_path: Path, active_issuer_id: str) -> Tuple[bool, str]:
        """
        Verifies a new license, checks it against the active_issuer_id, and activates it.
        """
        is_new_valid, new_payload = self._parse_and_verify_license_file(dropped_path)

        if not is_new_valid:
            return False, f"The provided license key is invalid: {new_payload.get('error', 'Unknown Error')}"

        if self.is_licensed:
            new_customer = new_payload.get("customer")
            if new_customer != self.customer_info:
                error_message = (
                    "License Mismatch:\n\n"
                    f"This new license belongs to '{new_customer}', but the currently active license is for '{self.customer_info}'.\n\n"
                    "Please use an updated license key issued to the original customer."
                )
                return False, error_message

        license_issuer_id = new_payload.get("issuer_id")
        
        if not active_issuer_id or active_issuer_id == "N/A":
             show_error("Activation Blocked", "Please create or load an Issuer Identity before activating a license.")
             return False, "Activation requires an active Issuer Identity."
             
        if not license_issuer_id or license_issuer_id != active_issuer_id:
            error_message = (
                "License Mismatch Error:\n\n"
                f"This license is locked to Issuer ID '{license_issuer_id}' "
                f"(or is missing the ID field), but your active ID is '{active_issuer_id}'.\n\n"
                "Please obtain a license specific to your active identity."
            )
            show_error("Security Check Failed", error_message)
            return False, error_message

        new_features = set(new_payload.get("features", []))
        current_features = self.enabled_features

        if new_features.issuperset(current_features):
            message = "License successfully upgraded!" if new_features != current_features else "License successfully re-activated."
            return self._replace_license_file(dropped_path, message)
        else:
            # REFACTORING NOTE: A direct UI call from a model class is a design compromise.
            # In a larger refactor, this should return a special status/exception
            # that the UI layer would catch and use to trigger this dialog.
            # For a drop-in replacement, we keep the original behavior.
            from tkinter import messagebox
            missing_features = ", ".join(sorted(current_features - new_features))
            warning_message = (
                "WARNING: This new license is missing some of your currently active features:\n\n"
                f"Missing: {missing_features}\n\n"
                "This will result in a downgrade. Are you sure you want to proceed?"
            )
            if messagebox.askyesno("Confirm License Downgrade", warning_message, icon='warning'):
                return self._replace_license_file(dropped_path, "License has been downgraded as requested.")
            else:
                return False, "License update cancelled by user."

    def _replace_license_file(self, source_path: Path, success_message: str) -> Tuple[bool, str]:
        """Copies the new license file and reloads the application state."""
        try:
            # THIS LINE IS NOW CORRECT
            shutil.copy(source_path, self.license_file_target_path)
            self.reload_license()
            return True, f"{success_message}\n\nCustomer: {self.customer_info}"
        except (IOError, OSError) as e:
            return False, f"Could not save the new license file. Error: {e}"

    def is_feature_enabled(self, feature_name: str) -> bool:
        """Checks if a specific pro feature is enabled by the license."""
        return feature_name in self.enabled_features

    def get_raw_license_key(self) -> str | None:
        """Reads and returns the raw content of the active license.key file."""
        license_path = self._get_license_path()
        if license_path and license_path.exists():
            try:
                return license_path.read_text(encoding='utf-8').strip()
            except Exception as e:
                logging.error(f"Could not read raw license key: {e}")
                return None
        return None