# models/license_manager.py
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

# SECURITY NOTE: This file is a DATA HOLDER only.
# All license verification logic has been moved to pro_features/licensing_handler.py
# (closed-source) to prevent tampering with security checks.

import sys
import shutil
import threading
from pathlib import Path
from typing import Tuple, Union
import logging
import json
import base64
import datetime

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
    """
    Data holder for license information.

    SECURITY: Verification logic is in pro_features/licensing_handler.py (closed-source).
    This class only stores and displays license data.
    """

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

        # License data (read-only display fields)
        self.is_licensed = False
        self.customer_info = "Not Active"
        self.is_licensed_expired = False
        self.expiry_date = None
        self.ipfs_cid = None
        self.watcher_observer = None

        # Load license from disk if it exists
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

    # SECURITY: License verification has been moved to pro_features/licensing_handler.py

    def reload_license(self):
        """
        Reloads license data from file.
        NOTE: Verification is handled by licensing_handler.py (closed-source).
        This just reads and displays the data.
        """
        # Reset state
        self.is_licensed = False
        self.customer_info = "Not Active"
        self.expiry_date = None
        self.ipfs_cid = None
        self.is_licensed_expired = False

        license_path = self._get_license_path()
        if not license_path or not license_path.exists():
            return

        try:
            # Just read the file - verification happens in licensing_handler
            license_key = license_path.read_text(encoding='utf-8').strip()
            payload_b64, _ = license_key.split('.', 1)
            payload_json = base64.urlsafe_b64decode(payload_b64 + '==')
            payload = json.loads(payload_json)

            self.is_licensed = payload.get("licensed", False)
            self.customer_info = payload.get("customer", "Licensed User")
            self.expiry_date = payload.get('expiry_date')
            self.ipfs_cid = payload.get('ipfs_cid')
        except Exception as e:
            logging.warning(f"Could not load license data: {e}")
            self.is_licensed_expired = True
            self.customer_info = "License Data Error"

    def activate_from_path(self, dropped_path: Path, active_issuer_id: str) -> Tuple[bool, str]:
        """
        DEPRECATED: This method is kept for backward compatibility but should not be called.
        Use licensing_handler.verify_and_activate_license() instead.
        """
        logging.error("activate_from_path() called directly - should use licensing_handler instead")
        return False, "License activation must go through licensing_handler"

    def set_license_data(self, customer: str, issuer_id: str = None, expiry_date=None, ipfs_cid=None):
        """
        Set license data after successful verification by licensing_handler.
        Called by licensing_handler after verification is complete.
        """
        self.is_licensed = True
        self.customer_info = customer
        self.expiry_date = expiry_date
        self.ipfs_cid = ipfs_cid
        self.is_licensed_expired = False

    def _replace_license_file(self, source_path: Path) -> bool:
        """Copies the new license file to the target location."""
        try:
            logging.info(f"Attempting to copy license from {source_path} to {self.license_file_target_path}")
            shutil.copy(source_path, self.license_file_target_path)
            logging.info(f"License file copied successfully. File exists on disk: {self.license_file_target_path.exists()}")
            self.reload_license()
            logging.info(f"License reloaded from disk. Expiry date in memory: {self.expiry_date}")
            return True
        except (IOError, OSError) as e:
            logging.error(f"Could not save license file: {e}")
            return False

    def is_feature_enabled(self, feature_name: str) -> bool:
        """
        Checks if pro features are enabled.

        Note: This uses BINARY/ALL-OR-NOTHING licensing - all pro features are gated
        by a single license flag. The feature_name parameter is accepted for UI organization
        and backward compatibility, but has no effect on the result.

        Returns:
            bool: True if license is active, False otherwise (regardless of feature_name)
        """
        return self.is_licensed

    def get_raw_license_key(self) -> Union[str, None]:
        """Reads and returns the raw content of the active license.key file."""
        license_path = self._get_license_path()
        if license_path and license_path.exists():
            try:
                return license_path.read_text(encoding='utf-8').strip()
            except Exception as e:
                logging.error(f"Could not read raw license key: {e}")
                return None
        return None
