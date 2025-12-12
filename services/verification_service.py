# services/verification_service.py
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
SystemVerificationService - Handles system status and server compatibility verification.

Responsibility: Verify issuer identity, check server status, validate public keys,
fetch logos, and run server compatibility tests.

Workflows:
1. System Status Verification: Fetch issuer data, validate public key, load logo
2. Server Compatibility: Run server tests, check insights config
3. Logo Fetching: Download and validate logos from server
"""

import io
import json
import logging
import threading
from pathlib import Path
from typing import Union, Dict, Any, Tuple, List
from PIL import Image, UnidentifiedImageError
import requests
from ttkbootstrap.constants import SUCCESS, DANGER

from models.config import APP_DATA_DIR, KEY_FILENAME_TEMPLATE, MAX_LOGO_SIZE_BYTES, INFO_FILENAME
from models.secure_storage import KeyStorage
from models.server_compatibility import ServerCompatibility


class SystemVerificationService:
    """
    Service for system status verification and server compatibility checks.

    This service is stateless - all state is passed as method parameters or
    updated through app_state.
    """

    def __init__(self, app_context):
        """
        Initialize SystemVerificationService with required dependencies.

        Args:
            app_context: AppContext instance containing all managers and services
        """
        self.crypto_manager = app_context.secure_storage
        self.ftp_manager = app_context.ftp_manager
        self.event_bus = app_context.event_bus
        self.ui_callback = app_context.ui_callback
        self.logger = logging.getLogger(__name__)
        self.logger.info("[VERIFICATION_SERVICE] Initialized")

    # === PUBLIC METHODS (called by controller) ===

    def check_system_status_threaded(self, app_state, active_issuer_data: Dict[str, Any]):
        """
        Check system status in background thread.

        Verifies public key accessibility and integrity on server.

        Args:
            app_state: AppState instance to update
            active_issuer_data: Active issuer data dict
        """
        if not active_issuer_data:
            self.logger.warning("check_system_status_threaded called without issuer data")
            return

        # Reset verification state
        app_state.system_is_verified = False
        app_state.active_issuer_contact_info = {}

        # Notify UI that check is starting
        self.event_bus.publish("status_check_start", active_issuer_data["infoUrl"])

        # Run verification in background thread
        threading.Thread(
            target=self._check_status_worker,
            args=(app_state, active_issuer_data),
            daemon=True
        ).start()

    def check_server_compatibility_threaded(
        self,
        app_state,
        ftp_settings: Dict[str, str],
        image_base_url: str,
        active_issuer_data: Dict[str, Any]
    ):
        """
        Check server compatibility in background thread.

        Runs full server compatibility tests including QR Insights status.

        Args:
            app_state: AppState instance to update
            ftp_settings: FTP connection settings
            image_base_url: Base URL for images on server
            active_issuer_data: Active issuer data dict
        """
        if not ftp_settings or not image_base_url:
            self.logger.warning("FTP settings or image URL not configured for server check")
            return

        threading.Thread(
            target=self._check_server_compatibility_worker,
            args=(app_state, ftp_settings, image_base_url, active_issuer_data),
            daemon=True
        ).start()

    # === WORKER METHODS (background threads) ===

    def _check_status_worker(self, app_state, active_issuer_data: Dict[str, Any]):
        """Check public key accessibility and integrity in background thread."""
        info_url = active_issuer_data["infoUrl"]
        try:
            # Fetch and validate online data
            online_data = self._fetch_online_issuer_data(info_url)
            if not online_data:
                return

            # Validate public key matches
            if not self._validate_public_key_match(app_state, active_issuer_data, online_data):
                return

            # Fetch and store logo
            logo_pil = self._load_and_store_logo(online_data.get("logoUrl"))

            # Update state and notify success
            app_state.active_issuer_contact_info = online_data.get("contactInfo", {})
            app_state.original_status_logo_pil = logo_pil
            app_state.system_is_verified = True

            self._notify_ui_status(
                True,
                "✅ System Online & Verified",
                SUCCESS,
                "Public key is accessible and correct.",
                logo_pil
            )

        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
            self.logger.error(f"System status check failed Network error: {e}", exc_info=True)
            # Try to load logo from local data as fallback
            logo_url = active_issuer_data.get("logoUrl")
            if logo_url:
                self.logger.info("[LOGO] Server unreachable - attempting to load logo from local data")
                logo_pil = self._load_and_store_logo(logo_url)
                app_state.original_status_logo_pil = logo_pil
            self._notify_ui_status(
                False,
                "⚠️ OFFLINE OR CONFIG ERROR!",
                DANGER,
                "Connection failed. Please check your internet connection and verify the server URL in your settings."
            )

        except requests.exceptions.RequestException as e:
            self.logger.error(f"System status check failed HTTP error: {e}", exc_info=True)
            status_code = e.response.status_code if e.response else 'Unknown'
            # Try to load logo from local data as fallback
            logo_url = active_issuer_data.get("logoUrl")
            if logo_url:
                self.logger.info("[LOGO] Server error - attempting to load logo from local data")
                logo_pil = self._load_and_store_logo(logo_url)
                app_state.original_status_logo_pil = logo_pil
            self._notify_ui_status(
                False,
                "⚠️ OFFLINE OR CONFIG ERROR!",
                DANGER,
                f"The server returned an error ({status_code}). Please ensure the URL is correct."
            )

        except (json.JSONDecodeError, KeyError) as e:
            self.logger.error(f"Parsing error from server: {e}", exc_info=True)
            self._notify_ui_status(
                False,
                "⚠️ INVALID PUBLIC FILE!",
                DANGER,
                f"The '{INFO_FILENAME}' on your server appears to be missing or corrupt."
            )

        except Exception as e:
            self.logger.error(f"System Status Check failed: {e}", exc_info=True)
            self._notify_ui_status(
                False,
                "❌ UNEXPECTED ERROR!",
                DANGER,
                f"An unexpected error occurred: {e}"
            )

    def _check_server_compatibility_worker(
        self,
        app_state,
        ftp_settings: Dict[str, str],
        image_base_url: str,
        active_issuer_data: Dict[str, Any]
    ):
        """Worker thread for full server compatibility checks including QR Insights status."""
        try:
            self._run_server_compatibility_checks(app_state, ftp_settings, image_base_url)
            self._check_server_insights_config(image_base_url, active_issuer_data)
            self._update_ui_with_server_status(app_state, active_issuer_data)

        except Exception as e:
            self.logger.error(f"Error during server compatibility check: {e}", exc_info=True)

    # === HELPER METHODS ===

    def _run_server_compatibility_checks(
        self,
        app_state,
        ftp_settings: Dict[str, str],
        image_base_url: str
    ):
        """Run full server compatibility tests and store results."""
        checker = ServerCompatibility(ftp_manager=self.ftp_manager)
        compatibility_results = checker.check_compatibility(ftp_settings, image_base_url)
        app_state.last_compatibility_results = compatibility_results
        self.logger.debug(f"Compatibility check completed: {compatibility_results}")

    def _check_server_insights_config(self, image_base_url: str, active_issuer_data: Dict[str, Any]):
        """Fetch and update QR Insights configuration from server."""
        try:
            config_url = f"{image_base_url}/.insights-config.json"
            response = requests.get(config_url, timeout=10, verify=True)
            if response.status_code == 200:
                config_data = response.json()
                server_insights_enabled = config_data.get("insights_enabled", False)
                self.event_bus.publish("qr_insights_status_update", server_insights_enabled)
                self.logger.info(f"Server QR Insights state: {server_insights_enabled}")
        except Exception as e:
            self.logger.warning(f"Could not fetch QR Insights config from server: {e}")

    def _update_ui_with_server_status(self, app_state, active_issuer_data: Dict[str, Any]):
        """Update the UI with server compatibility status after successful checks."""
        if not app_state.last_compatibility_results:
            return
        status_text = self._build_compatibility_status_text(app_state.last_compatibility_results)
        self.event_bus.publish("server_compatibility_status_update", status_text)
        qr_insights_enabled = self._get_qr_insights_enabled(active_issuer_data)
        self.event_bus.publish("qr_insights_status_update", qr_insights_enabled)

    def _build_compatibility_status_text(self, compatibility_results: List[Tuple[str, bool, str]]) -> str:
        """Build status text from compatibility results."""
        all_passed = all(passed for _, passed, _ in compatibility_results)
        if all_passed:
            return "| Server: Fully Compatible ✓"
        else:
            failed = [name for name, passed, _ in compatibility_results if not passed]
            return f"| Server: Issues ({', '.join(failed)})"

    def _get_qr_insights_enabled(self, active_issuer_data: Dict[str, Any]) -> bool:
        """Get QR Insights enabled status from issuer settings."""
        return active_issuer_data.get("settings", {}).get("enable_insights_logging", False)

    def _fetch_online_issuer_data(self, url: str) -> Union[Dict[str, Any], None]:
        """Fetch JSON data from issuer's server."""
        try:
            response = requests.get(url, timeout=10, verify=True)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            self.logger.error(f"Failed to fetch issuer data from {url}: {e}")
            raise

    def _validate_public_key_match(
        self,
        app_state,
        active_issuer_data: Dict[str, Any],
        online_data: Dict[str, Any]
    ) -> bool:
        """Validate local public key matches server key."""
        active_issuer_id = app_state.active_issuer_id
        key_location = active_issuer_data.get("priv_key_pem", KeyStorage.FILE.value)
        key_path = APP_DATA_DIR / KEY_FILENAME_TEMPLATE.format(issuer_id=active_issuer_id)
        local_pub_key_pem = self.crypto_manager.get_public_key_pem(key_location, active_issuer_id, key_path)

        if not local_pub_key_pem:
            self._notify_ui_status(
                False,
                "❌ LOCAL KEY ERROR!",
                DANGER,
                "Could not load local key to perform verification."
            )
            return False

        if online_data.get("publicKeyPem") != local_pub_key_pem:
            self._notify_ui_status(
                False,
                "❌ PUBLIC KEY MISMATCH!",
                DANGER,
                "Key on server differs from local key."
            )
            return False

        return True

    # === LOGO FETCHING ===

    def _load_and_store_logo(self, logo_url: Union[str, None]) -> Union[Image.Image, None]:
        """Load logo from URL if provided."""
        if not logo_url:
            return None
        return self._fetch_logo(logo_url)

    def _fetch_logo(self, url: str) -> Union[Image.Image, None]:
        """
        Fetches the logo from issuer's server with security validation.
        """
        try:
            with requests.get(url, timeout=10, stream=True) as r:
                r.raise_for_status()
                self._validate_logo_content_type(r.headers)
                image_data = self._download_logo_with_size_check(r)
                self._verify_logo_integrity(image_data, url)
                img = self._open_logo_image(image_data)
                self.logger.info(f"Successfully downloaded and validated logo from {url}")
                return img

        except requests.exceptions.RequestException as e:
            self.logger.warning(f"Failed to fetch logo from {url}: Network error. {e}")
            return None
        except UnidentifiedImageError:
            self.logger.warning(f"Failed to process logo from {url}: Not a valid image format.")
            return None
        except ValueError as e:
            self.logger.warning(f"Failed to fetch logo from {url}: {e}")
            return None

    def _validate_logo_content_type(self, headers):
        """Validate Content-Type header for image content (warning only).

        Args:
            headers: Dict-like object (dict, CaseInsensitiveDict, etc.)
        """
        content_type = headers.get('Content-Type', '').lower()
        if content_type and not content_type.startswith('image/'):
            self.logger.warning(f"Suspicious Content-Type for logo: Expected image/*, got '{content_type}'.")

    def _download_logo_with_size_check(self, response) -> io.BytesIO:
        """Download logo response body with size limit validation."""
        image_data = io.BytesIO()
        downloaded_size = 0

        for chunk in response.iter_content(chunk_size=8192):
            downloaded_size += len(chunk)
            if downloaded_size > MAX_LOGO_SIZE_BYTES:
                raise ValueError(f"Logo exceeds {MAX_LOGO_SIZE_BYTES / 1024:.0f}KB limit.")
            image_data.write(chunk)

        image_data.seek(0)
        return image_data

    def _verify_logo_integrity(self, image_data: io.BytesIO, url: str):
        """Verify image integrity by attempting to load and verify."""
        try:
            verify_img = Image.open(image_data)
            verify_img.verify()
            self.logger.debug(f"Logo integrity verified for {url}")
        except Exception as e:
            self.logger.warning(f"Logo verification warning (proceeding anyway): {e}")
        finally:
            image_data.seek(0)

    def _open_logo_image(self, image_data: io.BytesIO) -> Image.Image:
        """Open logo image and load into memory."""
        img = Image.open(image_data)
        img.load()
        return img

    # === UI COMMUNICATION ===

    def _notify_ui_status(self, success: bool, msg: str, style: str, details: str, logo_pil=None):
        """Notify UI of status check result (thread-safe)."""
        if self.ui_callback and hasattr(self.ui_callback, 'root') and self.ui_callback.root:
            # Use tkinter's thread-safe scheduling mechanism
            self.ui_callback.root.after(
                0,
                lambda: self.event_bus.publish("status_check_complete", success, msg, style, details, logo_pil)
            )
        else:
            # Fallback: publish directly if UI is not available
            # Note: This may not be thread-safe in tkinter context, but handles edge cases
            self.logger.warning("UI callback not available, publishing event directly")
            self.event_bus.publish("status_check_complete", success, msg, style, details, logo_pil)
