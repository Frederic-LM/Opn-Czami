# services/deployment_service.py
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
ServerDeploymentService - Handles server deployment and configuration.

Responsibility: Upload public files and server configuration to issuer's FTP server.

Workflow:
1. Upload public files (JSON, logo) to root directory
2. Upload server setup files (insights.php, .htaccess, config) to LKey directory
3. Run compatibility tests
4. Update server insights configuration
"""

import logging
import json
from pathlib import Path
from typing import Union, Tuple, Dict, Any
from urllib.parse import urlparse

from models.config import APP_DATA_DIR, INFO_FILENAME
from models.server_compatibility import ServerCompatibility


class ServerDeploymentService:
    """
    Service for server deployment and configuration operations.

    This service is stateless - all state is passed as method parameters.
    """

    def __init__(self, app_context):
        """
        Initialize ServerDeploymentService with required dependencies.

        Args:
            app_context: AppContext instance containing all managers
        """
        self.ftp_manager = app_context.ftp_manager
        self.event_bus = app_context.event_bus
        self.state = app_context.app_state
        self.logger = logging.getLogger(__name__)
        self.logger.info("[DEPLOYMENT_SERVICE] Initialized")

    def upload_public_files(
        self,
        active_issuer_id: str,
        active_issuer_data: Dict[str, Any],
        config,
        ftp_settings: Dict[str, str],
        server_setup
    ) -> Tuple[bool, str]:
        """
        Upload public files (JSON, logo, insights.php, .htaccess, .insights-config.json) to issuer's server.
        Then run compatibility tests.

        Args:
            active_issuer_id: ID of the active issuer
            active_issuer_data: Dictionary containing issuer data
            config: AppConfig instance with FTP settings
            ftp_settings: Dictionary with FTP connection settings
            server_setup: ServerSetup instance for generating server files

        Returns:
            (success, message)
        """
        if not active_issuer_id:
            return False, "No active issuer."

        if not ftp_settings:
            return False, "FTP settings are incomplete or missing credentials."

        try:
            # 1. JSON and logo go to root (/) based on infoUrl parent directory
            json_remote_dir = self._resolve_remote_dir_from_info_url(active_issuer_data, config)
            if not json_remote_dir:
                return False, "Could not determine JSON/logo upload directory from infoUrl."

            # 2. Server setup files (insights.php, .htaccess, config) go to /test based on imageBaseUrl
            is_success, server_setup_remote_dir, error_msg = self.ftp_manager.calculate_remote_path(
                ftp_root=config.ftp_path,
                image_base_url=active_issuer_data.get("imageBaseUrl", "")
            )
            if not is_success:
                return False, error_msg

            # 3. Prepare local file paths
            json_path = APP_DATA_DIR / INFO_FILENAME
            logo_path = self._get_local_logo_path(active_issuer_data)

            # 4. Upload JSON to root (/) - use ftp_manager.upload_file
            ok, msg = self.ftp_manager.upload_file(json_path, json_remote_dir, json_path.name, ftp_settings)
            if not ok:
                return False, f"Public info upload failed: {msg}"

            # 5. Upload logo to root (/) - use ftp_manager.upload_file
            if logo_path:
                ok, msg = self.ftp_manager.upload_file(logo_path, json_remote_dir, logo_path.name, ftp_settings)
                if not ok:
                    return False, f"Logo upload failed: {msg}"

            # 6. Upload server setup files to /test (insights.php, .htaccess, .insights-config.json)
            uploaded_files = []
            insights_config_path = self._create_temp_insights_config(enabled=False)
            try:
                ok, msg = self.ftp_manager.upload_file(insights_config_path, server_setup_remote_dir, ".insights-config.json", ftp_settings)
                if ok:
                    uploaded_files.append(".insights-config.json")
                else:
                    return False, f"Failed to upload insights config: {msg}"
            finally:
                if insights_config_path.exists():
                    insights_config_path.unlink()

            #  insights.php is uploaded for all users.
            #  Free users can enable logging on server,
            #  But only Pro users get the insights processing.
            ok, msg = server_setup.generate_and_upload_insights_php()
            if ok:
                uploaded_files.append("insights.php")
            else:
                return False, f"Failed to upload insights.php: {msg}"

            # Generate and upload .htaccess (FOR ALL USERS - core infrastructure)
            # IMPORTANT: .htaccess is IDENTICAL for free and pro users. It provides:
            # - URL rewriting for extension-less certificate URLs
            # - Protection of log files from direct HTTP access
            # - Routing of requests through insights.php
            ok, msg = server_setup.generate_and_upload_htaccess()
            if ok:
                uploaded_files.append(".htaccess")
            else:
                return False, f"Failed to upload .htaccess: {msg}"

            # 7. Run compatibility tests (informational only - files are NOT deleted on failure)
            image_base_url = active_issuer_data.get("imageBaseUrl", "")
            checker = ServerCompatibility(ftp_manager=self.ftp_manager)
            compatibility_results = checker.check_compatibility(ftp_settings, image_base_url)
            all_passed = all(passed for _, passed, _ in compatibility_results)

            # Store compatibility results for UI display (sticky status)
            self.state.last_compatibility_results = compatibility_results

            # Update UI with server compatibility status
            self._publish_server_status_update(active_issuer_data, compatibility_results)

            # NOTE: Files are kept regardless of test results
            # Tests are informational to help diagnose server issues
            # but don't prevent successful uploads
            if not all_passed:
                self.logger.warning("Some compatibility tests reported issues (files were NOT deleted)...")
                test_details = "\n".join([f"  ⚠ {name}: {msg}" for name, passed, msg in compatibility_results if not passed])
                self.logger.warning(f"Compatibility notes:\n{test_details}")
                # Still return success since files ARE uploaded
                return True, f"Public files uploaded successfully.\n\nServer notes:\n{test_details}"

            return True, "Public files uploaded and server compatibility verified."

        except FileNotFoundError as e:
            self.logger.warning(f"Public file not found: {e}")
            return False, f"Missing required file: {e}"
        except PermissionError:
            msg = f"Permission denied while accessing files in {APP_DATA_DIR}."
            self.logger.error(msg)
            return False, msg
        except Exception as e:
            self.logger.error(f"Unexpected error during public file upload: {e}", exc_info=True)
            return False, f"Unexpected error during public file upload: {e}"

    def update_server_insights_config(
        self,
        logging_enabled: bool,
        active_issuer_id: str,
        active_issuer_data: Dict[str, Any],
        config,
        ftp_settings: Dict[str, str]
    ) -> Tuple[bool, str]:
        """
        Update server insights configuration (.insights-config.json).

        Args:
            logging_enabled: Whether to enable server-side logging
            active_issuer_id: ID of the active issuer
            active_issuer_data: Dictionary containing issuer data
            config: AppConfig instance with FTP settings
            ftp_settings: Dictionary with FTP connection settings

        Returns:
            (success, message)
        """
        try:
            if not active_issuer_id:
                msg = "Cannot update server config: no active identity"
                self.logger.warning(msg)
                return False, msg

            if not ftp_settings:
                msg = "FTP settings are incomplete (host, username, or password missing)"
                self.logger.warning(msg)
                return False, msg

            # Calculate remote directory based on imageBaseUrl (LKY files directory)
            is_success, remote_dir, error_msg = self.ftp_manager.calculate_remote_path(
                ftp_root=config.ftp_path,
                image_base_url=active_issuer_data.get("imageBaseUrl", "")
            )
            if not is_success:
                self.logger.warning(f"Cannot calculate remote directory: {error_msg}")
                return False, error_msg

            config_path = self._create_temp_insights_config(enabled=logging_enabled)

            try:
                ok, msg = self.ftp_manager.upload_file(config_path, remote_dir, ".insights-config.json", ftp_settings)
            finally:
                if config_path.exists():
                    config_path.unlink()

            if ok:
                state_str = "enabled" if logging_enabled else "disabled"
                success_msg = f"Server logging successfully {state_str}"
                self.logger.info(f"Server insights config updated: logging_enabled={logging_enabled}")

                # Update issuer data
                if active_issuer_data:
                    if "settings" not in active_issuer_data:
                        active_issuer_data["settings"] = {}
                    active_issuer_data["settings"]["enable_insights_logging"] = logging_enabled

                # Publish event
                self.event_bus.publish("qr_insights_status_update", logging_enabled)

                return True, success_msg
            else:
                self.logger.warning(f"Failed to update server insights config: {msg}")
                return False, f"Server update failed: {msg}"

        except Exception as e:
            error_msg = f"Unexpected error updating server logging: {str(e)}"
            self.logger.error(error_msg, exc_info=True)
            return False, error_msg

    # --- Helper Methods ---

    def _resolve_remote_dir_from_info_url(
        self,
        active_issuer_data: Dict[str, Any],
        config
    ) -> Union[str, None]:
        """
        Calculate the correct remote FTP directory based on the issuer's public infoURL.

        Args:
            active_issuer_data: Dictionary containing issuer data
            config: AppConfig instance with FTP settings

        Returns:
            Remote directory path or None if calculation fails
        """
        try:
            ftp_root = config.ftp_path.strip()
            remote_suffix = self._extract_path_from_info_url(active_issuer_data)
            return (Path(ftp_root) / remote_suffix.lstrip('/\\')).as_posix()
        except Exception as e:
            self.logger.error(f"Failed to resolve remote directory: {e}")
            return None

    def _extract_path_from_info_url(self, active_issuer_data: Dict[str, Any]) -> str:
        """
        Extract parent path from issuer's info URL.

        Args:
            active_issuer_data: Dictionary containing issuer data

        Returns:
            Parent path of the info URL
        """
        info_url_path = urlparse(active_issuer_data["infoUrl"]).path
        return Path(info_url_path).parent.as_posix()

    def _get_local_logo_path(self, active_issuer_data: Dict[str, Any]) -> Union[Path, None]:
        """
        Retrieve the local logo file path from issuer data.

        The logoUrl contains a full URL like 'https://example.com/my-legato-link-logo-123.png'
        We extract the filename and look for it in APP_DATA_DIR.

        Args:
            active_issuer_data: Dictionary containing issuer data

        Returns:
            Path to local logo file or None if not found
        """
        logo_url = active_issuer_data.get("logoUrl", "")
        if not logo_url:
            self.logger.debug("[LOGO] No logoUrl found in issuer data")
            return None

        logo_filename = Path(logo_url).name
        logo_path = APP_DATA_DIR / logo_filename

        if logo_path.exists():
            self.logger.debug(f"[LOGO] Found local logo file: {logo_path}")
            return logo_path
        else:
            self.logger.warning(f"[LOGO] Logo file not found: {logo_path} (logoUrl={logo_url})")
            return None

    def _create_temp_insights_config(self, enabled: bool = False) -> Path:
        """
        Create temporary insights config JSON file.

        Args:
            enabled: Whether logging should be enabled

        Returns:
            Path to temporary config file
        """
        config = {"logging_enabled": enabled}
        temp_config_path = APP_DATA_DIR / ".insights-config.json.tmp"
        with open(temp_config_path, 'w') as f:
            json.dump(config, f)
        return temp_config_path

    def _publish_server_status_update(
        self,
        active_issuer_data: Dict[str, Any],
        compatibility_results: list
    ):
        """
        Publish server compatibility status to UI via event bus.

        Args:
            active_issuer_data: Dictionary containing issuer data
            compatibility_results: List of compatibility test results
        """
        if not compatibility_results:
            return

        # Build status text
        all_passed = all(passed for _, passed, _ in compatibility_results)
        if all_passed:
            status_text = "| Server: Fully Compatible ✓"
        else:
            failed = [name for name, passed, _ in compatibility_results if not passed]
            status_text = f"| Server: Issues ({', '.join(failed)})"

        # Publish status update
        self.event_bus.publish("server_compatibility_status_update", status_text)

        # Publish QR insights status
        qr_insights_enabled = active_issuer_data.get("settings", {}).get("enable_insights_logging", False)
        self.event_bus.publish("qr_insights_status_update", qr_insights_enabled)
