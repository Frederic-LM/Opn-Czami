# services/identity_service.py
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
IdentityService - Handles identity lifecycle management.

Responsibility: Create and delete issuer identities with proper cleanup.

Workflow:
1. Identity Creation: Create issuer, setup secure storage, initialize databases
2. Identity Deletion: Delete issuer data, cleanup FTP logs, reset state
3. FTP Host Auto-detection: Guess FTP host from URL
"""

import logging
import ftplib
from pathlib import Path
from typing import Union, Tuple, Dict, Any
from dataclasses import asdict
from urllib.parse import urlparse

from models.config import APP_DATA_DIR, FTP_TIMEOUT_SECONDS
from models.insights_db import InsightsDB
from models.utils import show_error


class IdentityService:
    """
    Service for identity lifecycle management operations.

    This service is stateless - all state is passed as method parameters.
    """

    def __init__(self, app_context):
        """
        Initialize IdentityService with required dependencies.

        Args:
            app_context: AppContext instance containing all managers
        """
        self.identity_manager = app_context.identity_manager
        self.settings_manager = app_context.settings_manager
        self.crypto_manager = app_context.secure_storage
        self.event_bus = app_context.event_bus
        self.logger = logging.getLogger(__name__)
        self.logger.info("[IDENTITY_SERVICE] Initialized")

    def handle_identity_creation(
        self,
        name: str,
        url_path: str,
        image_base_url: str,
        logo_path: Union[Path, None],
        contact_info: dict,
        all_issuer_data: Dict[str, Any],
        sync_and_save_settings_callback
    ):
        """
        Handle complete identity creation workflow.

        Args:
            name: Issuer name
            url_path: Public info URL
            image_base_url: Base URL for certificate images
            logo_path: Path to logo file (or None)
            contact_info: Contact information dictionary
            all_issuer_data: Current issuer data dictionary (will be updated)
            sync_and_save_settings_callback: Callback to save settings

        Returns:
            (success, issuer_id, updated_all_issuer_data, active_issuer_data, config, insights_db, ftp_host_guess)
        """
        # Import here to avoid circular dependency
        from opn_czami import AppConfig

        # Create and save identity
        success, result, new_data = self.identity_manager.create_and_save_identity(
            name, url_path, image_base_url, logo_path, contact_info
        )

        if not success:
            self.event_bus.publish("identity_creation_failed", result)
            return False, None, all_issuer_data, {}, AppConfig(), None, ""

        issuer_id = result
        new_data.pop('real_priv_key_pem', None)

        # Update issuer data
        all_issuer_data[issuer_id] = new_data
        active_issuer_data = new_data

        # Auto-detect FTP host
        final_ftp_guess = self._guess_ftp_host_from_url(url_path)

        # Setup secure key storage
        success, updated_data = self.identity_manager.setup_secure_key_storage(issuer_id, new_data)
        all_issuer_data[issuer_id] = updated_data
        active_issuer_data = updated_data

        # Save issuer data
        self.settings_manager.save_app_data(all_issuer_data)

        # Create initial config
        temp_config = AppConfig(ftp_host=final_ftp_guess)
        temp_config.ftp_pass_b64 = ""
        sync_and_save_settings_callback(asdict(temp_config), "")

        # Initialize insights database
        insights_db = None
        try:
            insights_db_dir = APP_DATA_DIR / "insights"
            insights_db_dir.mkdir(parents=True, exist_ok=True)
            insights_db_path = insights_db_dir / f"insights-{issuer_id}.db"
            insights_db = InsightsDB(insights_db_path)
            self.logger.info(f"InsightsDB initialized for newly created issuer {issuer_id}")
        except Exception as e:
            self.logger.error(f"Failed to initialize InsightsDB after identity creation: {e}", exc_info=True)

        # NOTE: Events are NOT published here - controller publishes them after updating state
        # to avoid race condition where UI handlers run before controller state is updated

        return True, issuer_id, all_issuer_data, active_issuer_data, temp_config, insights_db, final_ftp_guess

    def handle_identity_deletion(
        self,
        active_issuer_id: str,
        active_issuer_data: Dict[str, Any],
        config,
        all_issuer_data: Dict[str, Any]
    ):
        """
        Handle identity deletion with FTP cleanup.

        Args:
            active_issuer_id: ID of the active issuer to delete
            active_issuer_data: Dictionary containing active issuer data
            config: Current config instance
            all_issuer_data: All issuer data dictionary

        Returns:
            (success, updated_all_issuer_data, reset_config)
        """
        # Import here to avoid circular dependency
        from opn_czami import AppConfig

        if not active_issuer_id:
            return False, all_issuer_data, config

        # EDGE CASE FIX: Delete FTP logs BEFORE deleting local identity
        # Once identity is deleted, config is reset and FTP credentials are lost
        # So we must delete FTP logs first while we still have the FTP credentials
        self._delete_analytics_logs_from_ftp(active_issuer_id, active_issuer_data, config)

        # Delete identity
        success, message = self.identity_manager.delete_active_identity(active_issuer_id)

        if success:
            # Reset state
            all_issuer_data = {}
            reset_config = AppConfig()
            # NOTE: Event NOT published here - controller publishes after updating state
            return True, all_issuer_data, reset_config
        else:
            show_error("Deletion Failed", message)
            return False, all_issuer_data, config

    def _delete_analytics_logs_from_ftp(
        self,
        issuer_id: str,
        issuer_data: Dict[str, Any],
        config
    ) -> None:
        """
        Delete analytics logs from FTP server when identity is deleted.

        This prevents the "phantom logs" edge case where:
        1. User disables pro → has logs on FTP but not in local DB
        2. User deletes identity (same ID) → local DB deleted
        3. User recreates identity with same name (same ID)
        4. User enables pro → old logs imported into NEW identity's DB

        By deleting the logs when identity is deleted, we ensure a clean slate.

        Args:
            issuer_id: The issuer ID being deleted
            issuer_data: Dictionary containing imageBaseUrl and FTP settings
            config: Config instance with FTP settings
        """
        self.logger.info(f"[DELETE_IDENTITY] Starting FTP log deletion for {issuer_id}")
        self.logger.debug(f"[DELETE_IDENTITY] issuer_data keys: {list(issuer_data.keys()) if issuer_data else 'None'}")
        self.logger.debug(f"[DELETE_IDENTITY] imageBaseUrl: {issuer_data.get('imageBaseUrl') if issuer_data else 'No data'}")

        if not issuer_data or not issuer_data.get('imageBaseUrl'):
            self.logger.warning(f"[DELETE_IDENTITY] No imageBaseUrl found, cannot delete FTP logs for {issuer_id}")
            return

        try:
            image_base_url = issuer_data.get('imageBaseUrl', '')
            if not image_base_url:
                self.logger.warning("[DELETE_IDENTITY] No imageBaseUrl found, cannot delete FTP logs")
                return

            # Get FTP settings from config and retrieve password from keystore
            ftp_host = config.ftp_host
            ftp_user = config.ftp_user
            ftp_password = self._get_decrypted_ftp_password(issuer_id, config)

            self.logger.info(f"[DELETE_IDENTITY] FTP config - host={ftp_host}, user={ftp_user}, has_password={bool(ftp_password)}")

            # Validate FTP settings are available
            if not all([ftp_host, ftp_user, ftp_password]):
                self.logger.warning(f"[DELETE_IDENTITY] FTP settings incomplete (host={bool(ftp_host)}, user={bool(ftp_user)}, pass={bool(ftp_password)}), cannot delete logs from FTP")
                return

            ftp_settings = {
                'host': ftp_host,
                'user': ftp_user,
                'password': ftp_password,
            }

            # Parse the image base URL to get the remote directory
            # Example: https://test.ruederome.com/certificat → /certificat
            parsed_url = urlparse(image_base_url)
            remote_dir = parsed_url.path.rstrip('/')  # Remove trailing slash

            if not remote_dir:
                self.logger.warning(f"[DELETE_IDENTITY] Could not parse remote directory from {image_base_url}")
                return

            self.logger.info(f"[DELETE_IDENTITY] Attempting to delete analytics logs from FTP: {remote_dir}")

            # Try to delete analytics and insights log files
            try:
                with ftplib.FTP_TLS(timeout=FTP_TIMEOUT_SECONDS) as ftp:
                    ftp.connect(ftp_settings['host'])
                    ftp.login(ftp_settings['user'], ftp_settings['password'])
                    ftp.set_pasv(True)
                    ftp.prot_p()
                    ftp.cwd(remote_dir)

                    # First, try to list and delete all matching log files
                    files_to_delete = []
                    try:
                        # Get list of files in directory using nlst() which returns just filenames
                        file_list = ftp.nlst()
                        self.logger.info(f"[DELETE_IDENTITY] Files in {remote_dir}: {file_list}")

                        # Find all analytics and insights log files
                        for filename in file_list:
                            # Look for any analytics or insights log files
                            if ('analytics' in filename.lower() and filename.endswith('.log')) or \
                               ('insights' in filename.lower() and filename.endswith('.log')):
                                files_to_delete.append(filename)

                        self.logger.info(f"[DELETE_IDENTITY] Found {len(files_to_delete)} log files to delete: {files_to_delete}")
                    except Exception as e:
                        # FIX: Log specific listing error
                        self.logger.warning(f"[DELETE_IDENTITY] Could not list files from FTP (listing error): {e}")

                    # Delete each log file found
                    deleted_count = 0
                    for log_file in files_to_delete:
                        try:
                            ftp.delete(log_file)
                            deleted_count += 1
                            self.logger.info(f"[DELETE_IDENTITY] Successfully deleted {log_file} from FTP")
                        except Exception as e:
                            # FIX: Log specific deletion error
                            self.logger.warning(f"[DELETE_IDENTITY] Could not delete {log_file} (permission/lock error): {e}")

                    # Also try to delete specific known log file names directly (in case nlst() didn't find them)
                    specific_files = ['insights.log', 'analytics.log']
                    for log_file in specific_files:
                        if log_file not in files_to_delete:  # Only try if we haven't already
                            try:
                                ftp.delete(log_file)
                                deleted_count += 1
                                self.logger.info(f"[DELETE_IDENTITY] Successfully deleted {log_file} from FTP (direct attempt)")
                            except Exception as e:
                                # These files might not exist, which is fine, but we log it as DEBUG
                                # FIX: Use specific error log for debugging
                                self.logger.debug(f"[DELETE_IDENTITY] Could not direct-delete {log_file} (might not exist): {e}")

                    self.logger.info(f"[DELETE_IDENTITY] Total files deleted: {deleted_count}")

            except ftplib.all_errors as e:
                 # FIX: Catch FTP specific errors
                self.logger.error(f"[DELETE_IDENTITY] FTP Connection/Login error during log deletion: {e}")
            except Exception as e:
                 # FIX: Catch unexpected errors
                self.logger.error(f"[DELETE_IDENTITY] Unexpected error during FTP log deletion logic: {e}", exc_info=True)

            self.logger.info(f"[DELETE_IDENTITY] Completed FTP log deletion for identity {issuer_id}")

        except Exception as e:
            # Non-critical failure - log it but don't block identity deletion
            self.logger.warning(f"[DELETE_IDENTITY] Failed to delete analytics logs from FTP (top-level error): {e}", exc_info=True)

    def _get_decrypted_ftp_password(self, active_issuer_id: str, config) -> Union[str, None]:
        """
        Retrieve FTP password from secure storage.

        Args:
            active_issuer_id: ID of the active issuer
            config: Config instance

        Returns:
            Decrypted FTP password or None
        """
        # Try keystore first
        password = self.crypto_manager.load_ftp_password(active_issuer_id)
        if password:
            return password

        # Fall back to base64-encoded password in config
        if config.ftp_pass_b64:
            try:
                import base64
                return base64.b64decode(config.ftp_pass_b64).decode('utf-8')
            except Exception:
                return None

        return None

    def _guess_ftp_host_from_url(self, url_path: str) -> str:
        """
        Extract FTP host guess from URL by using the base domain.

        Removes common subdomain prefixes to get the main domain.

        Examples:
        - https://test.ruederome.com/ → ftp.ruederome.com
        - https://www.example.com/ → ftp.example.com
        - https://api.sub.domain.io/ → ftp.domain.io
        - https://example.com/ → ftp.example.com

        Args:
            url_path: URL to parse

        Returns:
            Guessed FTP host
        """
        try:
            parsed_url = urlparse(url_path)
            hostname = parsed_url.hostname
            if hostname:
                # Split by dots: test.ruederome.com → [test, ruederome, com]
                parts = hostname.lower().split('.')

                # Common subdomain prefixes to remove
                common_prefixes = {'www', 'test', 'api', 'staging', 'dev', 'prod', 'server', 'mail', 'smtp'}

                # Remove known subdomain prefixes, but keep at least 2 parts (domain.extension)
                while len(parts) > 2 and parts[0] in common_prefixes:
                    parts.pop(0)

                # Reconstruct base domain: [ruederome, com] → ruederome.com
                base_domain = '.'.join(parts)
                return f"ftp.{base_domain}"
        except Exception:
            pass
        return ""
