# services/certificate_service.py
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

"""Manages certificate lifecycle (upload, delete, state changes)."""

import logging
from pathlib import Path
from typing import Tuple, Optional, Union, Dict


class CertificateService:
    """Manages certificate lifecycle: upload/remove from FTP, delete local, update database state."""

    def __init__(self, ftp_manager, ui_callback=None):
        """Initialize with FTP manager and optional UI callback."""
        self.ftp_manager = ftp_manager
        self.ui_callback = ui_callback

    def upload_certificate(self, filename: str, date_created: str, config, active_issuer_data,
                          insights_db, pro_handler=None, ftp_settings: dict = None) -> Tuple[bool, str]:
        """Upload certificate to FTP and mark as ONLINE in database."""
        try:
            logging.info(f"[CERT_SERVICE] Starting upload for: {filename}")

            filename_with_ext = filename if filename.endswith('.lky') else f"{filename}.lky"

            cert_path = self._find_certificate_file(filename, date_created, config)
            if not cert_path:
                error_msg = f"Could not locate certificate file: {filename}"
                logging.error(f"[CERT_SERVICE] {error_msg}")
                return False, error_msg

            is_success, remote_dir, error_msg = self._calculate_remote_path(ftp_settings, config, active_issuer_data)
            if not is_success:
                logging.error(f"[CERT_SERVICE] {error_msg}")
                return False, error_msg

            logging.info(f"[CERT_SERVICE] Uploading {filename_with_ext} to FTP at {remote_dir}...")
            success, msg = self.ftp_manager.upload_file(
                cert_path,
                remote_dir,
                filename_with_ext,
                ftp_settings
            )

            if success:
                if insights_db:
                    insights_db.mark_online(filename_with_ext)
                    logging.info(f"[CERT_SERVICE] Marked {filename} as ONLINE in database")

                self._log_audit_event(config, pro_handler,
                    "Certificate Upload",
                    f"Uploaded certificate '{filename}' to FTP server.",
                    "SUCCESS"
                )

                logging.info(f"[CERT_SERVICE] Upload completed: {filename}")
                return True, f"Certificate '{filename}' uploaded successfully."
            else:
                error_msg = f"Failed to upload certificate: {msg}"
                logging.error(f"[CERT_SERVICE] {error_msg}")
                return False, error_msg

        except Exception as e:
            error_msg = f"Exception during upload: {str(e)}"
            logging.error(f"[CERT_SERVICE] {error_msg}", exc_info=True)
            return False, error_msg

    def remove_certificate(self, filename: str, date_created: str, config, active_issuer_data,
                          insights_db, pro_handler=None, ftp_settings: dict = None) -> Tuple[bool, str]:
        """Remove certificate from FTP and mark as PENDING in database."""
        try:
            logging.info(f"[CERT_SERVICE] Starting removal for: {filename}")

            filename_with_ext = filename if filename.endswith('.lky') else f"{filename}.lky"

            cert_path = self._find_certificate_file(filename, date_created, config)
            if not cert_path or not cert_path.exists():
                error_msg = f"No local copy found for: {filename}"
                logging.warning(f"[CERT_SERVICE] {error_msg}")
                return False, error_msg

            if not ftp_settings:
                error_msg = "FTP settings are required"
                logging.error(f"[CERT_SERVICE] {error_msg}")
                return False, error_msg

            is_success, remote_dir, error_msg = self._calculate_remote_path(ftp_settings, config, active_issuer_data)
            if not is_success:
                logging.error(f"[CERT_SERVICE] {error_msg}")
                return False, error_msg

            logging.info(f"[CERT_SERVICE] Removing {filename_with_ext} from FTP at {remote_dir}...")
            success, msg = self.ftp_manager.delete_file(
                remote_dir,
                filename_with_ext,
                ftp_settings
            )

            if success:
                if insights_db:
                    if not insights_db.mark_certificate_pending(filename_with_ext):
                        return False, f"Failed to update certificate status in database."

                self._log_audit_event(config, pro_handler,
                    "Certificate Removal",
                    f"Removed certificate '{filename}' from FTP server.",
                    "SUCCESS"
                )

                logging.info(f"[CERT_SERVICE] Removal completed: {filename}")
                return True, f"Certificate '{filename}' removed from FTP and status changed to PENDING."
            else:
                error_msg = f"Failed to remove certificate: {msg}"
                logging.error(f"[CERT_SERVICE] {error_msg}")
                return False, error_msg

        except Exception as e:
            error_msg = f"Exception during removal: {str(e)}"
            logging.error(f"[CERT_SERVICE] {error_msg}", exc_info=True)
            return False, error_msg

    def delete_certificate(self, filename: str, date_created: str, config, active_issuer_data,
                          insights_db, pro_handler=None) -> Tuple[bool, str]:
        """Delete certificate from local storage and mark as DELETED in database."""
        try:
            logging.info(f"[CERT_SERVICE] Starting deletion for: {filename}")

            filename_with_ext = filename if filename.endswith('.lky') else f"{filename}.lky"

            cert_path = self._find_certificate_file(filename, date_created, config)
            if cert_path and cert_path.exists():
                try:
                    cert_path.unlink()
                    logging.info(f"[CERT_SERVICE] Deleted certificate file: {cert_path}")
                except Exception as e:
                    error_msg = f"Failed to delete certificate file: {str(e)}"
                    logging.error(f"[CERT_SERVICE] {error_msg}")
                    return False, error_msg

                # Try to delete QR image if it exists
                qr_path = cert_path.parent / f"{cert_path.stem}-QR.png"
                if qr_path.exists():
                    try:
                        qr_path.unlink()
                        logging.info(f"[CERT_SERVICE] Deleted QR image: {qr_path}")
                    except Exception as e:
                        logging.warning(f"[CERT_SERVICE] Could not delete QR image: {e}")

            if insights_db:
                if not insights_db.mark_certificate_deleted(filename_with_ext):
                    return False, f"Failed to update certificate status in database."

            self._log_audit_event(config, pro_handler,
                "Certificate Deletion",
                f"Permanently deleted certificate '{filename}' from local storage.",
                "SUCCESS"
            )

            logging.info(f"[CERT_SERVICE] Deletion completed: {filename}")
            return True, f"Certificate '{filename}' has been permanently deleted."

        except Exception as e:
            error_msg = f"Exception during deletion: {str(e)}"
            logging.error(f"[CERT_SERVICE] {error_msg}", exc_info=True)
            return False, error_msg

    def upload_lkey_file(self, local_path: str, config, active_issuer_data,
                        insights_db, pro_handler=None, ftp_settings: dict = None) -> Tuple[bool, str]:
        """Upload single LKey file to FTP and mark as ONLINE."""
        try:
            local_path = Path(local_path) if isinstance(local_path, str) else local_path

            is_success, remote_dir, error_msg = self._calculate_remote_path(ftp_settings, config, active_issuer_data)
            if not is_success:
                logging.error(f"[CERT_SERVICE] Failed to calculate remote path: {error_msg}")
                return False, error_msg

            success, msg = self.ftp_manager.upload_file(
                local_path,
                remote_dir,
                local_path.name,
                ftp_settings
            )

            if success:
                if insights_db:
                    try:
                        insights_db.mark_online(local_path.name)
                        logging.info(f"[CERT_SERVICE] Marked {local_path.name} as ONLINE")
                    except Exception as e:
                        logging.error(f"[CERT_SERVICE] Failed to mark as ONLINE: {e}")

                self._log_audit_event(config, pro_handler,
                    "Certificate Upload",
                    f"Uploaded {local_path.name}",
                    "SUCCESS"
                )

                return True, f"File {local_path.name} uploaded successfully"
            else:
                logging.error(f"[CERT_SERVICE] Upload failed: {msg}")
                return False, msg

        except Exception as e:
            error_msg = f"Exception during LKey upload: {str(e)}"
            logging.error(f"[CERT_SERVICE] {error_msg}", exc_info=True)
            return False, error_msg

    # ========================================================================
    # HELPER METHODS
    # ========================================================================

    def _find_certificate_file(self, filename: str, date_created: str, config) -> Optional[Path]:
        """Search for certificate file by date structure or fallback to full tree search."""
        try:
            filename_with_ext = filename if filename.endswith('.lky') else f"{filename}.lky"

            if not date_created or len(date_created) < 7:
                logging.warning(f"[CERT_SERVICE] No valid date_created, searching all directories for {filename}")
                save_dir = Path(config.legato_files_save_path)
                if save_dir.exists():
                    for file in save_dir.rglob(filename_with_ext):
                        if file.suffix == ".lky":
                            logging.debug(f"[CERT_SERVICE] Found certificate: {file}")
                            return file
                    for file in save_dir.rglob(filename):
                        if file.suffix == ".lky":
                            logging.debug(f"[CERT_SERVICE] Found certificate (no ext): {file}")
                            return file
                return None

            # Parse date for year/month
            try:
                year, month, _ = date_created.split('-')
            except ValueError:
                logging.warning(f"[CERT_SERVICE] Could not parse date_created '{date_created}', falling back to full search")
                year = None
                month = None

            # Try exact path first
            if year and month:
                cert_path = Path(config.legato_files_save_path) / year / f"{month:0>2}" / filename_with_ext
                logging.debug(f"[CERT_SERVICE] Trying exact path: {cert_path}")
                if cert_path.exists():
                    logging.debug(f"[CERT_SERVICE] Found certificate at expected path: {cert_path}")
                    return cert_path
                else:
                    logging.debug(f"[CERT_SERVICE] Expected path does not exist: {cert_path}")

            # Fallback: search entire directory tree
            save_dir = Path(config.legato_files_save_path)
            logging.debug(f"[CERT_SERVICE] Searching in: {save_dir}")
            if save_dir.exists():
                logging.debug(f"[CERT_SERVICE] Searching for {filename_with_ext}")
                for file in save_dir.rglob(filename_with_ext):
                    if file.suffix == ".lky":
                        logging.info(f"[CERT_SERVICE] Found certificate via search: {file}")
                        return file
                logging.debug(f"[CERT_SERVICE] Searching for {filename} (no ext)")
                for file in save_dir.rglob(filename):
                    if file.suffix == ".lky":
                        logging.info(f"[CERT_SERVICE] Found certificate via search (no ext): {file}")
                        return file
            else:
                logging.error(f"[CERT_SERVICE] Save directory does not exist: {save_dir}")

            logging.warning(f"[CERT_SERVICE] Certificate file not found: {filename} (tried with and without .lky) - save_dir={save_dir}, date_created={date_created}")
            return None

        except Exception as e:
            logging.error(f"[CERT_SERVICE] Error finding certificate file: {e}")
            return None

    def _has_local_copy(self, filename: str, date_created: str, config) -> bool:
        """Check if local certificate copy exists."""
        cert_path = self._find_certificate_file(filename, date_created, config)
        return cert_path is not None and cert_path.exists()

    def _get_ftp_settings(self) -> Optional[dict]:
        """Get FTP settings from configuration."""
        if not hasattr(self.config, 'get_ftp_settings_for_connection'):
            logging.warning("[CERT_SERVICE] Config does not have FTP settings method")
            return None

        try:
            if hasattr(self.config, 'ftp_host') and self.config.ftp_host:
                return {
                    'host': self.config.ftp_host,
                    'port': getattr(self.config, 'ftp_port', 21),
                    'username': getattr(self.config, 'ftp_username', ''),
                    'password': getattr(self.config, 'ftp_password', ''),
                    'ftp_root': getattr(self.config, 'ftp_root', '/')
                }
            return None
        except Exception as e:
            logging.error(f"[CERT_SERVICE] Error getting FTP settings: {e}")
            return None

    def _calculate_remote_path(self, ftp_settings: dict, config, active_issuer_data) -> Tuple[bool, Optional[str], str]:
        """Calculate remote FTP path for certificate upload."""
        try:
            if not active_issuer_data:
                return False, None, "Active issuer data not available"

            image_base_url = active_issuer_data.get("imageBaseUrl", "")
            if not image_base_url:
                return False, None, "Active issuer does not have an image base URL configured"

            is_success, remote_dir, error_msg = self.ftp_manager.calculate_remote_path(
                ftp_settings.get('ftp_root', '/'),
                image_base_url
            )

            return is_success, remote_dir, error_msg

        except Exception as e:
            return False, None, f"Failed to calculate remote path: {str(e)}"

    def _log_audit_event(self, config, pro_handler, event_type: str, description: str, status: str):
        """Log event to audit trail (pro feature, no-op if disabled)."""
        try:
            if not pro_handler:
                return

            if not config.enable_audit_trail:
                logging.debug(f"[CERT_SERVICE] Audit trail disabled - skipping event: {event_type}")
                return

            if hasattr(pro_handler, 'log_audit_event'):
                details = {"description": description, "status": status}
                pro_handler.log_audit_event(event_type, details)
                logging.debug(f"[CERT_SERVICE] Logged audit event: {event_type}")
        except Exception as e:
            logging.warning(f"[CERT_SERVICE] Failed to log audit event: {e}")
