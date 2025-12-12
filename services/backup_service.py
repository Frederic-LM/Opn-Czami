# services/backup_service.py
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

"""Secure backup creation and restoration for identity data."""

import logging
from pathlib import Path
from typing import Union, Tuple, Dict, Any, List
import pyzipper

from models.config import APP_DATA_DIR, ISSUER_DB_FILE, KEY_FILENAME_TEMPLATE, INFO_FILENAME, STANDARDIZED_LOGO_BASENAME
from models.exceptions import KeystoreError, FileAccessError
from models.secure_storage import KeyStorage


class BackupService:
    """Manages encrypted backup creation and auto-migration to keystore."""

    def __init__(self, app_context):
        """Initialize with app context dependencies."""
        self.crypto_manager = app_context.secure_storage
        self.settings_manager = app_context.settings_manager
        self.logger = logging.getLogger(__name__)
        self.logger.info("[BACKUP_SERVICE] Initialized")

    def create_secure_backup(
        self,
        password: str,
        save_path_str: str,
        active_issuer_id: str,
        active_issuer_data: Dict[str, Any]
    ) -> Tuple[bool, str, Union[Path, None]]:
        """
        Create encrypted backup of active identity (key, settings, audit log, insights DB).

        Returns:
            (success, message, parent_directory)
        """
        if not active_issuer_id:
            return False, "No active identity.", None

        key_filepath = APP_DATA_DIR / KEY_FILENAME_TEMPLATE.format(issuer_id=active_issuer_id)
        settings_file_path = ISSUER_DB_FILE
        audit_log_path = self.crypto_manager.get_audit_log_path(active_issuer_id)
        is_key_in_keystore = active_issuer_data.get("priv_key_pem") == KeyStorage.KEYSTORE.value

        try:
            # Retrieve key from OS keystore if needed
            if is_key_in_keystore:
                key_from_keystore = self.crypto_manager.load_private_key_from_keystore(active_issuer_id)
                if not key_from_keystore:
                    raise KeystoreError("Could not retrieve private key from OS Keystore.")
                key_filepath.write_text(key_from_keystore, encoding="utf-8")

            # Validate files exist before backup
            if not key_filepath.exists() or not settings_file_path.exists():
                return False, "Missing key or settings file.", None

            save_path = Path(save_path_str)

            # Create encrypted ZIP
            with pyzipper.AESZipFile(save_path, "w", compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES) as zf:
                zf.setpassword(password.encode("utf-8"))

                # Always include: key and settings database
                zf.write(key_filepath, arcname=key_filepath.name)
                zf.write(settings_file_path, arcname=settings_file_path.name)

                # Include public info if exists
                info_file_path = APP_DATA_DIR / INFO_FILENAME
                if info_file_path.exists():
                    zf.write(info_file_path, arcname=info_file_path.name)
                    self.logger.info(f"[BACKUP] Included public info: {info_file_path.name}")

                # Include logo (extracted from logoUrl)
                logo_url = active_issuer_data.get("logoUrl", "")
                if logo_url:
                    logo_filename = Path(logo_url).name
                    logo_file_path = APP_DATA_DIR / logo_filename
                    if logo_file_path.exists():
                        zf.write(logo_file_path, arcname=logo_file_path.name)
                        self.logger.info(f"[BACKUP] Included logo: {logo_file_path.name}")

                # Include audit log if exists (pro feature)
                if audit_log_path.exists():
                    audit_arcname = f"audit/{audit_log_path.name}"
                    zf.write(audit_log_path, arcname=audit_arcname)
                    self.logger.info(f"[BACKUP] Included audit log: {audit_arcname}")

                # Include insights database if exists (pro feature)
                insights_db_path = APP_DATA_DIR / "insights" / f"insights-{active_issuer_id}.db"
                if insights_db_path.exists():
                    insights_arcname = f"insights/{insights_db_path.name}"
                    zf.write(insights_db_path, arcname=insights_arcname)
                    self.logger.info(f"[BACKUP] Included insights database: {insights_arcname}")

            return True, "Secure backup created successfully.\n(Includes private key, settings, logo, public info, audit trail, and analytics database)", save_path.parent

        except KeystoreError as e:
            msg = f"A security error occurred: {e}"
            self.logger.error(msg)
            return False, msg, None
        except PermissionError:
            msg = f"Permission denied. Cannot write backup to '{save_path_str}'. Check folder permissions."
            self.logger.error(msg)
            return False, msg, None
        except IOError as e:
            msg = f"File system error during backup: {e}"
            self.logger.error(msg, exc_info=True)
            return False, msg, None
        finally:
            # Clean up temporary key file extracted from keystore
            if is_key_in_keystore and key_filepath.exists():
                key_filepath.unlink()

    def attempt_backup_restore_migration(
        self,
        all_issuer_data: Dict[str, Any]
    ) -> Tuple[int, int, List[str]]:
        """
        Auto-migrate extracted backup files to keystore with security checks.

        CRITICAL: Only migrates if NO keystore key exists (prevents injection attacks).
        Validates identity exists in database before migrating.
        Deletes migrated files after successful transfer.

        Returns:
            (migrated_count, error_count, log_messages)
        """
        migrated_count = 0
        error_count = 0
        log_messages = []

        try:
            # Find all key files matching pattern
            for key_file in APP_DATA_DIR.glob(KEY_FILENAME_TEMPLATE.replace("{issuer_id}", "*")):
                try:
                    # Extract issuer_id from filename
                    issuer_id = key_file.stem.replace("abracadabra-", "")

                    # Safety check: issuer must exist in database
                    if issuer_id not in all_issuer_data:
                        msg = f"Skipping restore for unknown identity '{issuer_id}' - not found in database"
                        self.logger.warning(msg)
                        log_messages.append(msg)
                        continue

                    issuer_record = all_issuer_data[issuer_id]
                    current_key_location = issuer_record.get("priv_key_pem", KeyStorage.FILE.value)

                    # SECURITY: Block if keystore already has key (prevents injection)
                    if current_key_location == KeyStorage.KEYSTORE.value:
                        keystore_has_key = False
                        try:
                            existing_keystore_key = self.crypto_manager.load_private_key_from_keystore(issuer_id)
                            if existing_keystore_key:
                                keystore_has_key = True
                        except (KeystoreError, FileAccessError):
                            # Safe to proceed if keystore access fails
                            pass
                        except Exception as e:
                            # Unexpected error - block restore as safety measure
                            msg = f"SECURITY: Blocking restore for '{issuer_id}' - unexpected keystore error: {e}"
                            self.logger.error(msg, exc_info=True)
                            log_messages.append(msg)
                            error_count += 1
                            continue

                        if keystore_has_key:
                            msg = f"SECURITY: Blocking restore for '{issuer_id}' - keystore key already exists. Possible attack detected!"
                            self.logger.error(msg)
                            log_messages.append(msg)
                            error_count += 1
                            continue

                    # Validate key file
                    key_pem = key_file.read_text(encoding="utf-8")
                    if not key_pem or not key_pem.strip():
                        msg = f"Skipping restore for '{issuer_id}' - key file is empty"
                        self.logger.warning(msg)
                        log_messages.append(msg)
                        error_count += 1
                        continue

                    # Attempt keystore migration, fallback to file storage if unavailable
                    try:
                        self.crypto_manager.save_private_key_to_keystore(issuer_id, key_pem)
                        keystore_available = True
                    except (KeystoreError, FileAccessError) as e:
                        self.logger.warning(f"[BACKUP_RESTORE] Keystore unavailable for '{issuer_id}': {e}. Using file storage instead.")
                        keystore_available = False

                    try:
                        # Update database with correct key location
                        if keystore_available:
                            issuer_record["priv_key_pem"] = KeyStorage.KEYSTORE.value
                            msg = f"✅ Successfully auto-migrated backup key for identity '{issuer_id}' to secure keystore"
                        else:
                            issuer_record["priv_key_pem"] = KeyStorage.FILE.value
                            msg = f"✅ Successfully restored backup key for identity '{issuer_id}' to file storage (keystore unavailable)"

                        all_issuer_data[issuer_id] = issuer_record
                        self.settings_manager.save_app_data(all_issuer_data)
                        key_file.unlink()  # Delete temporary backup copy

                        self.logger.info(msg)
                        log_messages.append(msg)
                        migrated_count += 1

                    except Exception as e:
                        msg = f"Failed to finalize backup restore for '{issuer_id}': {e}"
                        self.logger.error(msg, exc_info=True)
                        log_messages.append(msg)
                        error_count += 1

                except Exception as e:
                    msg = f"Error processing backup file '{key_file.name}': {e}"
                    self.logger.error(msg, exc_info=True)
                    log_messages.append(msg)
                    error_count += 1

            # Log summary
            if migrated_count > 0:
                summary = f"Backup restore: Migrated {migrated_count} key(s) to secure keystore"
                self.logger.info(summary)
                log_messages.insert(0, summary)

            return migrated_count, error_count, log_messages

        except Exception as e:
            msg = f"Critical error during backup restore migration: {e}"
            self.logger.error(msg, exc_info=True)
            return 0, 1, [msg]
