# models/identity_manager.py
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

import json
import logging
import os
import shutil
from pathlib import Path
from typing import Union, Dict, Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from .secure_storage import SecureStorage, KeyStorage
from .settings_manager import SettingsManager
from .config import APP_DATA_DIR, INFO_FILENAME, KEY_FILENAME_TEMPLATE


class IdentityManager:
    """Does the creation, deletion, and security of the user's issuer identity."""

    def __init__(self, crypto_manager: SecureStorage, settings_manager: SettingsManager):
        self.crypto_manager = crypto_manager
        self.settings_manager = settings_manager

    def create_and_save_identity(
        self, 
        name: str, 
        url_path: str, 
        image_base_url: str, 
        logo_path: Union[Path, None], 
        contact_info: dict
    ) -> tuple[bool, str | None, Dict | None]:
        """
        Creates a new identity, saves key files, and returns the new data.
        will return (success, error_message, new_issuer_data_for_db).
        """
        if not all([name, url_path, image_base_url]):
            return False, "Missing required fields.", None

        issuer_id = self.crypto_manager.generate_id_from_name(name)
        
        # Define the final and temporary paths for "atomic" operations.
        info_filepath = APP_DATA_DIR / INFO_FILENAME
        key_filepath = APP_DATA_DIR / KEY_FILENAME_TEMPLATE.format(issuer_id=issuer_id)
        info_filepath_tmp = info_filepath.with_suffix('.tmp')
        key_filepath_tmp = key_filepath.with_suffix('.tmp')
        
        try:
            # 1. Generate Keys
            priv_key = ed25519.Ed25519PrivateKey.generate()
            priv_key_pem = priv_key.private_bytes(
                encoding=serialization.Encoding.PEM, 
                format=serialization.PrivateFormat.PKCS8, 
                encryption_algorithm=serialization.NoEncryption()
            ).decode("utf-8")
            pub_key_pem = priv_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM, 
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode("utf-8")

            # 2. Finalize URLs
            url_path = url_path.removesuffix("/") + "/"
            image_base_url = image_base_url.removesuffix("/") + "/"
            
            # 3. Create public JSON file content
            json_content = {"publicKeyPem": pub_key_pem, "imageBaseUrl": image_base_url, "issuerName": name}
            if logo_path:
                logo_filename = logo_path.name
                json_content["logoUrl"] = url_path + logo_filename
                logging.info(f"[LOGO] Logo will be referenced in public JSON: {json_content['logoUrl']}")
                logging.info(f"[LOGO] Local logo file location: {logo_path}")
                logging.info(f"[LOGO] Local logo file exists: {logo_path.exists()}")
            else:
                logging.info("[LOGO] No logo selected for this identity")
            if filtered_contact := {k: v for k, v in contact_info.items() if v}:
                json_content["contactInfo"] = filtered_contact

            # 3.b Write to temp files first to ensure atomicity.
            info_filepath_tmp.write_text(json.dumps(json_content, indent=2), encoding="utf-8")
            key_filepath_tmp.write_text(priv_key_pem, encoding="utf-8")
            
            # 3.c Set secure permissions for mac and linux, not used on windows
            
            if os.name == 'posix':
                os.chmod(key_filepath_tmp, 0o600)
                        
            # 4. Temp/real name swaps.
            os.rename(info_filepath_tmp, info_filepath)
            os.rename(key_filepath_tmp, key_filepath)
            
            # 5. Prepare the data structure for the main database
            new_issuer_data_for_db = {
                "name": name, 
                "infoUrl": url_path + INFO_FILENAME, 
                "imageBaseUrl": image_base_url,
                "priv_key_pem": KeyStorage.FILE.value, 
                "settings": {},
            }
            if logo_path:
                new_issuer_data_for_db["logoUrl"] = json_content["logoUrl"]

            new_issuer_data_for_db['real_priv_key_pem'] = priv_key_pem

            return True, issuer_id, new_issuer_data_for_db

        #  Catch IO errors => errors messages.
        except (IOError, OSError) as e:
            logging.error(f"File system error during identity creation: {e}", exc_info=True)
            return False, f"Failed to write identity files: {e}", None
        except Exception as e:
            logging.error(f"Identity creation failed: {e}", exc_info=True)
            return False, f"Failed to create identity: {e}", None
        finally:
            info_filepath_tmp.unlink(missing_ok=True)
            key_filepath_tmp.unlink(missing_ok=True)

    def setup_secure_key_storage(self, issuer_id: str, issuer_data: dict) -> tuple[bool, dict]:
        """
        REFACTOR FOR BUG #3: Setup secure key storage.
        ALWAYS tries OS keystore first. Falls back to FILE if keystore unavailable.
        Removes need for hardened_security config flag - one secure path always.

        Returns: (success, updated_issuer_data with priv_key_pem set to KEYSTORE or FILE)
        """
        try:
            # Get the private key that was just created
            key_file_path = APP_DATA_DIR / KEY_FILENAME_TEMPLATE.format(issuer_id=issuer_id)
            if not key_file_path.exists():
                logging.error(f"Private key file not found: {key_file_path}")
                issuer_data["priv_key_pem"] = "STORED_IN_FILE"
                return False, issuer_data

            private_key_pem = key_file_path.read_text(encoding="utf-8")

            # TRY KEYSTORE FIRST (most secure)
            if self.crypto_manager.is_keystore_available():
                try:
                    self.crypto_manager.save_private_key_to_keystore(issuer_id, private_key_pem)
                    # Successfully saved to keystore - delete file
                    key_file_path.unlink(missing_ok=True)
                    issuer_data["priv_key_pem"] = "STORED_IN_KEYSTORE"
                    logging.info(f"Private key for {issuer_id} stored in OS keystore")
                    return True, issuer_data
                except Exception as e:
                    logging.warning(f"Failed to save to keystore, falling back to file: {e}")
                    # Fall through to FILE storage
            else:
                logging.info(f"OS Keystore not available, using file storage for {issuer_id}")

            # FALLBACK TO FILE (if keystore unavailable or failed)
            issuer_data["priv_key_pem"] = "STORED_IN_FILE"
            logging.info(f"Private key for {issuer_id} stored in file (keystore unavailable)")
            return True, issuer_data

        except Exception as e:
            logging.error(f"Failed to setup secure key storage: {e}", exc_info=True)
            issuer_data["priv_key_pem"] = "STORED_IN_FILE"
            return False, issuer_data

    def delete_active_identity(self, issuer_id: str):
        """ Delete all identity files and settings."""
        if not issuer_id: return False, "No active issuer ID provided."

        # Semi "atomic" deletion, not as important as for the creation.

        try:
            # Delete private key file (contains Ed25519 private key)
            (APP_DATA_DIR / KEY_FILENAME_TEMPLATE.format(issuer_id=issuer_id)).unlink(missing_ok=True)

            # Delete public info file (my-legato-link.json) - FIX FOR BUG: Win error 183 on identity recreation
            (APP_DATA_DIR / INFO_FILENAME).unlink(missing_ok=True)

            # Delete logo file (has dynamic name with timestamp: my-legato-link-logo-*.png)
            # FIX FOR BUG: Logo file wasn't deleted, preventing identity recreation
            for logo_file in APP_DATA_DIR.glob("my-legato-link-logo-*.png"):
                logo_file.unlink(missing_ok=True)

            # Delete audit log if it exists
            audit_log_path = self.crypto_manager.get_audit_log_path(issuer_id)
            if audit_log_path.exists(): audit_log_path.unlink()

            # Delete credentials from OS Keystore
            self.crypto_manager.delete_private_key_from_keystore(issuer_id)
            self.crypto_manager.delete_ftp_password(issuer_id)
            self.crypto_manager.delete_filebase_credentials(issuer_id)

            # Clear identity database
            self.settings_manager.clear_identity_file()

            logging.info(f"Identity {issuer_id} and all associated files have been deleted.")
            return True, "Identity deleted successfully."
        except (IOError, OSError) as e:
            logging.error(f"File system error during identity deletion: {e}", exc_info=True)
            return False, f"Could not delete all identity files: {e}"
        except Exception as e:
            logging.error(f"Error during identity deletion: {e}", exc_info=True)
            return False, f"Could not completely delete identity: {e}"

    def toggle_hardened_security(self, enable_security: bool, issuer_id: str, current_key_location: str, priv_key_pem: str, ftp_password: str) -> tuple[bool, str]:
        """
        Moves sensitive credentials between file and OS Keystore.

        Args:
            enable_security: If True, move to keystore. If False, move to file.
            issuer_id: The issuer ID
            current_key_location: Current key location (KeyStorage.FILE.value or KeyStorage.KEYSTORE.value)
            priv_key_pem: The actual private key PEM content (NOT a location string)
            ftp_password: The FTP password to store (can be empty string)

        Returns:
            (success, new_key_location_or_error_message)
        """
        if not issuer_id:
            return False, "No active issuer."

        # Validate that we received actual key content, not a location string
        if not priv_key_pem or priv_key_pem.startswith("STORED_"):
            return False, "Invalid private key provided to toggle_hardened_security. Expected key content, got location string."

        key_filepath = APP_DATA_DIR / KEY_FILENAME_TEMPLATE.format(issuer_id=issuer_id)

        try:
            if enable_security:
                # === ENABLING HARDENED SECURITY: File -> Keystore ===
                # Order is critical here to prevent partial states:
                # 1. Save key to keystore first (most critical)
                # 2. Save FTP password if provided
                # 3. Only delete file after both keystore operations succeed

                try:
                    self.crypto_manager.save_private_key_to_keystore(issuer_id, priv_key_pem)
                except Exception as e:
                    logging.error(f"Critical: Failed to save private key to keystore: {e}")
                    raise

                try:
                    if ftp_password:
                        self.crypto_manager.save_ftp_password(issuer_id, ftp_password)
                except Exception as e:
                    # Log but continue - FTP password optional, but warn loudly
                    logging.warning(f"Failed to save FTP password to keystore (key still safe): {e}")

                # Only delete file after keystore operations succeed
                key_filepath.unlink(missing_ok=True)
                new_key_location = KeyStorage.KEYSTORE.value
                logging.info(f"Successfully moved credentials for {issuer_id} to OS keystore")

            else:
                # === DISABLING HARDENED SECURITY: Keystore -> File ===
                # Order is critical:
                # 1. Retrieve key from keystore
                # 2. Write atomically to file (using temp file)
                # 3. Only delete from keystore after file is safe

                key_from_keystore = self.crypto_manager.load_private_key_from_keystore(issuer_id)
                if not key_from_keystore:
                    logging.error(f"Failed to retrieve private key from keystore for {issuer_id}")
                    return False, "Could not retrieve private key from keystore. Key may be lost!"

                # Write key to file atomically using temp file
                key_filepath_tmp = key_filepath.with_suffix('.tmp')
                try:
                    key_filepath_tmp.write_text(key_from_keystore, encoding="utf-8")
                    if os.name == 'posix':
                        os.chmod(key_filepath_tmp, 0o600) # Enforce secure permissions on Unix
                    os.rename(key_filepath_tmp, key_filepath)
                    logging.info(f"Successfully wrote private key to file for {issuer_id}")
                except Exception as e:
                    # Cleanup temp file if write failed
                    key_filepath_tmp.unlink(missing_ok=True)
                    logging.error(f"Failed to write private key to file: {e}")
                    raise

                # Now safe to delete from keystore and credential storage
                try:
                    self.crypto_manager.delete_private_key_from_keystore(issuer_id)
                    self.crypto_manager.delete_ftp_password(issuer_id)
                    logging.info(f"Successfully removed credentials for {issuer_id} from OS keystore")
                except Exception as e:
                    logging.warning(f"Could not fully clean keystore for {issuer_id}: {e}")
                    # Don't fail the operation since file is already safe

                new_key_location = KeyStorage.FILE.value

            return True, new_key_location

        except (IOError, OSError) as e:
            logging.error(f"File system error during security toggle: {e}", exc_info=True)
            return False, f"Could not write security files: {e}"
        except Exception as e:
            logging.error(f"Security operation failed: {e}", exc_info=True)
            return False, f"Could not update security settings: {e}"