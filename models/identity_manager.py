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

from .crypto_manager import CryptoManager, KeyStorage
from .settings_manager import SettingsManager
from .config import APP_DATA_DIR, INFO_FILENAME, KEY_FILENAME_TEMPLATE


class IdentityManager:
    """Does the creation, deletion, and security of the user's issuer identity."""

    def __init__(self, crypto_manager: CryptoManager, settings_manager: SettingsManager):
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
                json_content["logoUrl"] = url_path + logo_path.name
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

    def delete_active_identity(self, issuer_id: str):
        """ Delete all identity files and settings."""
        if not issuer_id: return False, "No active issuer ID provided."
        
        # Semi "atomic" deletion, not as important as for the creataion.

        try:
            (APP_DATA_DIR / KEY_FILENAME_TEMPLATE.format(issuer_id=issuer_id)).unlink(missing_ok=True)
            audit_log_path = self.crypto_manager.get_audit_log_path(issuer_id)
            if audit_log_path.exists(): audit_log_path.unlink()
            
            self.crypto_manager.delete_private_key_from_keystore(issuer_id)
            self.crypto_manager.delete_ftp_password(issuer_id)
            self.crypto_manager.delete_filebase_credentials(issuer_id)
            self.settings_manager.clear_identity_file()

            logging.info(f"Identity {issuer_id} and all associated files have been deleted.")
            return True, "Identity deleted successfully."
        except (IOError, OSError) as e:
            logging.error(f"File system error during identity deletion: {e}", exc_info=True)
            return False, f"Could not delete all identity files: {e}"
        except Exception as e:
            logging.error(f"Error during identity deletion: {e}", exc_info=True)
            return False, f"Could not completely delete identity: {e}"

    def toggle_hardened_security(self, enable_security: bool, issuer_id: str, priv_key_pem: str, ftp_password: str) -> tuple[bool, str]:
        """Moves sensible info between file and OS Keystore."""
        if not issuer_id: 
            return False, "No active issuer."
            
        key_filepath = APP_DATA_DIR / KEY_FILENAME_TEMPLATE.format(issuer_id=issuer_id)

        try:
            if enable_security:
                # Save to keystore first, then delete file.
                self.crypto_manager.save_private_key_to_keystore(issuer_id, priv_key_pem)
                self.crypto_manager.save_ftp_password(issuer_id, ftp_password)
                key_filepath.unlink(missing_ok=True)
                new_key_location = KeyStorage.KEYSTORE.value
            else:
                # Disabling security: Write key back to file .
                key_from_keystore = self.crypto_manager.load_private_key_from_keystore(issuer_id)
                key_to_write = key_from_keystore or priv_key_pem
                
                key_filepath_tmp = key_filepath.with_suffix('.tmp')
                try:
                    key_filepath_tmp.write_text(key_to_write, encoding="utf-8")
                    if os.name == 'posix':
                        os.chmod(key_filepath_tmp, 0o600) # Enforce secure permissions for the Unixoid.
                    os.rename(key_filepath_tmp, key_filepath)
                finally:
                    key_filepath_tmp.unlink(missing_ok=True)

                # Once the file is safely written, delete from keystore.
                self.crypto_manager.delete_private_key_from_keystore(issuer_id)
                self.crypto_manager.delete_ftp_password(issuer_id)
                new_key_location = KeyStorage.FILE.value
            
            return True, new_key_location
        
        except (IOError, OSError) as e:
            logging.error(f"File system error during security toggle: {e}", exc_info=True)
            return False, f"Could not write security files: {e}"
        except Exception as e:
            logging.error(f"Security operation failed: {e}", exc_info=True)
            return False, f"Could not update security settings: {e}"