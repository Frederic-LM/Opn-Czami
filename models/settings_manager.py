# settings_manager.py
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
import logging
import os
from pathlib import Path
from typing import Union
from models.exceptions import SettingsError
from models.secure_storage import KeyStorage

class SettingsManager:
    """Does the loading and saving of the main application settings file."""
    def __init__(self, db_path: Path):
        self.db_path = db_path

    def load_app_data(self) -> tuple[Union[str, None], Union[dict, None]]:
        if not self.db_path.exists():
            return None, None
        try:
            issuers = json.loads(self.db_path.read_text(encoding="utf-8"))
            if not issuers:
                return None, None
            # This logic remains unchanged, as requested.
            issuer_id, issuer_data = list(issuers.items())[0]
            return issuer_id, issuer_data
        except (json.JSONDecodeError, IndexError, Exception) as e:
            raise SettingsError(f"Could not load or parse issuer database: {e}") from e

    def save_app_data(self, all_data: dict):
        """   Safe save    """
      
        tmp_path = self.db_path.with_suffix(self.db_path.suffix + '.tmp')

        try:
            with tmp_path.open("w", encoding="utf-8") as f:
                json.dump(all_data, f, indent=4)
            
            os.replace(tmp_path, self.db_path)
            
            # logging.info("Application data saved successfully.")  # Commented out - verbose log for debugging
        except Exception as e:
            if tmp_path.exists():
                tmp_path.unlink()
            raise SettingsError(f"Could not save issuer database: {e}") from e

    def clear_identity_file(self):
        """Wipes the issuer database file, effectively deleting the identity."""
        self.save_app_data({})

    # ========================================================================
    # SETTINGS SYNC OPERATIONS
    # ========================================================================

    def sync_and_save_settings(self, ui_config_data: dict, ftp_password: str,
                               config, active_issuer_id: str, active_issuer_data: dict,
                               all_issuer_data: dict, crypto_manager) -> bool:
        """
        Synchronizes UI settings with configuration and saves to database.

        Args:
            ui_config_data: Dictionary of settings from UI form
            ftp_password: FTP password from UI (may be empty)
            config: AppConfig instance to update
            active_issuer_id: Current issuer ID
            active_issuer_data: Current issuer's data dict
            all_issuer_data: All issuers' data dict (will be updated)
            crypto_manager: CryptoManager for secure storage operations

        Returns:
            True if saved successfully, False otherwise
        """
        try:
            if not active_issuer_id:
                logging.warning("[SETTINGS_MGR] No active issuer, cannot sync settings")
                return False

            # Update basic settings from UI
            config.ftp_host = ui_config_data.get("ftp_host", "").strip()
            config.ftp_user = ui_config_data.get("ftp_user", "").strip()
            ftp_path_from_ui = ui_config_data.get("ftp_path", "").strip()
            config.ftp_path = ftp_path_from_ui or "/"
            config.watermark_text = ui_config_data.get("watermark_text", "").strip()
            config.legato_files_save_path = ui_config_data.get("legato_files_save_path", "")
            config.enable_audit_trail = ui_config_data.get("enable_audit_trail", False)
            config.ftp_auto_upload = ui_config_data.get("ftp_auto_upload", False)
            config.apply_watermark = ui_config_data.get("apply_watermark", False)
            config.apply_logo_watermark = ui_config_data.get("apply_logo_watermark", False)
            config.randomize_lkey_name = ui_config_data.get("randomize_lkey_name", False)
            config.doc_num_mask = ui_config_data.get("doc_num_mask", "")
            config.check_for_updates = ui_config_data.get("check_for_updates", True)
            config.enable_insights_logging = ui_config_data.get("enable_insights_logging", False)

            # Determine if key is in secure storage
            is_key_secured = active_issuer_data.get("priv_key_pem") == KeyStorage.KEYSTORE.value

            # Handle FTP password based on key storage location
            if is_key_secured:
                # Key is in keystore - try to store FTP password securely there
                keystore_save_success = False
                if ftp_password:
                    try:
                        crypto_manager.save_ftp_password(active_issuer_id, ftp_password)
                        keystore_save_success = True
                        config.ftp_pass_b64 = ""  # Clear fallback if keystore succeeded
                        logging.debug("[SETTINGS_MGR] FTP password saved to OS keystore")
                    except Exception as e:
                        logging.warning(f"[SETTINGS_MGR] Failed to save FTP password to keystore: {e}. Using fallback.")
                        # Fall through to save in config as backup
                        config.ftp_pass_b64 = base64.b64encode(ftp_password.encode("utf-8")).decode("utf-8")

                # If we couldn't save to keystore AND no password provided, clear the fallback
                if not keystore_save_success and not ftp_password:
                    config.ftp_pass_b64 = ""
            else:
                # Key is in file - store FTP password in config (base64 encoded)
                if ftp_password:
                    config.ftp_pass_b64 = base64.b64encode(ftp_password.encode("utf-8")).decode("utf-8")
                else:
                    config.ftp_pass_b64 = ""

            # Handle Filebase credentials if provided
            filebase_creds = ui_config_data.pop("filebase_creds", {})
            if filebase_creds:
                crypto_manager.save_filebase_credentials(
                    active_issuer_id,
                    filebase_creds.get("key", ""),
                    filebase_creds.get("secret", "")
                )
                # Also save the non-sensitive bucket name to the main settings DB
                if "settings" not in all_issuer_data.get(active_issuer_id, {}):
                    all_issuer_data[active_issuer_id]["settings"] = {}
                all_issuer_data[active_issuer_id]["settings"]["filebase_bucket"] = filebase_creds.get("bucket", "")

            # Convert config to database dict and merge
            db_settings = config.to_db_dict()

            if active_issuer_id in all_issuer_data:
                all_issuer_data[active_issuer_id]["settings"].update(db_settings)
                try:
                    self.save_app_data(all_issuer_data)
                    # logging.info("[SETTINGS_MGR] Settings synchronized and saved to database")  # Commented out - verbose log for debugging
                    return True
                except SettingsError as e:
                    logging.error(f"[SETTINGS_MGR] Failed to save settings: {e}")
                    return False
            else:
                logging.warning(f"[SETTINGS_MGR] Issuer {active_issuer_id} not found in database")
                return False

        except Exception as e:
            logging.error(f"[SETTINGS_MGR] Exception during settings sync: {e}", exc_info=True)
            return False