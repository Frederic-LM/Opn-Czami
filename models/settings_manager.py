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

import json
import logging
import os
from pathlib import Path
from typing import Union
from models.exceptions import SettingsError

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
            
            logging.info("Application data saved successfully.")
        except Exception as e:
            if tmp_path.exists():
                tmp_path.unlink()
            raise SettingsError(f"Could not save issuer database: {e}") from e

    def clear_identity_file(self):
        """Wipes the issuer database file, effectively deleting the identity."""
        self.save_app_data({})