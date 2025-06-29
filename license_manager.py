# license_manager.py
# Op'n-Czami
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

import base64
import json
import sys
import shutil
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
from typing import Union


def get_app_data_path(app_name="OpnCzami") -> Path:
    """Returns the standard OS-specific path for application data."""
    if sys.platform == "win32":
        path = Path.home() / "AppData" / "Roaming" / app_name
    elif sys.platform == "darwin":  # macOS
        path = Path.home() / "Library" / "Application Support" / app_name
    else:  # Linux
        path = Path.home() / ".local" / "share" / app_name

    path.mkdir(parents=True, exist_ok=True)
    return path


class LicenseManager:
    """Manages verification of the pro license key."""
# In license_manager.py

    def __init__(self, app_base_path: Path, app_data_path: Path):

        if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):

            self.app_base_path = Path(sys._MEIPASS)
        else:

            self.app_base_path = app_base_path

        self.app_data_path = app_data_path
        self.public_key_file = self.app_base_path / "license_public.pem"

        self.is_licensed = False
        self.enabled_features = set()
        self.customer_info = "Not Active"
        self._load_and_verify_license()

    def _get_license_path(self) -> Union[Path, None]:
        """Finds the license.key file in standard locations."""
        app_data_license = self.app_data_path / "license.key"
        if app_data_license.exists():
            return app_data_license

        exe_license = self.app_base_path / "license.key"
        if exe_license.exists():
            return exe_license
        return None

    def _load_and_verify_license(self, license_key_path: Union[Path, None] = None) -> bool:
        """
        Attempts to load and verify a license key.
        Returns True on success, False on failure.
        """
        key_file_to_check = license_key_path or self._get_license_path()

        self.is_licensed = False
        self.enabled_features = set()
        self.customer_info = "Not Active"

        if not self.public_key_file.exists():

            return False

        if not key_file_to_check or not key_file_to_check.exists():
            return False

        try:
            with open(self.public_key_file, "rb") as f:
                public_key = serialization.load_pem_public_key(f.read())

            license_key = key_file_to_check.read_text().strip()
            payload_b64, signature_b64 = license_key.split('.', 1)
            payload_json = base64.b64decode(payload_b64)
            signature = base64.b64decode(signature_b64)

            public_key.verify(
                signature, payload_json,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )

            payload = json.loads(payload_json)
            self.is_licensed = True
            self.enabled_features = set(payload.get("features", []))
            self.customer_info = payload.get("customer", "Licensed User")
            return True

        except (InvalidSignature, ValueError, json.JSONDecodeError, TypeError):

            self.customer_info = "Invalid/Tampered Key"
            return False
        except Exception:

            self.customer_info = "Verification Error"
            return False

    def activate_from_path(self, dropped_path: Path) -> bool:
        """
        Verifies a license file and copies it to the persistent app data folder.
        This now uses self.app_data_path instead of taking it as a redundant argument.
        """
        if self._load_and_verify_license(license_key_path=dropped_path):

            target_path = self.app_data_path / "license.key"
            try:
                shutil.copy(dropped_path, target_path)
                return True
            except (IOError, OSError) as e:

                self.customer_info = f"Copy Failed: {e}"
                return False
        else:

            return False

    def is_feature_enabled(self, feature_name: str) -> bool:
        """Checks if a specific pro feature is enabled by the license."""
        return feature_name in self.enabled_features
