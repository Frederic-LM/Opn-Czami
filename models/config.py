# config.py
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




import sys
from pathlib import Path
from models.utils import get_app_data_path


# --- Application Constants ---
APP_VERSION = "4.2.5"
APP_NAME = "OpnCzami"
KEYRING_SERVICE_NAME = "Abracadabra"
KEY_CHUNK_SIZE = 1000  # (windows hack) we split the secrets otherwise windows find it too long to be stored -_-
MAX_SUMMARY_CHARS = 400
MAX_LOGO_SIZE_BYTES = 256 * 1024  # 256 KB
MAX_LOGO_PIXELS = 74000  # Approx. 400x185 (recomended)
STANDARDIZED_LOGO_BASENAME = "my-legato-link-logo"

# --- Buffer/Chunk Size Constants ---
HASH_BUFFER_SIZE = 4096  # Buffer size for file hashing operations
DOWNLOAD_CHUNK_SIZE = 8192  # Chunk size for HTTP downloads

# --- Network Constants ---
FTP_TIMEOUT_SECONDS = 15  # Standard timeout setting for FTP
FTP_MAX_RETRIES = 3  # Max retry attempts
FTP_RETRY_DELAY = 2  # Be polite (seconds between retries)

# HTTP Request Timeouts (seconds)
HTTP_TIMEOUT_INSTANT = 3  # For startup checks (fail fast)
HTTP_TIMEOUT_SHORT = 10  # For quick API calls (version checks, info fetches)
HTTP_TIMEOUT_STANDARD = 15  # For standard operations (license renewal)
HTTP_TIMEOUT_LONG = 20  # For backend operations (anchoring, registrations)

# --- Path Definitions ---
APP_DATA_DIR = get_app_data_path(APP_NAME)
USER_DOCS_DIR = Path.home() / "Documents"
APP_DOCS_DIR = USER_DOCS_DIR / APP_NAME
SCRIPT_DIR = Path(sys.argv[0] if getattr(sys, "frozen", False) else __file__).parent
ISSUER_DB_FILE = APP_DATA_DIR / "opn_czami_settings.json"
KEY_FILENAME_TEMPLATE = "abracadabra-{issuer_id}.key"
INFO_FILENAME = "my-legato-link.json"
AUDIT_LOG_FILENAME_TEMPLATE = "Audit-Trail-{issuer_id}.log"
LOG_DIR = APP_DATA_DIR / "logs"
APP_LOG_FILE = LOG_DIR / "opn-czami-app.log"

# --- Directory Creation ---
(APP_DOCS_DIR / "Legato_Keys").mkdir(parents=True, exist_ok=True)
LOG_DIR.mkdir(parents=True, exist_ok=True)


# --- Application-Specific ---
# (Leaving these here for future functionality expansion but as Enums)
DOC_TYPES = {
    "2": "Valuation Letter", "3": "Report", "4": "Other"
}
ITEM_TYPES = {
    "1": "Violin", "2": "Viola", "3": "Cello", "4": "Double Bass",
    "5": "Violin bow", "6": "Viola bow", "7": "Cello bow", "8": "Double Bass bow",
    "9": "Custom", "10": "Custom bow"
}
DOC_TYPES_REVERSE = {v: k for k, v in DOC_TYPES.items()}
ITEM_TYPES_REVERSE = {v: k for k, v in ITEM_TYPES.items()}

# --- Pro Feature Constants ---
# Note: These are used for UI organization and as references in the codebase.
# The actual licensing system is ALL-OR-NOTHING (see license_manager.py:is_feature_enabled()).
# All features are gated by a single license flag, regardless of which feature name is used.
FEATURE_WATERMARK = "watermark"
FEATURE_AUDIT = "audit"
FEATURE_BATCH = "batch"
FEATURE_MASKED_IDS = "masked_ids"
FEATURE_DASHBOARD = "dashboard"