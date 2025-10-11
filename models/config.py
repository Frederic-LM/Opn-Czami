# config.py

import sys
from pathlib import Path
from .utils import get_app_data_path

# --- Application Constants ---
APP_VERSION = "2.0.1"
APP_NAME = "OpnCzami"
KEYRING_SERVICE_NAME = "OperatorIssuerApp"
KEY_CHUNK_SIZE = 1000  # For splitting secrets for keyring storage
MAX_SUMMARY_CHARS = 400
MAX_LOGO_SIZE_BYTES = 256 * 1024  # 256 KB
MAX_LOGO_PIXELS = 74000  # Approx. 400x185
STANDARDIZED_LOGO_BASENAME = "my-legato-link-logo"

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


# --- Application-Specific Enums & Data Structures ---

# Document and Item type definitions
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
