import json
import logging
from pathlib import Path
from typing import Union

# Import from our new utils file
from models.utils import show_error

class SettingsManager:
    """Handles loading and saving of the main application settings file."""
    def __init__(self, db_path: Path):
        self.db_path = db_path

    def load_app_data(self) -> tuple[Union[str, None], Union[dict, None]]:
        """
        Loads the issuer data from the JSON file.
        Returns the first issuer ID found and their data dictionary.
        """
        if not self.db_path.exists():
            return None, None
        try:
            issuers = json.loads(self.db_path.read_text(encoding="utf-8"))
            if not issuers:
                return None, None
            # The app is designed to handle only one identity at a time.
            issuer_id, issuer_data = list(issuers.items())[0]
            return issuer_id, issuer_data
        except (json.JSONDecodeError, IndexError, Exception) as e:
            show_error("DB Load Error", f"Could not load or parse issuer database: {e}")
            return None, None

    def save_app_data(self, all_data: dict):
        """Saves the provided data dictionary to the JSON settings file."""
        try:
            with self.db_path.open("w", encoding="utf-8") as f:
                json.dump(all_data, f, indent=4)
            logging.info("Application data saved successfully.")
        except Exception as e:
            show_error("DB Save Error", f"Could not save issuer database: {e}")

    def clear_identity_file(self):
        """Wipes the issuer database file, effectively deleting the identity."""
        self.save_app_data({})
