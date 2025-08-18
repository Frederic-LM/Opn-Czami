import logging
from tkinter import messagebox
from pathlib import Path

# --- Application-Specific Enums & Data Structures ---
from enum import Enum

class KeyStorage(Enum):
    """Enumeration for where a private key is stored."""
    KEYSTORE = "STORED_IN_KEYSTORE"
    FILE = "STORED_IN_FILE"

# --- Helper Functions ---
def show_error(title: str, message: str, log_error: bool = True):
    """Convenience function for showing a messagebox error and logging it."""
    if log_error:
        logging.error(f"{title}: {message}")
    messagebox.showerror(title, message)

def show_info(title: str, message: str):
    """Convenience function for showing a messagebox info dialog."""
    logging.info(f"{title}: {message}")
    messagebox.showinfo(title, message)
