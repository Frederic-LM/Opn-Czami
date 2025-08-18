# utils.py

import sys
import logging
from pathlib import Path
from tkinter import messagebox

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

def resource_path(relative_path: str) -> Path:
    """ Get absolute path to resource, works for dev and for PyInstaller. """
    try:
        base_path = Path(sys._MEIPASS)
    except AttributeError:
        base_path = Path(__file__).parent.resolve()
    return base_path / "assets" / relative_path

def show_error(title: str, message: str, log_error: bool = True):
    """Convenience function for showing a messagebox error and logging it."""
    if log_error:
        logging.error(f"{title}: {message}")
    messagebox.showerror(title, message)

def show_info(title: str, message: str):
    """Convenience function for showing a messagebox info dialog."""
    logging.info(f"{title}: {message}")
    messagebox.showinfo(title, message)
