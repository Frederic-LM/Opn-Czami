# --- START OF FILE models/utils.py (FINAL, CORRECTED VERSION) ---

# utils.py

import sys
import logging
from pathlib import Path

# --- Platform-specific Conditional Imports for Message Boxes ---
# This check isolates Tkinter to ONLY non-macOS platforms, preserving the Windows experience.
TKINTER_MESSAGEBOX_AVAILABLE = False
if sys.platform != 'darwin':
    try:
        # NOTE: This import will now work because you are running Tkinter/ttkbootstrap on Windows/Linux
        from tkinter import messagebox 
        TKINTER_MESSAGEBOX_AVAILABLE = True
    except ImportError:
        pass


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
    """ 
    FIXED: Get absolute path to resource. Uses sys.argv[0] for reliable project root detection 
    in development/script mode, regardless of where the module file is located.
    """
    try:
        # 1. PyInstaller Path (always available in frozen environment)
        base_path = Path(sys._MEIPASS)
    except AttributeError:
        # 2. Development/Script Run Path
        # Get the directory of the script that *started* the application (e.g., opnczamimac.py)
        # This is CRITICAL for preventing failure when run directly or when module paths change.
        base_path = Path(sys.argv[0]).parent.resolve()
        
    return base_path / "assets" / relative_path

def show_error(title: str, message: str, log_error: bool = True):
    """
    FIXED: Convenience function for showing a messagebox error and logging it.
    Uses tkinter.messagebox only if not on macOS.
    """
    if log_error:
        logging.error(f"{title}: {message}")

    # Only display the Tkinter message box if on a supported OS (non-Mac)
    if TKINTER_MESSAGEBOX_AVAILABLE:
        messagebox.showerror(title, message)

def show_info(title: str, message: str):
    """
    FIXED: Convenience function for showing a messagebox info dialog.
    Uses tkinter.messagebox only if not on macOS.
    """
    logging.info(f"{title}: {message}")
    
    # Only display the Tkinter message box if on a supported OS (non-Mac)
    if TKINTER_MESSAGEBOX_AVAILABLE:
        messagebox.showinfo(title, message)
        
# --- END OF FILE models/utils.py ---
