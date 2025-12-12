# utils.py
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
import sys
import logging
from pathlib import Path

# --- non Mac Mac cuisine because they think different ---
# isolates Tkinter to ONLY non-macOS platforms, preserving the Windows experience.
TKINTER_MESSAGEBOX_AVAILABLE = False
if sys.platform != 'darwin':
    try:
        # NOTE: This now work because we are running on Windows/Linux
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
    FIXED: Get absolute path to resource. Uses sys.argv[0] for reliable root detection
    in both executable and py environments.
    """
    try:
        # 1. PyInstaller Path
        base_path = Path(sys._MEIPASS)
    except AttributeError:
        # 2. Script Run Path
        # Get the directory of the script that *started* the application (e.g., opnczami_mac.py)
        # CRITICAL for preventing failure if module paths change.
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