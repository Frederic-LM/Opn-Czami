# main.py
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
# Op'n-Czami - V3.x

# --- Standard Library Imports ---
import logging
import sys
import threading
import webbrowser
from logging.handlers import RotatingFileHandler
from pathlib import Path

# --- Third-Party Imports ---
try:
    import ttkbootstrap as ttk
    from tkinterdnd2 import TkinterDnD
    from tkinter import messagebox
    import requests
    from packaging import version
except ImportError:
    print("You are missing the required libraries to run Op'n-Czmi! Please use requirements.txt to install them")
    sys.exit(1)

# --- Local Application Imports ---
from models.config import APP_LOG_FILE, APP_VERSION
from models.utils import resource_path

# --- GUI import ---
from ui.app import OpnCzamiApp

# --- Application Update Constants ---
GITHUB_USER = "Frederic-LM"
GITHUB_REPO = "Opn-Czami"


class DndTtkWindow(ttk.Window, TkinterDnD.DnDWrapper):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.TkdndVersion = TkinterDnD._require(self)

def _configure_logging():
    log_formatter = logging.Formatter("%(asctime)s - %(levelname)s - [%(funcName)s] - %(message)s")
    log_handler = RotatingFileHandler(APP_LOG_FILE, maxBytes=5*1024*1024, backupCount=5, encoding='utf-8')
    log_handler.setFormatter(log_formatter)
    logger = logging.getLogger()
    logger.handlers.clear()
    logger.addHandler(log_handler)
    logger.setLevel(logging.INFO)
    logging.info("--- Application Logging Started ---")


# --- Update Check Logic (non tested yet)---

def _show_update_notification(new_version_str: str, download_url: str):
    """Displays a message box to the user about the new version."""
    if messagebox.askyesno(
        "Update Available",
        f"A new version ({new_version_str}) of Op'n-Czami is available!\n\n"
        f"Your current version is {APP_VERSION}.\n\n"
        "Would you like to go to the download page?"
    ):
        webbrowser.open(download_url)

def _update_check_worker(root: ttk.Window):
    """
    Worker function to be run in a background thread.
    Checks GitHub for the latest release and schedules a UI notification if needed.
    """
    try:
        api_url = f"https://api.github.com/repos/{GITHUB_USER}/{GITHUB_REPO}/releases/latest"
        response = requests.get(api_url, timeout=10)
        response.raise_for_status()  

        data = response.json()
        remote_version_str = data.get("tag_name", "").lstrip('v')
        local_version_str = APP_VERSION

        if not remote_version_str:
            logging.warning("Could not find version tag in GitHub API response.")
            return

        if version.parse(remote_version_str) > version.parse(local_version_str):
            logging.info(f"New version found: {remote_version_str}. Current: {local_version_str}")
            download_url = data.get("html_url")
            if download_url:
                # Schedule the messagebox to be shown on the main UI thread
                root.after(0, _show_update_notification, remote_version_str, download_url)

    except requests.exceptions.RequestException as e:
        logging.error(f"Failed to check for updates (network error): {e}")
    except Exception as e:
        logging.error(f"An unexpected error occurred during update check: {e}", exc_info=True)

def check_for_updates_threaded(root: ttk.Window):
    """Starts the update check in a non-blocking background thread."""
    threading.Thread(target=_update_check_worker, args=(root,), daemon=True).start()


if __name__ == "__main__":
    _configure_logging()
    logging.info("================ Application Starting ================")


    if sys.platform == "win32":
        # --- Win32 specific Constants ---
        WIN_APP_ID = "com.mazloumlevif.opnczami.legato"
        WM_SETICON = 0x0080
        ICON_BIG = 1
        LR_LOADFROMFILE = 0x0010

        try:
            import ctypes
            from ctypes import windll  
            # Set DPI awareness
            try:
                windll.shcore.SetProcessDpiAwareness(2)
            except (AttributeError, OSError):
                # Fallback for older Windows versions
                windll.user32.SetProcessDPIAware()
            
            # Set AppUserModelID for proper taskbar grouping and notifications
            windll.shell32.SetCurrentProcessExplicitAppUserModelID(WIN_APP_ID)

        except Exception as e:
            logging.error(f"Could not set Windows-specific properties: {e}")

    root = DndTtkWindow(themename="litera")
    root.withdraw()

    app = OpnCzamiApp(root)

    # --- Trigger the update check after the app is initialized ---
    check_for_updates_threaded(root)
    # Trigger the Pro license check (only if pro features are available).
    # This now contains the logic to only call home if the local key is expired.
    if hasattr(app.logic.pro_handler, 'check_and_renew_license_on_startup'):
        app.logic.pro_handler.check_and_renew_license_on_startup()

    if sys.platform == "win32":
        try:
            icon_path = resource_path("icon.ico")
            if icon_path.exists():
                root.iconbitmap(default=str(icon_path))
                
                windll = ctypes.windll
                root.update_idletasks()
                hwnd = windll.user32.GetParent(root.winfo_id())
                if hwnd:
                    h_icon_big = windll.user32.LoadImageW(None, str(icon_path), 1, 32, 32, LR_LOADFROMFILE)
                    if h_icon_big:
                        windll.user32.SendMessageW(hwnd, WM_SETICON, ICON_BIG, h_icon_big)
                else:
                    logging.warning("Could not find window handle to set high-res taskbar icon.")
        except Exception as e:

            logging.error(f"Failed to set Windows taskbar icon: {e}", exc_info=True)

    root.deiconify()
    root.mainloop()

    logging.info("================ Application Closed ================\n")