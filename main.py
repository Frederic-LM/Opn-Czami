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
# Op'n-Czami - V4.x
#
# SPDX-License-Identifier: LGPL-3.0-or-later

import logging
import sys
import threading
import webbrowser
import platform
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional

# ---------- Third-party imports (with friendly error) ----------
try:
    import tkinter as tk
    from tkinter import ttk, messagebox
    import ttkbootstrap
    import requests
    from packaging import version
    from tkinterdnd2 import TkinterDnD
except ImportError as e:
    print("Missing required libraries to run Op'n-Czami.")
    print("Please run: pip install -r requirements.txt")
    print(f"Missing: {getattr(e, 'name', str(e))}")
    sys.exit(1)

# ---------- Local application imports ----------
from opn_czami import AppConfig
from models.config import APP_LOG_FILE, APP_VERSION
from models.utils import resource_path
from models.app_state import AppState
from services.app_context import AppContext
from ui.app import OpnCzamiApp

# ---------- Constants ----------
GITHUB_USER = "Frederic-LM"
GITHUB_REPO = "Opn-Czami"

# Windows constants (used only on Windows)
WIN_APP_ID = "com.mazloumlevif.opnczami.legato"
WM_SETICON = 0x0080
ICON_BIG = 1
LR_LOADFROMFILE = 0x0010

# ---------- Window class ----------
class DndTtkWindow(ttkbootstrap.Window, TkinterDnD.DnDWrapper):
    """Main application window combining ttkbootstrap and optional DnD."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # TkinterDnD expects a TkdndVersion attribute in some implementations
        try:
            self.TkdndVersion = TkinterDnD._require(self)
        except (AttributeError, ImportError, RuntimeError) as e:
            # FIX: Log the error instead of silently swallowing
            logging.debug(f"TkinterDnD initialization issue (non-critical): {e}")
            self.TkdndVersion = "UnknownDnd"


# ---------- Logging ----------
def _configure_logging():
    """Set up rotating file logging (safe: creates parent dir if needed)."""
    try:
        Path(APP_LOG_FILE).parent.mkdir(parents=True, exist_ok=True)
    except Exception as e:
        # If we cannot create log folder, log to stderr instead and continue
        print(f"Could not create log directory for {APP_LOG_FILE}: {e}")

    handler = RotatingFileHandler(APP_LOG_FILE, maxBytes=5 * 1024 * 1024, backupCount=5, encoding="utf-8")
    formatter = logging.Formatter("%(asctime)s - %(levelname)s - [%(funcName)s] - %(message)s")
    handler.setFormatter(formatter)

    root_logger = logging.getLogger()
    root_logger.handlers.clear()
    root_logger.addHandler(handler)
    root_logger.setLevel(logging.INFO)

    logging.info("--- Application logging initialized ---")


# ---------- Update check ----------
def _notify_update(new_version: str, url: str):
    """Ask the user whether to open the release page."""
    if messagebox.askyesno("Update Available",
                           f"A new version ({new_version}) is available.\n"
                           f"Current version: {APP_VERSION}\n\n"
                           "Open the release page?"):
        webbrowser.open(url)


def _update_worker(root: ttkbootstrap.Window, timeout: int = 5):
    """Background worker that checks GitHub releases/latest and notifies UI."""
    api_url = f"https://api.github.com/repos/{GITHUB_USER}/{GITHUB_REPO}/releases/latest"
    logging.debug(f"[update] checking {api_url}")

    try:
        resp = requests.get(api_url, timeout=timeout, verify=True)
        resp.raise_for_status()
        data = resp.json()
        remote_tag = data.get("tag_name", "")
        if remote_tag:
            remote_ver = remote_tag.lstrip("v")
            try:
                if version.parse(remote_ver) > version.parse(APP_VERSION):
                    download_url = data.get("html_url", "")
                    logging.info(f"[update] newer version found: {remote_ver}")
                    if download_url:
                        root.after(0, _notify_update, remote_ver, download_url)
                else:
                    logging.debug("[update] running latest version")
            except Exception as e:
                logging.warning(f"[update] version comparison failed: {e}")
        else:
            logging.warning("[update] no tag_name in GitHub response")
    except requests.exceptions.RequestException as e:
        logging.debug(f"[update] network error or timeout: {e}")
    except Exception as e:
        logging.warning(f"[update] unexpected error: {e}")


def check_for_updates_threaded(root: ttkbootstrap.Window):
    """Launch the update worker on a daemon thread."""
    threading.Thread(target=_update_worker, args=(root,), daemon=True).start()


# ---------- Platform-specific helpers ----------
# Provide no-op defaults for non-Windows platforms
def _configure_windows_system_properties() -> None:
    """Set DPI awareness and AppUserModelID on Windows, if possible."""
    if platform.system() != "Windows":
        return

    try:
        import ctypes
        from ctypes import windll
        # Try modern API first, fallback if unavailable
        try:
            windll.shcore.SetProcessDpiAwareness(2)
        except (OSError, AttributeError, RuntimeError) as e:
            # FIX: Log specific failure
            logging.debug(f"[win] SetProcessDpiAwareness failed: {e}")
            try:
                windll.user32.SetProcessDPIAware()
            except (OSError, AttributeError, RuntimeError) as e2:
                # FIX: Log specific failure
                logging.debug(f"[win] SetProcessDPIAware failed: {e2}")

        try:
            windll.shell32.SetCurrentProcessExplicitAppUserModelID(WIN_APP_ID)
        except (OSError, AttributeError, RuntimeError) as e:
            # FIX: Log specific failure
            logging.debug(f"[win] SetCurrentProcessExplicitAppUserModelID failed: {e}")

        logging.info("[win] Windows-specific settings applied")
    except Exception as e:
        logging.debug(f"[win] windows helpers could not be applied: {e}")


def _set_windows_icons(root: DndTtkWindow) -> None:
    """Set the window and taskbar icon on Windows where possible."""
    if platform.system() != "Windows":
        return

    try:
        import ctypes
        from ctypes import windll
        icon_path = resource_path("icon.ico")
        if not icon_path.exists():
            logging.debug("[win] icon.ico not found; skipping icon setup")
            return

        try:
            root.iconbitmap(default=str(icon_path))
        except Exception as e:
            # FIX: Log error instead of silent fail
            logging.debug(f"[win] root.iconbitmap failed: {e}")

        # Attempt to set the high-resolution taskbar icon
        try:
            root.update_idletasks()
            hwnd = windll.user32.GetParent(root.winfo_id())
            if hwnd:
                hicon = windll.user32.LoadImageW(None, str(icon_path), 1, 32, 32, LR_LOADFROMFILE)
                if hicon:
                    windll.user32.SendMessageW(hwnd, WM_SETICON, ICON_BIG, hicon)
                    logging.info("[win] taskbar icon set")
                else:
                    logging.debug("[win] LoadImageW returned null")
            else:
                logging.debug("[win] could not obtain hwnd for root window")
        except Exception as e:
            logging.debug(f"[win] error setting high-res icon: {e}")

    except Exception as e:
        logging.debug(f"[win] icon setup could not run: {e}")

# ---------- macOS icon helper ----------
def _set_macos_icon(root: DndTtkWindow) -> None:
    """ macOS: Try to set window icon (works better than nothing during dev)"""
    if platform.system() != "Darwin":
        return

    try:
        icon_path = resource_path("icon.png")
        if not icon_path.exists():
            logging.debug("[mac] icon.png not found; skipping icon setup")
            return

        # Pillow-based approach
        try:
            from PIL import Image, ImageTk
        except ImportError:
            logging.debug("[mac] Pillow not available; cannot set icon.png")
            return

        try:
            img = Image.open(icon_path)
            # macOS window icons benefit from being fairly large
            img = img.resize((256, 256))
            photo = ImageTk.PhotoImage(img)
            root.iconphoto(False, photo)
            logging.info("[mac] macOS icon set successfully")
        except Exception as e:
            logging.debug(f"[mac] failed to load icon.png: {e}")

    except Exception as e:
        logging.debug(f"[mac] _set_macos_icon internal error: {e}")


# ---------- Entrypoint ----------
def main():
    _configure_logging()
    logging.info("=== Application starting ===")

    # Apply Windows tweaks early so DPI is configured before window creation.
    if platform.system() == "Windows":
        _configure_windows_system_properties()

    # Initialize configuration and state
    app_config = AppConfig()
    app_state = AppState(config=app_config)
    logging.info("AppConfig and AppState initialized")

    # Create root window
    root = DndTtkWindow(themename="litera")
    root.withdraw()  # hide until ready

    # Initialize application context & UI
    app_context = AppContext(app_state, None)
    app = OpnCzamiApp(root, app_context=app_context, app_state=app_state)
    app_context.ui_callback = app
    logging.info("UI initialized")

    # Background update check (if allowed in config)
    try:
        if getattr(app_config, "check_for_updates", False):
            check_for_updates_threaded(root)
            logging.info("Update check scheduled")
        else:
            logging.debug("Update check disabled by config")
    except Exception as e:
        logging.debug(f"Could not schedule update check: {e}")

    # Optional license renewal (best-effort, don't crash app if missing)
    pro_handler = getattr(app.logic, "pro_handler", None)
    if pro_handler and hasattr(pro_handler, "check_and_renew_license_on_startup"):
        try:
            pro_handler.check_and_renew_license_on_startup()
            logging.info("Pro license renewal checked")
        except Exception as e:
            logging.warning(f"License renewal check failed: {e}")

    # Platform-specific icon handling (best-effort)
    try:
        if platform.system() == "Windows":
            _set_windows_icons(root)
        elif platform.system() == "Darwin":
            _set_macos_icon(root)
        # other platforms ignored intentionally
    except Exception as e:
        # FIX: Log exception instead of silent ignore
        logging.debug(f"Icon setup raised exception (continuing without icon): {e}")

    root.deiconify()
    try:
        root.mainloop()
    except Exception as e:
        logging.exception(f"Main loop exited with exception: {e}")

    logging.info("=== Application closed ===")


if __name__ == "__main__":
    main()