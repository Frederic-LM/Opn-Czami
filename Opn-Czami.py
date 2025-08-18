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
# along with this program.  If not, see
# <https://www.gnu.org/licenses/>.
# 

# --- Standard Library Imports ---
import base64
import base45
import cbor2
import datetime
import io
import json
import logging
import math
import os
import posixpath
import random
import shutil
import string
import subprocess
import sys
import tempfile
import threading
import webbrowser
import zlib
from dataclasses import dataclass
from enum import Enum
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Union
from urllib.parse import urlparse

# --- Third-Party Imports ---
import qrcode
import requests
import ttkbootstrap as ttk
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from PIL import Image, ImageDraw, ImageFont, ImageTk
from ttkbootstrap.constants import *
from ttkbootstrap.scrolled import ScrolledText
from ttkbootstrap.tableview import Tableview
from tkinter import filedialog, messagebox

try:
    import pyzipper
    PYZIPPER_AVAILABLE = True
except ImportError:
    PYZIPPER_AVAILABLE = False

try:
    import pandas as pd
    PANDAS_AVAILABLE = True
except ImportError:
    PANDAS_AVAILABLE = False


# --- Local Application Imports ---
from config import *
from utils import *
from settings_manager import SettingsManager
from ftp_manager import FTPManager
from crypto_manager import CryptoManager, KeyStorage
from license_manager import LicenseManager

# --- Pro Features Handling ---
try:
    from pro_features import ProFeatures
    PRO_FEATURES_AVAILABLE = True
except ImportError:
    PRO_FEATURES_AVAILABLE = False
    class ProFeatures:
        """A mock class for when pro features are not installed."""
        def __init__(self, app_instance, app_data_path=None):
            logging.warning("Pro features module not found. Pro functionality is disabled.")
        def load_data_file(self): pass
        def process_batch_threaded(self): pass
        def load_and_verify_audit_log(self, *args):
            return [], False, "Pro features are not available.", DANGER

# --- Application-Specific Enums & Data Structures ---
class FTPMode(Enum):
    """Enumeration for FTP upload mode."""
    MANUAL = "Manual"
    AUTOMATIC = "Automatic"

class UploadButtonState(Enum):
    """Enumeration for the states of the main upload button."""
    INITIAL = ("🚀 Upload LKey", SECONDARY, "disabled")
    READY = ("🚀 Upload LKey", PRIMARY, "normal")
    UPLOADING = ("Uploading...", WARNING, "disabled")
    SUCCESS = ("Upload Successful!", SUCCESS, "normal")
    FAILURE = ("Upload Failed! (Retry)", DANGER, "normal")

class FormState(Enum):
    """Represents the state of a form (e.g., has it been changed)."""
    PRISTINE = 1
    DIRTY = 2
    TESTING = 3

@dataclass
class AppConfig:
    """Holds the application's user-configurable settings."""
    randomize_lkey_name: bool = False
    apply_watermark: bool = False
    apply_logo_watermark: bool = False
    watermark_text: str = "SIGNED"
    legato_files_save_path: str = ""
    ftp_host: str = ""
    ftp_user: str = ""
    ftp_path: str = ""
    ftp_pass_b64: str = ""  # Base64 encoded, used only when not in hardened mode
    ftp_auto_upload: bool = False
    hardened_security: bool = False
    enable_audit_trail: bool = False

    def __post_init__(self):
        """Set default save path if it is not provided."""
        if not self.legato_files_save_path:
            self.legato_files_save_path = str(APP_DOCS_DIR / "Legato_Keys")

# --- Core Application Logic Classes ---
      
class ImageProcessor:
    """Handles all image manipulation tasks like watermarking and QR code generation."""
    def __init__(self, checkmark_icon_path: Union[Path, None]):
        self.resample_method = Image.Resampling.LANCZOS if hasattr(Image, "Resampling") else Image.LANCZOS
        self.checkmark_icon_pil = None
        if checkmark_icon_path and checkmark_icon_path.exists():
            try:
                self.checkmark_icon_pil = Image.open(checkmark_icon_path).convert("RGBA")
            except Exception as e:
                logging.warning(f"Could not load checkmark icon '{checkmark_icon_path}'. Error: {e}")

    def apply_text_watermark(self, image_pil: Image.Image, text: str, apply: bool) -> Image.Image:
        """Applies a centered text watermark to an image if 'apply' is True."""
        if not apply:
            return image_pil
        
        image = image_pil.copy().convert("RGBA")
        text_layer = Image.new("RGBA", image.size, (255, 255, 255, 0))
        draw = ImageDraw.Draw(text_layer)
        
        font_size = int(image.width / 10)
        try:
            font = ImageFont.truetype("arial.ttf", font_size)
        except IOError:
            font = ImageFont.load_default()

        text_bbox = draw.textbbox((0, 0), text, font=font)
        pos = (
            (image.width - (text_bbox[2] - text_bbox[0])) // 2,
            (image.height - (text_bbox[3] - text_bbox[1])) // 2,
        )
        draw.text(pos, text, font=font, fill=(255, 255, 255, 128))
        return Image.alpha_composite(image, text_layer)

    def apply_logo_watermark(self, image_pil: Image.Image, logo_pil: Union[Image.Image, None], apply: bool) -> Image.Image:
        """Applies a logo watermark to the bottom-right corner if 'apply' is True."""
        if not apply or not logo_pil:
            return image_pil

        image = image_pil.copy().convert("RGBA")
        logo = logo_pil.copy().convert("RGBA")
        
        # Make logo semi-transparent
        try:
            alpha = logo.getchannel('A')
            alpha = alpha.point(lambda p: p * 0.5)
            logo.putalpha(alpha)
        except (IndexError, ValueError): # No alpha channel or not RGBA
            pass
        
        logo.thumbnail((int(image.width * 0.25), image.height), self.resample_method)
        margin = int(image.width * 0.02)
        pos = (image.width - logo.width - margin, image.height - logo.height - margin)
        
        image.paste(logo, pos, mask=logo)
        return image

    def overlay_checkmark(self, background_pil: Image.Image, scale_ratio: float = 0.8) -> Image.Image:
        """Overlays the checkmark icon in the center of an image."""
        if not background_pil or not self.checkmark_icon_pil:
            return background_pil
        
        background = background_pil.copy().convert("RGBA")
        overlay = self.checkmark_icon_pil
        
        target_width = int(background.width * scale_ratio)
        target_height = int(target_width * (overlay.height / overlay.width))
        overlay_resized = overlay.resize((target_width, target_height), self.resample_method)
        
        offset = (
            (background.width - overlay_resized.width) // 2,
            (background.height - overlay_resized.height) // 2,
        )
        background.paste(overlay_resized, offset, mask=overlay_resized)
        return background

    def generate_qr_with_logo(
        self,
        data: str,
        logo_pil: Union[Image.Image, None],
        box_size: int = 10,
        sizing_ratio: float = 0.28
    ) -> Image.Image:
        """Generates a QR code with an optional logo embedded in the center."""
        qr = qrcode.QRCode(
            error_correction=qrcode.constants.ERROR_CORRECT_H,
            box_size=box_size,
            border=4,
        )
        qr.add_data(data)
        qr.make(fit=True)
        qr_img = qr.make_image(fill_color="black", back_color="white").convert("RGBA")

        if logo_pil:
            logo_resized = logo_pil.copy().convert("RGBA")
            logo_max_size = (
                int(qr_img.width * sizing_ratio),
                int(qr_img.height * sizing_ratio),
            )
            logo_resized.thumbnail(logo_max_size, self.resample_method)
            
            pos = (
                (qr_img.width - logo_resized.width) // 2,
                (qr_img.height - logo_resized.height) // 2,
            )
            qr_img.paste(logo_resized, pos, mask=logo_resized)
        
        return qr_img.convert("RGB")

class IssuerApp:
   
    def __init__(self, root: ttk.Window):
        self.root = root
        self._configure_root_window()
        self._init_managers_and_config()
        self._init_state_variables()
        self._init_ui()
        self._load_and_display_initial_data()
        self._bind_events()

    def _configure_root_window(self):
        """Sets up the main application window properties."""
        self.root.title("Op’n-Czami - Legato-Key Certification Authority Dashboard")
        self.root.geometry("1260x970")
        self.root.minsize(1260, 980)
        self.root.resizable(False, True)
        self._set_window_icon()

    def _init_managers_and_config(self):
        """Initializes all manager classes and the application configuration."""
        self._configure_logging()
        self.settings_manager = SettingsManager(ISSUER_DB_FILE)
        self.crypto_manager = CryptoManager(KEYRING_SERVICE_NAME, APP_DATA_DIR)
        self.image_processor = ImageProcessor(resource_path("checkmark.png"))
        self.ftp_manager = FTPManager()
        self.license_manager = LicenseManager(SCRIPT_DIR, APP_DATA_DIR)
        self.logging = logging
        self.pro_handler = ProFeatures(self, APP_DATA_DIR)
        self.config = AppConfig()
        
    def _init_state_variables(self):
        """Initializes all Tkinter variables and internal state flags."""
        self.active_issuer_id = None
        self.active_issuer_data = None
        self.active_issuer_contact_info = {}
        self.all_issuer_data = {}
        self.system_is_verified = False
        self.is_generating = False
        self.selected_image_file_path = None
        self.prepared_upload_path = None
        self.last_signed_payload = None
        self.upload_button_state = UploadButtonState.INITIAL
        self.qr_image_pil = None
        self.issuer_qr_image_pil = None
        self.lkey_image_pil = None
        self.lkey_image_tk = None
        self.original_status_logo_pil = None
        self.logo_path = None
        # --- Variables for Enhanced Signing ---
        self.include_doc_num_var = ttk.BooleanVar(value=False)
        self.auto_gen_doc_num_var = ttk.BooleanVar(value=False)
        self.doc_num_var = ttk.StringVar()
        self.use_mask_var = ttk.BooleanVar(value=False)     
        self.mask_string_var = ttk.StringVar(value="####-MM/YY") 
        # --- END OF NEW VARIABLES ---
        self.url_path_var = ttk.StringVar(value="https://")
        self.image_base_url_var = ttk.StringVar()
        self.ftp_host_var = ttk.StringVar()
        self.ftp_user_var = ttk.StringVar()
        self.ftp_pass_var = ttk.StringVar()
        self.ftp_path_var = ttk.StringVar()
        self.show_pass_var = ttk.BooleanVar(value=False)
        self.watermark_text_var = ttk.StringVar()
        self.legato_files_save_path_var = ttk.StringVar()
        self.hardened_security_var = ttk.BooleanVar()
        self.enable_audit_trail_var = ttk.BooleanVar()
        self.ftp_auto_upload_var = ttk.BooleanVar()
        self.apply_watermark_var = ttk.BooleanVar()
        self.apply_logo_watermark_var = ttk.BooleanVar()
        self.randomize_lkey_name_var = ttk.BooleanVar()
        self.ftp_form_state = FormState.PRISTINE

    def _init_ui(self):
        """Creates all the UI components of the application."""
        self.create_status_panel()
        self.create_main_ui()

    def _load_and_display_initial_data(self):
        """Loads issuer data from files and populates the UI accordingly."""
        self.populate_ui_from_config() # Set defaults first
        self.load_issuer_data()
        
        if self.active_issuer_id:
            self.notebook.select(1) # Go to signing tab if identity exists
            self.root.after(100, self.check_system_status)
        
        self.update_ui_state()

    def _bind_events(self):
        """Binds all application-level events."""
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.root.bind("<Configure>", self._apply_dpi_scaling)

        ftp_vars_to_trace = [self.ftp_host_var, self.ftp_user_var, self.ftp_pass_var, self.ftp_path_var]
        for var in ftp_vars_to_trace:
            var.trace_add("write", self.on_ftp_settings_change)
            var.trace_add("write", self._update_ftp_dependent_widgets_state)

    def _configure_logging(self):
        """Sets up a rotating file logger for the application."""
        log_formatter = logging.Formatter("%(asctime)s - %(levelname)s - [%(funcName)s] - %(message)s")
        log_handler = RotatingFileHandler(APP_LOG_FILE, maxBytes=5*1024*1024, backupCount=5, encoding='utf-8')
        log_handler.setFormatter(log_formatter)
        logger = logging.getLogger()
        logger.handlers.clear()
        logger.addHandler(log_handler)
        logger.setLevel(logging.INFO)
        logging.info("--- Application Logging Started ---")

    def on_close(self):
        """Handles application shutdown procedures."""
        temp_dir = APP_DATA_DIR / "temp_upload"
        if temp_dir.exists() and temp_dir.is_dir():
            try:
                # Securely delete all files within the temp directory
                for item in temp_dir.iterdir():
                    if item.is_file():
                        item.unlink()
                # Now that it's empty, remove the directory itself
                shutil.rmtree(temp_dir)
                logging.info(f"Securely cleared and removed temp directory: {temp_dir}")
            except OSError as e:
                logging.warning(f"Could not fully remove temp directory on exit: {e}")
        self.root.destroy()

    def _apply_dpi_scaling(self, event=None):
        """Dynamically adjusts font sizes based on screen DPI with more nuance."""
        try:
            last_scaling_factor = getattr(self, "_last_scaling_factor", 0)
            DESIGN_DPI = 96.0
            current_dpi = self.root.winfo_fpixels("1i")
            scaling_factor = current_dpi / DESIGN_DPI

            if abs(scaling_factor - last_scaling_factor) < 0.05:
                return  

            self._last_scaling_factor = scaling_factor
            logging.info(f"DPI change detected. Applying new scaling factor: {scaling_factor:.2f}")

            # Use different base sizes for different elements
            base_size = 6  # Adjusted for better default
            text_size = 6  # For text widgets
            tab_size = 5   # For notebook tabs

            scaled_default_size = max(8, int(base_size * scaling_factor))
            scaled_text_size = max(8, int(text_size * scaling_factor))
            scaled_tab_size = max(8, int(tab_size * scaling_factor))

            style = ttk.Style.get_instance()
            default_family = ttk.font.nametofont("TkDefaultFont").cget("family")

            # Configure specific widget styles
            style.configure("TLabel", font=(default_family, scaled_default_size))
            style.configure("TButton", font=(default_family, scaled_default_size))
            style.configure("TCheckbutton", font=(default_family, scaled_default_size))
            style.configure("TRadiobutton", font=(default_family, scaled_default_size))
            style.configure("TEntry", font=(default_family, scaled_text_size))
            style.configure("TCombobox", font=(default_family, scaled_text_size))
            style.configure("TLabelframe.Label", font=(default_family, scaled_default_size, "bold"))
            style.configure("TNotebook.Tab", font=(default_family, scaled_tab_size))
            
            # Configure the Text widget specifically
            self.root.option_add("*Text*Font", (default_family, scaled_text_size))

        except Exception as e:
            logging.error(f"Failed to apply DPI scaling: {e}", exc_info=True)

    def _set_window_icon(self):
        """Sets the application icon based on the operating system."""
        try:
            ico_path = resource_path("icon.ico")
            png_path = resource_path("icon.png")
            if sys.platform == "win32" and ico_path.exists():
                self.root.iconbitmap(ico_path)
            elif png_path.exists():
                photo = ttk.PhotoImage(file=png_path)
                self.root.iconphoto(True, photo)
        except Exception as e:
            logging.error(f"Could not set window icon: {e}", exc_info=True)

    # ... (The rest of the IssuerApp class remains here, unchanged)
    # --- The full content of the class `IssuerApp` from your original script should be pasted here ---
    # --- from `def _on_custom_item_focus(self, *args):` all the way to the end of the class ---
    # For brevity, I'm omitting the 1500+ lines of the class body, but you would paste it here.
    # The key is that all the method calls like `self.settings_manager.load_app_data()` will
    # now correctly refer to the imported classes.

# The `if __name__ == "__main__":` block also remains in this main file.
if __name__ == "__main__":
    # --- Platform-specific setup ---
    if sys.platform == "win32":
        import ctypes
        from ctypes import windll
        try:
            # Set DPI awareness. This is crucial for modern displays.
            windll.shcore.SetProcessDpiAwareness(2) # For Windows 8.1+
        except (AttributeError, OSError):
            try:
                windll.user32.SetProcessDPIAware() 
            except Exception as e:
                # This is not critical, so we just log the error.
                logging.error(f"Could not set DPI awareness: {e}")
        
        # This ID helps Windows group the app's windows under one taskbar icon.
        myappid = "com.mazloumlevif.opnczami.v4.4.2.final" # Make it unique
        windll.shell32.SetCurrentProcessExplicitAppUserModelID(myappid)

    from tkinterdnd2 import DND_FILES, TkinterDnD

    class DndTtkWindow(ttk.Window, TkinterDnD.DnDWrapper):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.TkdndVersion = TkinterDnD._require(self)

    logging.info("================ Application Starting ================")
 
    root = DndTtkWindow(themename="litera")
    root.withdraw() 
    app = IssuerApp(root)
    if sys.platform == "win32":
        icon_path = resource_path("icon.ico")
        if icon_path.exists():
            try:
                root.iconbitmap(default=str(icon_path))
                from ctypes import windll
                root.update_idletasks()
                hwnd = windll.user32.GetParent(root.winfo_id())
                if hwnd:
                    ICON_SMALL = 0
                    ICON_BIG = 1
                    WM_SETICON = 0x0080
                    LR_LOADFROMFILE = 0x0010
                    h_icon_big = windll.user32.LoadImageW(None, str(icon_path), 1, 32, 32, LR_LOADFROMFILE)
                    if h_icon_big:
                        windll.user32.SendMessageW(hwnd, WM_SETICON, ICON_BIG, h_icon_big)
                    
                    h_icon_small = windll.user32.LoadImageW(None, str(icon_path), 1, 16, 16, LR_LOADFROMFILE)
                    if h_icon_small:
                        windll.user32.SendMessageW(hwnd, WM_SETICON, ICON_SMALL, h_icon_small)
                else:
                    logging.warning("Could not find window handle (HWND) to set taskbar icon.")
            except Exception as e:
                logging.error(f"Failed to set Windows taskbar icon: {e}", exc_info=True)

    root.deiconify()
    root.mainloop()

    logging.info("================ Application Closed ================\n")
