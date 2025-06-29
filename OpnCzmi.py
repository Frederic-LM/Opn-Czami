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
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

# --- Standard Library Imports ---
import sys
import os
import json
import random
import base64
import string
import io
import shutil
import subprocess
import webbrowser
import tempfile
import hashlib
import datetime
import logging
import threading
import ftplib
import requests
from urllib.parse import urlparse
from pathlib import Path
from enum import Enum
from typing import Union
from dataclasses import dataclass, field
from logging.handlers import RotatingFileHandler

# --- Third-Party Imports ---
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from ttkbootstrap.scrolled import ScrolledText
from ttkbootstrap.tableview import Tableview
from tkinter import filedialog, messagebox
import keyring
import qrcode
from PIL import Image, ImageTk, ImageDraw, ImageFont
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding, utils
from cryptography.exceptions import InvalidSignature

try:
    import pyzipper
    PYZIPPER_AVAILABLE = True
except ImportError:
    PYZIPPER_AVAILABLE = False


# --- Local Application Imports ---
from license_manager import LicenseManager, get_app_data_path

APP_VERSION = "4.4.2"

# Setup cross-platform application data paths
APP_NAME = "OpnCzami"
APP_DATA_DIR = get_app_data_path(APP_NAME)
USER_DOCS_DIR = Path.home() / "Documents"
APP_DOCS_DIR = USER_DOCS_DIR / APP_NAME
SCRIPT_DIR = Path(sys.argv[0] if getattr(sys, "frozen", False) else __file__).parent

# Ensure required directories exist
(APP_DOCS_DIR / "Signed_Legato_Keys").mkdir(parents=True, exist_ok=True)
(APP_DOCS_DIR / "Signed_Proofs").mkdir(parents=True, exist_ok=True)
LOG_DIR = APP_DATA_DIR / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)


logging.basicConfig(
    level=logging.CRITICAL,
    format="%(asctime)s - %(levelname)s - [%(funcName)s] - %(message)s",
)


try:
    from pro_features import ProFeatures
    PRO_FEATURES_AVAILABLE = True
except ImportError:
    PRO_FEATURES_AVAILABLE = False

    class ProFeatures:
        def __init__(self, app_instance, app_data_path=None):
            app_instance.logging.warning(
                "Pro features module not found. Pro functionality will be disabled."
            )

        def load_data_file(self): pass
        def process_batch_threaded(self): pass
        def load_and_verify_audit_log(self): pass

try:
    import pandas as pd
    PANDAS_AVAILABLE = True
except ImportError:
    PANDAS_AVAILABLE = False


# --- Application-Specific Data Structures & Enums ---
class KeyStorage(Enum):
    KEYSTORE = "STORED_IN_KEYSTORE"
    FILE = "STORED_IN_FILE"


class FTPMode(Enum):
    MANUAL = "Manual"
    AUTOMATIC = "Automatic"


class UploadButtonState(Enum):
    INITIAL = ("🚀 Upload Fingerprinted Image", SECONDARY, "disabled")
    READY = ("🚀 Upload Fingerprinted Image", PRIMARY, "normal")
    UPLOADING = ("Uploading...", WARNING, "disabled")
    SUCCESS = ("Upload Successful!", SUCCESS, "normal")
    FAILURE = ("Upload Failed! (Retry)", DANGER, "normal")


class FormState(Enum):
    PRISTINE = 1
    DIRTY = 2
    TESTING = 3


@dataclass
class AppConfig:
    randomize_proof_name: bool = False
    make_local_copy: bool = True
    apply_watermark: bool = False
    apply_logo_watermark: bool = False
    watermark_text: str = "SIGNED"
    qr_save_path: str = ""
    proof_save_path: str = ""
    ftp_host: str = ""
    ftp_user: str = ""
    ftp_path: str = ""
    ftp_pass_b64: str = ""
    ftp_auto_upload: bool = False
    hardened_security: bool = False
    enable_audit_trail: bool = False

    def __post_init__(self):
        if not self.qr_save_path:
            self.qr_save_path = str(APP_DOCS_DIR / "Signed_Legato_Keys")
        if not self.proof_save_path:
            self.proof_save_path = str(APP_DOCS_DIR / "Signed_Proofs")


# --- Global Constants ---
ISSUER_DB_FILE = APP_DATA_DIR / "opn_czami_settings.json"
KEY_FILENAME_TEMPLATE = "abracadabra-{issuer_id}.key"
INFO_FILENAME = "my-legato-link.json"
KEYRING_SERVICE_NAME = "OperatorIssuerApp"
KEY_CHUNK_SIZE = 1000
AUDIT_LOG_FILENAME_TEMPLATE = "Audit-Trail-{issuer_id}.log"
APP_LOG_FILE = LOG_DIR / "opn-czami-app.log"
MAX_SUMMARY_CHARS = 400
MAX_LOGO_SIZE_BYTES = 256 * 1024
MAX_LOGO_PIXELS = 74000
STANDARDIZED_LOGO_BASENAME = "my-legato-link-logo"


# --- Helper Classes ---
def resource_path(relative_path):
    try:
        base_path = Path(sys._MEIPASS)
    except Exception:
        base_path = Path(os.path.abspath("."))
    return base_path / "assets" / relative_path


class SettingsManager:
    def __init__(self, db_path: Path):
        self.db_path = db_path

    def load_app_data(self) -> tuple[Union[str, None], Union[dict, None]]:
        try:
            if not self.db_path.exists():
                return None, None
            issuers = json.loads(self.db_path.read_text())
            if not issuers:
                return None, None
            return list(issuers.items())[0]
        except (json.JSONDecodeError, IndexError, Exception) as e:
            logging.error(
                f"Could not load or parse issuer database: {e}",
                exc_info=True)
            messagebox.showerror("DB Load Error",
                                 f"Could not load or parse issuer database: {e}")
            return None, None

    def save_app_data(self, all_data: dict):
        try:
            with open(self.db_path, "w") as f:
                json.dump(all_data, f, indent=4)
            logging.info("Application data saved successfully.")
        except Exception as e:
            logging.error(f"Could not save issuer database: {e}", exc_info=True)
            messagebox.showerror(
                "DB Save Error",
                f"Could not save issuer database: {e}")

    def clear_identity_file(self):
        self.save_app_data({})


class CryptoManager:
    def __init__(self, service_name: str, app_data_path: Path):
        self.service_name = service_name
        self.key_chunk_size = KEY_CHUNK_SIZE
        self.app_data_path = app_data_path
        self.log_dir = self.app_data_path / "logs"
        self.log_dir.mkdir(parents=True, exist_ok=True)

    def _save_to_keystore(self, key_name: str, secret_value: str):
        try:
            b64_secret = base64.b64encode(secret_value.encode("utf-8")).decode("utf-8")
            chunks = [b64_secret[i: i + self.key_chunk_size]
                      for i in range(0, len(b64_secret), self.key_chunk_size)]
            metadata = {"chunks": len(chunks)}
            keyring.set_password(
                self.service_name,
                f"{key_name}_meta",
                json.dumps(metadata))
            for i, chunk in enumerate(chunks):
                keyring.set_password(self.service_name, f"{key_name}_chunk_{i}", chunk)
            return True
        except Exception as e:
            logging.error(f"Could not save to keystore: {e}", exc_info=True)
            messagebox.showerror("Keystore Error",
                                 f"Could not save secret to OS keystore: {e}")
            return False

    def _load_from_keystore(self, key_name: str) -> Union[str, None]:
        try:
            metadata_str = keyring.get_password(self.service_name, f"{key_name}_meta")
            if not metadata_str:
                return None
            num_chunks = json.loads(metadata_str).get("chunks", 0)
            chunks = [
                keyring.get_password(
                    self.service_name,
                    f"{key_name}_chunk_{i}") for i in range(num_chunks)]
            if any(c is None for c in chunks):
                raise ValueError(f"Missing chunks for '{key_name}'")
            return base64.b64decode("".join(chunks)).decode("utf-8")
        except Exception as e:
            logging.error(f"Could not load from keystore: {e}", exc_info=True)
            messagebox.showerror("Keystore Error",
                                 f"Could not load secret from OS keystore: {e}")
            return None

    def _delete_from_keystore(self, key_name: str):
        try:
            metadata_str = keyring.get_password(self.service_name, f"{key_name}_meta")
            if metadata_str:
                num_chunks = json.loads(metadata_str).get("chunks", 0)
                for i in range(num_chunks):
                    try:
                        keyring.delete_password(
                            self.service_name, f"{key_name}_chunk_{i}")
                    except Exception:
                        pass
                keyring.delete_password(self.service_name, f"{key_name}_meta")
        except Exception:
            logging.warning(
                f"Could not fully delete '{key_name}' from keystore.",
                exc_info=True)

    def save_private_key_to_keystore(
            self,
            issuer_id: str,
            private_key_pem: str) -> bool:
        return self._save_to_keystore(issuer_id, private_key_pem)

    def load_private_key_from_keystore(self, issuer_id: str) -> Union[str, None]:
        return self._load_from_keystore(issuer_id)

    def delete_private_key_from_keystore(self, issuer_id: str):
        self._delete_from_keystore(issuer_id)

    def save_ftp_password(self, issuer_id: str, password: str) -> bool:
        return self._save_to_keystore(f"{issuer_id}_ftp", password)

    def load_ftp_password(self, issuer_id: str) -> Union[str, None]:
        return self._load_from_keystore(f"{issuer_id}_ftp")

    def delete_ftp_password(self, issuer_id: str):
        self._delete_from_keystore(f"{issuer_id}_ftp")

    @staticmethod
    def generate_id_from_name(name: str) -> str:
        return hashlib.sha256(name.lower().strip().encode("utf-8")).hexdigest()[:12]

    @staticmethod
    def calculate_file_hash(filepath: Path) -> Union[str, None]:
        if not filepath.exists():
            return None
        hasher = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                while chunk := f.read(4096):
                    hasher.update(chunk)
            return hasher.hexdigest()[:32]
        except Exception as e:
            logging.error(f"Error calculating hash for {filepath}: {e}", exc_info=True)
            return None

    @staticmethod
    def sign_payload(private_key_pem: str, payload_dict: dict) -> str:
        priv_key = serialization.load_pem_private_key(
            private_key_pem.encode("utf-8"), password=None)
        payload_json = json.dumps(payload_dict, separators=(",", ":")).encode("utf-8")
        hasher = hashes.Hash(hashes.SHA256())
        hasher.update(payload_json)
        digest = hasher.finalize()
        signature = priv_key.sign(
            digest, padding.PSS(
                mgf=padding.MGF1(
                    hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), utils.Prehashed(
                hashes.SHA256()))
        return base64.b64encode(signature).decode("utf-8")

    @staticmethod
    def verify_signature(
            public_key_pem: str,
            signature_b64: str,
            payload_dict: dict) -> bool:
        try:
            pub_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
            payload_json = json.dumps(
                payload_dict, separators=(
                    ",", ":")).encode("utf-8")
            hasher = hashes.Hash(hashes.SHA256())
            hasher.update(payload_json)
            digest = hasher.finalize()
            signature = base64.b64decode(signature_b64)
            pub_key.verify(
                signature, digest, padding.PSS(
                    mgf=padding.MGF1(
                        hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), utils.Prehashed(
                    hashes.SHA256()))
            return True
        except (InvalidSignature, ValueError, Exception):
            return False

    def get_audit_log_path(self, issuer_id: str) -> Path:
        return self.log_dir / AUDIT_LOG_FILENAME_TEMPLATE.format(issuer_id=issuer_id)

    def get_last_log_hash(self, log_path: Path) -> Union[str, None]:
        if not log_path.exists() or os.path.getsize(log_path) == 0:
            return None
        try:
            with open(log_path, "rb") as f:
                try:
                    f.seek(-2, os.SEEK_END)
                    while f.read(1) != b"\n":
                        f.seek(-2, os.SEEK_CUR)
                except OSError:
                    f.seek(0)
                last_line = f.readline().decode("utf-8").strip()
            if "::" not in last_line:
                logging.warning(
                    f"Audit log '{log_path}' may be corrupt. Last line is malformed.")
                return None
            json_part, _ = last_line.split("::", 1)
            return hashlib.sha256(json_part.encode("utf-8")).hexdigest()
        except Exception as e:
            logging.error(
                f"Error reading last audit log entry from {log_path}: {e}",
                exc_info=True)
            messagebox.showwarning(
                "Audit Log Warning",
                f"Could not read the last entry of the audit trail. A new chain may be started. Error: {e}")
            return None

    def log_event(
            self,
            issuer_id: str,
            private_key_pem: str,
            event_type: str,
            details: dict):
        try:
            log_path = self.get_audit_log_path(issuer_id)
            previous_hash = self.get_last_log_hash(log_path)

            log_entry = {
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "issuer_id": issuer_id,
                "event_type": event_type,
                "details": details,
                "previous_hash": previous_hash
            }

            signature_b64 = self.sign_payload(private_key_pem, log_entry)
            log_line = f"{
                json.dumps(
                    log_entry,
                    separators=(
                        ',',
                        ':'))}::{signature_b64}\n"

            with open(log_path, "a") as f:
                f.write(log_line)

            logging.info(f"Logged event '{event_type}' to audit trail.")

            try:
                head_hash_path = self.get_audit_log_path(issuer_id).with_suffix('.head')
                current_entry_hash = hashlib.sha256(
                    json.dumps(
                        log_entry, separators=(
                            ',', ':')).encode('utf-8')).hexdigest()
                head_hash_path.write_text(current_entry_hash)
            except Exception as e:
                logging.critical(
                    f"FATAL: Could not write audit head hash file! {e}",
                    exc_info=True)
                messagebox.showerror(
                    "Audit Log Critical Failure",
                    "Could not update the audit trail's head file. The log may now be in an inconsistent state.")

        except Exception as e:
            logging.critical(f"Failed to write to audit log! Error: {e}", exc_info=True)
            messagebox.showerror(
                "Audit Log Failure",
                f"Could not write a tamper-evident log entry. Please check file permissions for '{
                    log_path.name}'. Error: {e}")


class FTPManager:
    def test_connection(self, host: str, user: str, password: str) -> str:
        if not all([host, user, password]):
            return "Host, User, and Password cannot be empty."
        try:
            with ftplib.FTP_TLS(timeout=10) as ftp:
                ftp.connect(host)
                ftp.login(user, password)
                ftp.prot_p()
                ftp.retrlines("LIST", lambda line: None)
            return "Success"
        except Exception as e:
            return f"Test failed: {e}"

    def upload_file(
            self,
            local_path: Path,
            remote_filename: str,
            ftp_settings: dict) -> str:
        host, user, password = (ftp_settings.get("host"), ftp_settings.get(
            "user"), ftp_settings.get("password"))
        remote_path_str = ftp_settings.get("path")
        if not all([host, user, password, remote_path_str]):
            return "FTP settings are incomplete."
        try:
            with ftplib.FTP_TLS(timeout=15) as ftp:
                ftp.connect(host)
                ftp.login(user, password)
                ftp.prot_p()
                path_parts = Path(remote_path_str).parts
                for i in range(1, len(path_parts)):
                    current_dir_to_check = Path(*path_parts[: i + 1]).as_posix()
                    try:
                        ftp.cwd(current_dir_to_check)
                    except ftplib.error_perm:
                        try:
                            ftp.mkd(current_dir_to_check)
                            ftp.cwd(current_dir_to_check)
                        except ftplib.error_perm as mkd_e:
                            return f"FTP Error: Failed to create directory '{current_dir_to_check}'. Error: {mkd_e}"
                with open(local_path, "rb") as f:
                    ftp.storbinary(f"STOR {remote_filename}", f)
            return f"Successfully uploaded {remote_filename}."
        except ftplib.all_errors as e:
            return f"FTP Error: {e}"
        except Exception as e:
            return f"An unexpected error occurred during upload: {e}"


class ImageProcessor:
    def __init__(self, checkmark_icon_path: Union[Path, None]):
        self.checkmark_icon_pil = None
        self.resample_method = (
            Image.Resampling.LANCZOS if hasattr(
                Image, "Resampling") else Image.LANCZOS)
        if checkmark_icon_path and checkmark_icon_path.exists():
            try:
                self.checkmark_icon_pil = Image.open(checkmark_icon_path)
            except Exception as e:
                logging.warning(
                    f"Could not load '{checkmark_icon_path}'. Error: {e}",
                    exc_info=True)

    def apply_text_watermark(
            self,
            image_pil: Image.Image,
            text: str,
            apply: bool) -> Image.Image:
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
        pos = ((image.width - (text_bbox[2] - text_bbox[0])) //
               2, (image.height - (text_bbox[3] - text_bbox[1])) // 2)
        draw.text(pos, text, font=font, fill=(255, 255, 255, 128))
        return Image.alpha_composite(image, text_layer)

    def apply_logo_watermark(self,
                             image_pil: Image.Image,
                             logo_pil: Union[Image.Image,
                                             None],
                             apply: bool) -> Image.Image:
        if not apply or not logo_pil:
            return image_pil
        image = image_pil.copy().convert("RGBA")
        logo = logo_pil.copy().convert("RGBA")
        try:
            alpha = logo.split()[3]
            logo.putalpha(alpha.point(lambda p: p * 0.5))
        except IndexError:
            pass
        logo.thumbnail((int(image.width * 0.25), image.height), self.resample_method)
        margin = int(image.width * 0.02)
        pos = (image.width - logo.width - margin, image.height - logo.height - margin)
        image.paste(logo, pos, logo)
        return image

    def overlay_checkmark(self, background_pil: Image.Image,
                          scale_ratio: float = 1) -> Image.Image:
        if not background_pil or not self.checkmark_icon_pil:
            return background_pil
        background = background_pil.copy().convert("RGBA")
        overlay = self.checkmark_icon_pil.copy().convert("RGBA")
        target_width = int(background.width * scale_ratio)
        overlay_aspect_ratio = overlay.height / overlay.width
        target_height = int(target_width * overlay_aspect_ratio)
        overlay_resized = overlay.resize(
            (target_width, target_height), self.resample_method)
        offset = ((background.width - overlay_resized.width) // 2,
                  (background.height - overlay_resized.height) // 2)
        background.paste(overlay_resized, offset, overlay_resized)
        return background

    def generate_qr_with_logo(self,
                              data: str,
                              logo_pil: Union[Image.Image,
                                              None],
                              fixed_size: Union[tuple[int,
                                                      int],
                                                None] = None,
                              sizing_ratio: float = 0.28,
                              box_size: int = 10) -> Image.Image:
        qr = qrcode.QRCode(
            error_correction=qrcode.constants.ERROR_CORRECT_H,
            box_size=box_size,
            border=4)
        qr.add_data(data)
        qr.make(fit=True)
        qr_img = qr.make_image(fill_color="black", back_color="white").convert("RGBA")
        if logo_pil:
            logo_resized = logo_pil.copy().convert("RGBA")
            dynamic_size = (int(qr_img.width * sizing_ratio),
                            int(qr_img.height * sizing_ratio))
            logo_max_size = fixed_size or dynamic_size
            logo_resized.thumbnail(logo_max_size, self.resample_method)
            pos = ((qr_img.width - logo_resized.width) // 2,
                   (qr_img.height - logo_resized.height) // 2)
            qr_img.paste(logo_resized, pos, mask=logo_resized)
        return qr_img.convert("RGB")


class IssuerApp:
    def handle_create_backup(self):
        if not self.active_issuer_id:
            messagebox.showwarning(
                "No Identity",
                "You must have an active identity to create a backup.")
            return

        password = self.backup_pass_var.get()
        if not password:
            messagebox.showerror("Password Required",
                                 "You must enter a password to encrypt the backup file.")
            return

        if len(password) < 10:
            if not messagebox.askyesno(
                "Weak Password",
                    "Your password is less than 10 characters. Are you sure you want to proceed?"):
                return

        key_file_path = APP_DATA_DIR / \
            KEY_FILENAME_TEMPLATE.format(issuer_id=self.active_issuer_id)
        settings_file_path = ISSUER_DB_FILE
        if not key_file_path.exists() or not settings_file_path.exists():
            messagebox.showerror(
                "Files Missing",
                "Could not find the necessary key or settings file to back up.")
            return

        default_filename = f"opn-czami-backup-{self.active_issuer_id}-{datetime.date.today()}.zip"
        save_path_str = filedialog.asksaveasfilename(
            title="Save Secure Backup As...",
            defaultextension=".zip",
            initialfile=default_filename,
            filetypes=[
                ("ZIP Archives",
                 "*.zip")])
        if not save_path_str:
            return

        save_path = Path(save_path_str)
        try:
            with pyzipper.AESZipFile(save_path, "w", compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES) as zf:
                zf.setpassword(password.encode("utf-8"))
                zf.write(key_file_path, arcname=key_file_path.name)
                zf.write(settings_file_path, arcname=settings_file_path.name)

            self.backup_pass_var.set("")

            messagebox.showinfo(
                "Backup Successful",
                f"Secure backup created successfully at:\n\n{save_path}")
            webbrowser.open(f"file:///{save_path.parent}")

        except Exception as e:
            logging.error(f"Failed to create secure backup: {e}", exc_info=True)
            messagebox.showerror(
                "Backup Failed",
                f"An error occurred while creating the backup file:\n\n{e}")

    def handle_license_drop(self, event):
        filepath_str = event.data.strip("{}")
        dropped_path = Path(filepath_str)
        if dropped_path.name.lower() != "license.key":
            messagebox.showerror("Invalid File",
                                 "Please drop a valid 'license.key' file.")
            return

        try:
            success = self.license_manager.activate_from_path(dropped_path)
            if success:
                self.update_pro_license_status_display()
                messagebox.showinfo(
                    "Success!",
                    f"Professional license for '{self.license_manager.customer_info}' has been successfully activated.\n\n"
                    "Please restart the application to enable all Professional features.",
                )
            else:
                self.update_pro_license_status_display()
                messagebox.showerror(
                    "Activation Failed",
                    f"The license key is invalid or activation failed: {
                        self.license_manager.customer_info}")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred during activation: {e}")
            logging.error(f"License drop activation failed: {e}", exc_info=True)

    def update_pro_license_status_display(self, event=None):
        if hasattr(self, "pro_status_label"):
            license_status_text = f"Pro License: {self.license_manager.customer_info}"
            license_status_style = SUCCESS if self.license_manager.is_licensed else WARNING
            self.pro_status_label.config(
                text=license_status_text,
                bootstyle=license_status_style)

        if hasattr(self, "drop_zone_label"):
            if self.license_manager.is_licensed:
                features = ", ".join(
                    sorted(
                        list(
                            self.license_manager.enabled_features))).title()
                about_text = f"Features Activated: {features}\n\nYou can drag and drop a new license file here in the future to upgrade."
                self.drop_zone_label.config(text=about_text, bootstyle="success")
            else:
                about_text = "To activate, drag and drop your 'license.key' file anywhere on this 'About' page."
                self.drop_zone_label.config(text=about_text, bootstyle="info")

    def __init__(self, root):
        self.root = root
        self.root.title("Op’n-Czami - Legato-Key Certification Authority Dashboard")
        self.root.geometry("1260x970")
        self.root.minsize(1260, 980)
        self.root.resizable(False, True)
        if getattr(sys, "frozen", False):
            self.executable_dir = Path(sys.executable).parent
        else:
            self.executable_dir = Path(__file__).parent
        self.license_manager = LicenseManager(self.executable_dir, APP_DATA_DIR)
        self.settings_manager = SettingsManager(ISSUER_DB_FILE)
        self.crypto_manager = CryptoManager(KEYRING_SERVICE_NAME, APP_DATA_DIR)
        self.image_processor = ImageProcessor(
            self.executable_dir / "assets" / "checkmark.png")
        self.ftp_manager = FTPManager()
        self.logging = logging
        self._configure_logging()
        self.pro_handler = ProFeatures(self, APP_DATA_DIR)
        self.config = AppConfig()
        self.active_issuer_id = None
        self.active_issuer_data = None
        self.active_issuer_contact_info = {}
        self.all_issuer_data = {}
        self.qr_image_pil = None
        self.issuer_qr_image_pil = None
        self.status_logo_pil = None
        self.proof_image_pil = None
        self.proof_image_tk = None
        self.last_signed_payload = None
        self.selected_proof_file_path = None
        self.prepared_upload_path = None
        self.upload_button_state = UploadButtonState.INITIAL
        self.system_is_verified = False
        self.is_generating = False
        self.original_status_logo_pil = None
        self.logo_path = None
        self.url_path_var = ttk.StringVar()
        self.image_base_url_var = ttk.StringVar()
        self.current_root_url = ""
        self.ftp_host_var = ttk.StringVar()
        self.ftp_user_var = ttk.StringVar()
        self.ftp_pass_var = ttk.StringVar()
        self.ftp_path_var = ttk.StringVar()
        self.show_pass_var = ttk.BooleanVar(value=False)
        self.ftp_host_var.trace_add("write", self.on_ftp_settings_change)
        self.ftp_user_var.trace_add("write", self.on_ftp_settings_change)
        self.ftp_pass_var.trace_add("write", self.on_ftp_settings_change)
        self.ftp_path_var.trace_add("write", self.on_ftp_settings_change)
        self.ftp_host_var.trace_add("write", self._update_ftp_dependent_widgets_state)
        self.ftp_user_var.trace_add("write", self._update_ftp_dependent_widgets_state)
        self.ftp_pass_var.trace_add("write", self._update_ftp_dependent_widgets_state)
        self.ftp_path_var.trace_add("write", self._update_ftp_dependent_widgets_state)
        self.watermark_text_var = ttk.StringVar()
        self.qr_save_path_var = ttk.StringVar()
        self.proof_save_path_var = ttk.StringVar()
        self.hardened_security_var = ttk.BooleanVar()
        self.enable_audit_trail_var = ttk.BooleanVar()
        self.ftp_auto_upload_var = ttk.BooleanVar()
        self.apply_watermark_var = ttk.BooleanVar()
        self.apply_logo_watermark_var = ttk.BooleanVar()
        self.randomize_proof_name_var = ttk.BooleanVar()
        self.make_local_copy_var = ttk.BooleanVar()
        self.ftp_form_state = FormState.PRISTINE
        self.create_status_panel()
        self.create_main_ui()
        self.populate_ui_from_config()
        self.load_issuer_data()
        if self.active_issuer_id:
            self.notebook.select(1)
        self.update_ui_state()
        if self.active_issuer_id:
            self.root.after(100, self.check_system_status)
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self._apply_dpi_scaling()
        self.root.bind('<Configure>', self._apply_dpi_scaling)

    def _apply_dpi_scaling(self, event=None):

        try:

            last_scaling_factor = getattr(self, "_last_scaling_factor", 0)

            DESIGN_DPI = 96.0
            current_dpi = self.root.winfo_fpixels('1i')
            scaling_factor = current_dpi / DESIGN_DPI

            if abs(scaling_factor - last_scaling_factor) < 0.05:
                return

            self._last_scaling_factor = scaling_factor

            logging.info(
                f"DPI change detected. Applying new scaling factor: {
                    scaling_factor:.2f}")

            base_size = 5
            text_size = 4

            scaled_default_size = max(8, int(base_size * scaling_factor))
            scaled_text_size = max(8, int(text_size * scaling_factor))

            style = ttk.Style.get_instance()
            default_family = ttk.font.nametofont("TkDefaultFont").cget("family")

            style.configure("TLabel", font=(default_family, scaled_default_size))
            style.configure("TButton", font=(default_family, scaled_default_size))
            style.configure("TCheckbutton", font=(default_family, scaled_default_size))
            style.configure("TRadiobutton", font=(default_family, scaled_default_size))
            style.configure("TEntry", font=(default_family, scaled_default_size))
            style.configure("TCombobox", font=(default_family, scaled_default_size))
            style.configure(
                "TLabelframe.Label",
                font=(
                    default_family,
                    scaled_default_size,
                    "bold"))
            style.configure("TNotebook.Tab", font=(default_family, scaled_text_size))
            self.root.option_add("*Text*Font", (default_family, scaled_default_size))

        except Exception as e:
            logging.error(f"Failed to apply DPI scaling: {e}", exc_info=True)

    def _set_window_icon(self):
        try:
            if sys.platform == "win32":
                ico_path = resource_path("icon.ico")
                self.root.iconbitmap(ico_path)
            else:
                png_path = resource_path("icon.png")
                photo = ttk.PhotoImage(file=png_path)
                self.root.iconphoto(True, photo)
        except Exception as e:
            logging.error(f"Could not set window icon: {e}", exc_info=True)

    def _show_upgrade_prompt(self, feature_name: str):
        messagebox.showinfo(
            "Professional Feature",
            f"'{feature_name}' is a Professional feature.\n\nPlease purchase a license to unlock this functionality.")

    def _handle_load_data_file(self):
        if self.license_manager.is_feature_enabled("batch"):
            self.pro_handler.load_data_file()
        else:
            self._show_upgrade_prompt("Batch Processing")

    def _handle_process_batch(self):
        if self.license_manager.is_feature_enabled("batch"):
            self.pro_handler.process_batch_threaded()
        else:
            self._show_upgrade_prompt("Batch Processing")

    def _handle_refresh_audit(self):
        if not self.active_issuer_id:
            if hasattr(self, "audit_status_label"):
                self.audit_status_label.config(
                    text="Load an identity to view the audit trail.")
            return

        if self.license_manager.is_feature_enabled("audit"):
            self.audit_status_label.config(
                text="Verifying Audit Trail...", bootstyle="info")
            self.root.update_idletasks()

            row_data, is_valid, msg, style = self.pro_handler.load_and_verify_audit_log(
                self.active_issuer_id, self.active_issuer_data["priv_key_pem"])

            self.audit_tree.delete_rows()
            if row_data:
                self.audit_tree.insert_rows("end", row_data)
                self.audit_tree.load_table_data()
            self.audit_status_label.config(text=msg, bootstyle=style)
        else:
            self.audit_status_label.config(
                text="Audit Trail is a Professional Feature.",
                bootstyle="info")
            self._show_upgrade_prompt("Audit Trail")

    def _configure_logging(self):
        log_level = logging.INFO
        log_formatter = logging.Formatter(
            "%(asctime)s - %(levelname)s - [%(funcName)s] - %(message)s")
        log_handler = RotatingFileHandler(
            APP_LOG_FILE, maxBytes=5 * 1024 * 1024, backupCount=5)
        log_handler.setFormatter(log_formatter)
        log_handler.setLevel(log_level)
        logger = logging.getLogger()
        if logger.hasHandlers():
            logger.handlers.clear()
        logger.addHandler(log_handler)
        logger.setLevel(log_level)
        logging.info("Application logging is permanently ENABLED.")

    def on_close(self):
        temp_dir = APP_DATA_DIR / "temp_upload"
        if temp_dir.exists():
            try:
                shutil.rmtree(temp_dir)
            except Exception as e:
                logging.warning(f"Could not remove temp directory: {e}", exc_info=True)
        self.root.destroy()

    def browse_for_qr_save_path(self):
        new_path = filedialog.askdirectory(title="Select Folder for QR Code Saving")
        if new_path:
            self.qr_save_path_var.set(new_path)
            self.save_settings()

    def browse_for_proof_save_path(self):
        new_path = filedialog.askdirectory(title="Select Folder for Local Proof Copies")
        if new_path:
            self.proof_save_path_var.set(new_path)
            self.save_settings()

    def on_auto_upload_toggle(self):
        self.config.ftp_auto_upload = self.ftp_auto_upload_var.get()
        self.save_settings()
        self.update_upload_button_display()
        self.update_auto_upload_indicator()

    def _update_ftp_dependent_widgets_state(self, *args):
        if not hasattr(self, "auto_upload_check"):
            return

        settings_are_valid = all([
            self.ftp_host_var.get().strip(),
            self.ftp_user_var.get().strip(),
            self.ftp_pass_var.get().strip(),
            self.ftp_path_var.get().strip()
        ])

        if settings_are_valid:

            self.auto_upload_check.config(state="normal")
        else:

            self.auto_upload_check.config(state="disabled")

            if self.ftp_auto_upload_var.get():
                self.ftp_auto_upload_var.set(False)

                self.on_auto_upload_toggle()

    def toggle_watermark_state(self):
        is_licensed = self.license_manager.is_feature_enabled("watermark")
        state = ("normal" if self.apply_watermark_var.get()
                 and is_licensed else "disabled")
        self.watermark_entry.config(state=state)

    def toggle_proof_path_state(self):
        state = "normal" if self.make_local_copy_var.get() else "disabled"
        self.proof_path_entry.config(state="readonly" if state == "normal" else state)
        self.proof_path_browse_btn.config(state=state)

    def update_auto_upload_indicator(self):
        if self.config.ftp_auto_upload:
            self.auto_upload_indicator_label.config(
                text="✓ Auto-Upload: ON", bootstyle="success")
        else:
            self.auto_upload_indicator_label.config(
                text="✗ Auto-Upload: OFF", bootstyle="secondary")

    def load_issuer_data(self):
        self.active_issuer_id, data = self.settings_manager.load_app_data()
        if not self.active_issuer_id or not data:
            self.active_issuer_data = None
            logging.info("No active issuer found.")
            return
        logging.info(f"Loading data for issuer ID: {self.active_issuer_id}")
        try:
            self.all_issuer_data = (
                json.loads(
                    ISSUER_DB_FILE.read_text()) if ISSUER_DB_FILE.exists() else {})
        except (IOError, json.JSONDecodeError):
            self.all_issuer_data = {}
            logging.warning(
                "Could not load or parse issuer DB file. Starting with empty data.")
        self.active_issuer_data = self.all_issuer_data.get(
            self.active_issuer_id, data).copy()
        key_loc = self.active_issuer_data.get("priv_key_pem")
        if key_loc == KeyStorage.KEYSTORE.value:
            self.config.hardened_security = True
            key = self.crypto_manager.load_private_key_from_keystore(
                self.active_issuer_id)
            if not key:
                messagebox.showerror(
                    "Fatal Error", "Failed to load key from OS keystore.")
                self.active_issuer_data = None
                return
            self.active_issuer_data["priv_key_pem"] = key
        elif key_loc == KeyStorage.FILE.value:
            self.config.hardened_security = False
            key_path = APP_DATA_DIR / \
                KEY_FILENAME_TEMPLATE.format(issuer_id=self.active_issuer_id)
            try:
                self.active_issuer_data["priv_key_pem"] = key_path.read_text()
            except FileNotFoundError:
                messagebox.showerror(
                    "Fatal Error", f"Private key file missing: {key_path}")
                self.active_issuer_data = None
                return
        self.populate_config_from_issuer_data()
        self.populate_ui_from_config()

    def populate_config_from_issuer_data(self):
        s = self.active_issuer_data.get("settings", {})
        ftp_settings = s.get("ftp_settings", {})
        self.config = AppConfig(
            randomize_proof_name=s.get("randomize_proof_name", False),
            make_local_copy=s.get("make_local_copy", False),
            apply_watermark=s.get("apply_watermark", False),
            apply_logo_watermark=s.get("apply_logo_watermark", False),
            watermark_text=s.get("watermark_text", "VERIFIED"),
            qr_save_path=s.get("qr_save_path", ""),
            proof_save_path=s.get("proof_save_path", ""),
            ftp_host=ftp_settings.get("host", ""),
            ftp_user=ftp_settings.get("user", ""),
            ftp_path=ftp_settings.get("path", ""),
            ftp_pass_b64=ftp_settings.get("pass_b64", ""),
            ftp_auto_upload=ftp_settings.get("mode", FTPMode.MANUAL.value) == FTPMode.AUTOMATIC.value,
            hardened_security=self.config.hardened_security,
            enable_audit_trail=s.get("enable_audit_trail", False),
        )
        self._configure_logging()
        logging.info("Configuration object populated from issuer data.")

    def populate_ui_from_config(self):
        self.ftp_host_var.set(self.config.ftp_host)
        self.ftp_user_var.set(self.config.ftp_user)
        self.ftp_path_var.set(self.config.ftp_path)
        self.watermark_text_var.set(self.config.watermark_text)
        self.qr_save_path_var.set(self.config.qr_save_path)
        self.proof_save_path_var.set(self.config.proof_save_path)
        if self.config.hardened_security:
            password = (
                self.crypto_manager.load_ftp_password(
                    self.active_issuer_id) or "")
        else:
            try:
                password = base64.b64decode(self.config.ftp_pass_b64).decode("utf-8")
            except Exception:
                password = ""
        self.ftp_pass_var.set(password)
        self.hardened_security_var.set(self.config.hardened_security)
        self.enable_audit_trail_var.set(self.config.enable_audit_trail)
        self.ftp_auto_upload_var.set(self.config.ftp_auto_upload)
        self.apply_watermark_var.set(self.config.apply_watermark)
        self.apply_logo_watermark_var.set(self.config.apply_logo_watermark)
        self.randomize_proof_name_var.set(self.config.randomize_proof_name)
        self.make_local_copy_var.set(self.config.make_local_copy)
        self.update_auto_upload_indicator()
        self.toggle_proof_path_state()
        self.toggle_watermark_state()
        self.ftp_form_state = FormState.PRISTINE
        logging.info("UI elements synced from configuration object.")
        if hasattr(self, "save_and_upload_button"):
            self.save_and_upload_button.config(state="disabled")
        self._update_ftp_dependent_widgets_state()

    def _gather_settings_data_from_config(self) -> dict:
        ftp_settings = {
            "host": self.config.ftp_host,
            "user": self.config.ftp_user,
            "path": self.config.ftp_path,
            "mode": (
                FTPMode.AUTOMATIC.value if self.config.ftp_auto_upload else FTPMode.MANUAL.value),
        }
        if not self.config.hardened_security:
            ftp_settings["pass_b64"] = self.config.ftp_pass_b64
        return {
            "randomize_proof_name": self.config.randomize_proof_name,
            "make_local_copy": self.config.make_local_copy,
            "apply_watermark": self.config.apply_watermark,
            "apply_logo_watermark": self.config.apply_logo_watermark,
            "watermark_text": self.config.watermark_text,
            "qr_save_path": self.config.qr_save_path,
            "proof_save_path": self.config.proof_save_path,
            "ftp_settings": ftp_settings,
            "enable_audit_trail": self.config.enable_audit_trail,
        }

    def _sync_config_from_ui(self):
        self.config.ftp_host = self.ftp_host_var.get()
        self.config.ftp_user = self.ftp_user_var.get()
        self.config.ftp_path = self.ftp_path_var.get()
        self.config.watermark_text = self.watermark_text_var.get()
        self.config.qr_save_path = self.qr_save_path_var.get()
        self.config.proof_save_path = self.proof_save_path_var.get()
        if not self.hardened_security_var.get():
            self.config.ftp_pass_b64 = base64.b64encode(
                self.ftp_pass_var.get().encode("utf-8")).decode("utf-8")
        self.config.hardened_security = self.hardened_security_var.get()
        self.config.enable_audit_trail = self.enable_audit_trail_var.get()
        self.config.ftp_auto_upload = self.ftp_auto_upload_var.get()
        self.config.apply_watermark = self.apply_watermark_var.get()
        self.config.apply_logo_watermark = self.apply_logo_watermark_var.get()
        self.config.randomize_proof_name = self.randomize_proof_name_var.get()
        self.config.make_local_copy = self.make_local_copy_var.get()

    def save_settings(self):
        if not self.active_issuer_id:
            return
        self._sync_config_from_ui()
        self._configure_logging()
        if self.active_issuer_id in self.all_issuer_data:
            self.all_issuer_data[self.active_issuer_id]["settings"] = self._gather_settings_data_from_config(
            )
            self.settings_manager.save_app_data(self.all_issuer_data)
        logging.info("Settings saved.")

    def save_issuer_identity(self):
        if not self.active_issuer_id:
            return
        is_enabling_security = self.hardened_security_var.get()
        action_text = "ENABLING" if is_enabling_security else "DISABLING"
        warning_text = ("This will move your Private Key and FTP Password into the secure OS Keychain." if is_enabling_security else "WARNING: This will move your Private Key and FTP Password OUT of the secure OS Keychain and into local files. This is less secure.")
        if not messagebox.askokcancel(
                f"Confirm {action_text} Hardened Security",
                f"{warning_text}\n\nThis is a critical security operation. Proceed?",
                icon="info" if is_enabling_security else "warning"):
            self.pro_security_checkbox.cget("variable").set(not is_enabling_security)
            return

        priv_key_pem = self.active_issuer_data.get("priv_key_pem")
        key_filepath = APP_DATA_DIR / \
            KEY_FILENAME_TEMPLATE.format(issuer_id=self.active_issuer_id)
        try:
            if is_enabling_security:
                if not self.crypto_manager.save_private_key_to_keystore(
                        self.active_issuer_id, priv_key_pem):
                    raise ValueError("Failed to save private key to OS Keystore.")
                if not self.crypto_manager.save_ftp_password(
                        self.active_issuer_id, self.ftp_pass_var.get()):
                    raise ValueError("Failed to save FTP password to OS Keystore.")
                self.all_issuer_data[self.active_issuer_id]["priv_key_pem"] = KeyStorage.KEYSTORE.value
                if key_filepath.exists():
                    key_filepath.unlink()
            else:
                ftp_password = self.crypto_manager.load_ftp_password(
                    self.active_issuer_id)
                if ftp_password:
                    self.ftp_pass_var.set(ftp_password)
                    self.config.ftp_pass_b64 = base64.b64encode(
                        ftp_password.encode("utf-8")).decode("utf-8")
                self.crypto_manager.delete_private_key_from_keystore(
                    self.active_issuer_id)
                self.crypto_manager.delete_ftp_password(self.active_issuer_id)
                key_filepath.write_text(priv_key_pem)
                self.all_issuer_data[self.active_issuer_id]["priv_key_pem"] = KeyStorage.FILE.value
            self.config.hardened_security = is_enabling_security
            self.save_settings()
            messagebox.showinfo(
                "Success", "Security settings have been updated successfully.")
        except Exception as e:
            logging.error(f"Security operation failed: {e}", exc_info=True)
            messagebox.showerror(
                "Security Operation Failed",
                f"Could not update security settings: {e}\n\nReverting the change.")
            self.pro_security_checkbox.cget("variable").set(not is_enabling_security)

    def delete_identity(self):
        if not messagebox.askyesno(
            "CONFIRM DELETION",
            "Are you absolutely sure?\nThis is PERMANENT.",
                icon="warning"):
            return
        audit_log_path = self.crypto_manager.get_audit_log_path(self.active_issuer_id)
        if audit_log_path.exists():
            if messagebox.askyesno(
                    "Delete Audit Trail?",
                    f"Do you also want to permanently delete the audit trail log file '{
                        audit_log_path.name}'?",
                    icon="warning"):
                try:
                    audit_log_path.unlink()
                    logging.info(f"Deleted audit trail: {audit_log_path.name}")
                except Exception as e:
                    logging.error(f"Could not delete audit trail: {e}", exc_info=True)
                    messagebox.showerror(
                        "Deletion Error",
                        f"Could not delete the audit trail log file: {e}")
        self.crypto_manager.delete_private_key_from_keystore(self.active_issuer_id)
        self.crypto_manager.delete_ftp_password(self.active_issuer_id)
        key_filepath = APP_DATA_DIR / \
            KEY_FILENAME_TEMPLATE.format(issuer_id=self.active_issuer_id)
        if key_filepath.exists():
            key_filepath.unlink()
        self.settings_manager.clear_identity_file()
        self.active_issuer_id = None
        self.active_issuer_data = None
        self.last_signed_payload = None
        self.issuer_qr_image_pil = None
        self.active_issuer_contact_info = {}
        self.all_issuer_data = {}
        self.clear_proof_image_display()
        self.message_text.delete("1.0", "end")
        self.qr_display_label.config(image="")
        self.notebook.select(0)
        self.config = AppConfig()
        self.update_ui_state()
        logging.info("Active identity and all associated files have been deleted.")

    def create_and_save_identity(self):
        name = self.name_entry.get().strip()
        url_path = self.url_path_var.get().strip()
        image_base_url = self.image_base_url_var.get().strip()
        error_messages = []
        if not name:
            error_messages.append("• Issuer Name is required.")
        if not url_path or url_path == "https://":
            error_messages.append("• The URL Path for your Public ID file is required.")
        if not image_base_url or image_base_url == "https://":
            error_messages.append("• The Base URL for Document Images is required.")
        if error_messages:
            messagebox.showerror(
                "Input Error",
                "Please correct the following errors:\n\n" +
                "\n".join(error_messages))
            return
        try:
            parsed_url = urlparse(url_path)
            hostname = parsed_url.hostname
            if hostname:
                base_domain = (hostname[4:] if hostname.lower(
                ).startswith("www.") else hostname)
                final_ftp_guess = f"ftp.{base_domain}"
                self.config.ftp_host = final_ftp_guess
                self.ftp_host_var.set(final_ftp_guess)
            else:
                logging.warning(
                    "Could not extract a valid hostname from the provided URL.")
        except Exception as e:
            logging.error(f"Error parsing URL to get FTP host: {e}", exc_info=True)
        logo_filename = ""
        if self.logo_path:
            logo_filename = self.logo_path.name
        else:
            user_choice = messagebox.askyesno(
                "Confirm: No Logo Selected",
                "You have not selected a logo.\n\nIf you proceed, this identity will be created without one. This decision is PERMANENT and cannot be changed later.\n\nAre you sure you want to continue without a logo?",
                icon="warning")
            if not user_choice:
                return
        url_path = url_path if url_path.endswith("/") else url_path + "/"
        image_base_url = (image_base_url if image_base_url.endswith(
            "/") else image_base_url + "/")
        issuer_id = self.crypto_manager.generate_id_from_name(name)
        if not messagebox.askokcancel(
            "Confirm Identity Creation",
                f"This will create the identity '{name}' with the permanent ID:\n\n{issuer_id}\n\nProceed?"):
            return
        try:
            priv_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            priv_key_pem = priv_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()).decode("utf-8")
            pub_key_pem = (
                priv_key.public_key().public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo).decode("utf-8"))
            public_json_path = APP_DATA_DIR / INFO_FILENAME
            json_content = {
                "publicKeyPem": pub_key_pem,
                "imageBaseUrl": image_base_url,
                "issuerName": name}
            if logo_filename:
                json_content["logoUrl"] = url_path + logo_filename
            contact_info = {
                k: v for k,
                v in {
                    "email": self.email_entry.get().strip(),
                    "phone": self.phone_entry.get().strip(),
                    "address": self.address_entry.get().strip()}.items() if v}
            if contact_info:
                json_content["contactInfo"] = contact_info
            public_json_path.write_text(json.dumps(json_content, indent=2))
            key_filepath = APP_DATA_DIR / \
                KEY_FILENAME_TEMPLATE.format(issuer_id=issuer_id)
            key_filepath.write_text(priv_key_pem)
            try:
                self.all_issuer_data = (
                    json.loads(
                        ISSUER_DB_FILE.read_text()) if ISSUER_DB_FILE.exists() else {})
            except (IOError, json.JSONDecodeError):
                self.all_issuer_data = {}
            new_issuer_data_for_db = {
                "name": name,
                "infoUrl": url_path + INFO_FILENAME,
                "imageBaseUrl": image_base_url,
                "priv_key_pem": KeyStorage.FILE.value,
                "settings": {}}
            self.active_issuer_id = issuer_id
            self.all_issuer_data[self.active_issuer_id] = new_issuer_data_for_db
            self.config = AppConfig()
            self.config.hardened_security = False
            self.save_settings()
            self.active_issuer_data = new_issuer_data_for_db.copy()
            self.active_issuer_data["priv_key_pem"] = priv_key_pem
            logging.info(f"New identity created: {name} ({issuer_id})")
            key_file_name = key_filepath.name
            final_message = (
                "IDENTITY CREATED SUCCESSFULLY!\n\n"
                "Your critical identity files have been generated in the application's data folder. "
                "These files CANNOT be recovered if lost.\n\n"
                "**You MUST create a secure, offline backup of:**\n"
                f"  •  `{key_file_name}` (Your Private Key)\n"
                f"  •  `{ISSUER_DB_FILE.name}` (Your Settings)\n\n"
                "---------------------------------------------------\n"
                "**NEXT STEP: SERVER SETUP**\n\n"
                "You will now be taken to the 'Settings' tab to finalize your server configuration."
            )
            messagebox.showinfo("Success & Next Steps", final_message)
            self.update_ui_state()
            self.root.after(100, self.check_system_status)
            self.notebook.select(2)
        except Exception as e:
            logging.error(f"Failed to create identity: {e}", exc_info=True)
            messagebox.showerror(
                "Identity Creation Error",
                f"Failed to create identity: {e}")

    def _sign_single_document(self, proof_path: Path, summary_msg: str) -> bool:
        try:
            apply_text_watermark = (
                self.config.apply_watermark and self.license_manager.is_feature_enabled("watermark"))
            apply_logo_watermark = (
                self.config.apply_logo_watermark and self.license_manager.is_feature_enabled("watermark"))
            if self.config.apply_logo_watermark and not apply_logo_watermark:
                logging.warning(
                    "Logo watermark is toggled on, but license is missing. Skipping.")
            source_image = Image.open(proof_path)
            watermarked_img = self.image_processor.apply_text_watermark(
                source_image, self.config.watermark_text, apply_text_watermark)
            final_proof_image = self.image_processor.apply_logo_watermark(
                watermarked_img, self.original_status_logo_pil, apply_logo_watermark).convert("RGB")
            temp_dir = APP_DATA_DIR / "temp_upload"
            temp_dir.mkdir(exist_ok=True)
            sanitized_base = self.sanitize_filename(proof_path.stem)
            suffix = (f"-{''.join(random.choices(string.ascii_lowercase + string.digits,
                                                 k=4))}-Proof" if self.config.randomize_proof_name else "-Proof")
            upload_filename = f"{sanitized_base}{suffix}{proof_path.suffix}"
            prepared_upload_path = temp_dir / upload_filename
            image_format = (
                "JPEG" if proof_path.suffix.lower() in [
                    ".jpg", ".jpeg"] else "PNG")
            final_proof_image.save(
                prepared_upload_path,
                format=image_format,
                quality=95)
            file_hash = self.crypto_manager.calculate_file_hash(prepared_upload_path)
            if not file_hash:
                raise ValueError("Could not calculate proof file hash.")
            payload_dict = {
                "imgId": upload_filename,
                "msg": summary_msg,
                "h": file_hash}
            signature_b64 = self.crypto_manager.sign_payload(
                self.active_issuer_data["priv_key_pem"], payload_dict)
            if (self.config.enable_audit_trail and self.license_manager.is_feature_enabled("audit")):
                log_details = {
                    "filename": upload_filename,
                    "message": summary_msg,
                    "file_hash": file_hash}
                self.crypto_manager.log_event(
                    self.active_issuer_id,
                    self.active_issuer_data["priv_key_pem"],
                    "SIGN_SUCCESS",
                    log_details)
            payload_b64 = base64.b64encode(
                json.dumps(
                    payload_dict, separators=(
                        ",", ":")).encode("utf-8")).decode("utf-8")
            final_qr_string = f"{self.active_issuer_id}-{payload_b64}-{signature_b64}"
            doc_logo_path = resource_path("legatokey.png")
            document_logo_pil = (Image.open(doc_logo_path)
                                 if doc_logo_path.exists() else None)
            qr_image_pil = self.image_processor.generate_qr_with_logo(
                final_qr_string, document_logo_pil, box_size=10, sizing_ratio=0.40)
            save_dir = Path(self.config.qr_save_path)
            save_dir.mkdir(exist_ok=True)
            qr_save_path = save_dir / f"{prepared_upload_path.stem}-QR.png"
            qr_image_pil.save(qr_save_path)
            if self.config.make_local_copy:
                permanent_dir = Path(self.config.proof_save_path)
                permanent_dir.mkdir(exist_ok=True)
                shutil.copy(prepared_upload_path, permanent_dir / upload_filename)
            if self.config.ftp_auto_upload:
                is_success, result_msg = self._upload_single_file(prepared_upload_path)
                if not is_success:
                    logging.error(
                        f"Upload failed for {
                            prepared_upload_path.name}: {result_msg}")
            self.qr_image_pil = qr_image_pil
            self.prepared_upload_path = prepared_upload_path
            self.last_signed_payload = f"{upload_filename}|{summary_msg}|{file_hash}"
            return True
        except Exception as e:
            logging.error(
                f"Error signing document {
                    proof_path.name}: {e}",
                exc_info=True)
            if not threading.current_thread().name.startswith("Thread"):
                messagebox.showerror(
                    "Signing Error",
                    f"An error occurred while signing {
                        proof_path.name}: {e}")
            return False

    def generate_document_qr(self):
        if self.is_generating or not self.selected_proof_file_path:
            return
        self.is_generating = True
        try:
            summary_msg = self.message_text.get("1.0", "end-1c").strip()
            if self._sign_single_document(self.selected_proof_file_path, summary_msg):
                self.update_qr_display(self.qr_image_pil)
                final_proof_image = Image.open(self.prepared_upload_path)
                proof_with_overlay = self.image_processor.overlay_checkmark(
                    final_proof_image, scale_ratio=0.8)
                self.update_proof_display(proof_with_overlay)
                if not self.config.ftp_auto_upload:
                    self.upload_button_state = UploadButtonState.READY
                    self.update_upload_button_display()
        finally:
            self.is_generating = False

    def update_ui_state(self):
        self.upload_button_state = UploadButtonState.INITIAL
        self.update_upload_button_display()
        has_identity = bool(self.active_issuer_id)
        for i in range(1, self.notebook.index("end")):
            tab_text = self.notebook.tab(i, "text")
            if "💎" not in tab_text:
                self.notebook.tab(i, state="normal" if has_identity else "disabled")

        widget_map = {
            self.pro_security_checkbox: has_identity,
            self.randomize_proof_name_checkbox: has_identity,
            self.make_local_copy_checkbox: has_identity,
        }
        for widget, is_enabled in widget_map.items():
            widget.config(state="normal" if is_enabled else "disabled")

        is_watermark_licensed = self.license_manager.is_feature_enabled("watermark")
        self.apply_watermark_checkbox.config(
            state="normal" if has_identity and is_watermark_licensed else "disabled")
        self.apply_logo_watermark_checkbox.config(
            state="normal" if has_identity and is_watermark_licensed else "disabled")
        is_audit_licensed = self.license_manager.is_feature_enabled("audit")
        self.enable_audit_trail_checkbox.config(
            state="normal" if has_identity and is_audit_licensed else "disabled")

        if has_identity:
            self.toggle_proof_path_state()
            self.toggle_watermark_state()
            self.setup_frame.pack_forget()
            self.manage_frame.pack(fill="x", pady=(0, 10))
            self.update_manage_frame_display()
            self.update_issuer_qr_display()
            self._update_ftp_dependent_widgets_state()

            if is_audit_licensed:
                self._handle_refresh_audit()
        else:
            self.proof_path_entry.config(state="disabled")
            self.proof_path_browse_btn.config(state="disabled")
            self.watermark_entry.config(state="disabled")

            if hasattr(self, 'auto_upload_check'):
                self.auto_upload_check.config(state="disabled")

            if hasattr(self, "setup_frame"):
                self.setup_frame.pack(fill="x", pady=(0, 10))
            if hasattr(self, "manage_frame"):
                self.manage_frame.pack_forget()
            self.status_message_label.config(
                text="No identity loaded. Create one to begin.",
                bootstyle=PRIMARY)
            self.status_details_label.config(text="Go to the 'Issuer Identity' tab.")
            self.set_status_logo(None)
            self.check_status_button.config(state="disabled")
        self.update_auto_upload_indicator()

    def update_manage_frame_display(self):
        if not self.active_issuer_data:
            return
        self.id_label.config(text=self.active_issuer_id)
        self.name_label.config(text=self.active_issuer_data.get("name", "N/A"))
        self.url_label.config(text=self.active_issuer_data.get("infoUrl", "N/A"))
        contact = self.active_issuer_contact_info
        self.email_label_val.config(text=contact.get("email", "N/A"))
        self.phone_label_val.config(text=contact.get("phone", "N/A"))
        self.address_label_val.config(text=contact.get("address", "N/A"))

    def update_qr_display(self, pil_image: Image.Image):
        display_qr = pil_image.copy()
        display_qr.thumbnail((300, 300), self.image_processor.resample_method)
        qr_tk = ImageTk.PhotoImage(display_qr)
        self.qr_display_label.config(image=qr_tk)
        self.qr_display_label.image = qr_tk

    def update_proof_display(self, pil_image: Image.Image):
        display_proof = pil_image.copy()
        display_proof.thumbnail((300, 300), self.image_processor.resample_method)
        self.proof_image_tk = ImageTk.PhotoImage(display_proof.convert("RGB"))
        self.proof_image_display_label.config(image=self.proof_image_tk)
        self.proof_image_display_label.image = self.proof_image_tk

    def clear_proof_image_display(self):
        self.proof_image_display_label.config(image="")
        self.proof_image_pil = None
        self.proof_image_tk = None

    def update_issuer_qr_display(self):
        if not self.active_issuer_id:
            if hasattr(self, "issuer_qr_display_label"):
                self.issuer_qr_display_label.config(image="")
            self.issuer_qr_image_pil = None
            return
        payload = {
            "qr_type": "issuer_info_v1",
            "id": self.active_issuer_id,
            "name": self.active_issuer_data["name"],
            "infoUrl": self.active_issuer_data["infoUrl"]}
        self.issuer_qr_image_pil = self.image_processor.generate_qr_with_logo(
            json.dumps(payload), self.original_status_logo_pil, sizing_ratio=0.85)
        display_img = self.issuer_qr_image_pil.copy()
        display_img.thumbnail((250, 250), self.image_processor.resample_method)
        img_tk = ImageTk.PhotoImage(display_img)
        self.issuer_qr_display_label.config(image=img_tk)
        self.issuer_qr_display_label.image = img_tk

    def browse_and_set_proof_file(self):
        if not self.reset_upload_button_state():
            return
        filepath_str = filedialog.askopenfilename(
            title="Select the original proof file", filetypes=[
                ("Image Files", "*.jpg *.jpeg *.png *.bmp"), ("All files", "*.*")])
        if not filepath_str:
            self.clear_proof_image_display()
            self.doc_id_helper_label.config(text="File selection cancelled.")
            self.generate_qr_button.config(state="disabled")
            self.selected_proof_file_path = None
            return
        self.selected_proof_file_path = Path(filepath_str)
        self.doc_id_helper_label.config(
            text=f"Selected: {
                self.selected_proof_file_path.name}")
        try:
            self.proof_image_pil = Image.open(self.selected_proof_file_path)
            self.update_proof_display(self.proof_image_pil)
            self.generate_qr_button.config(state="normal")
        except Exception as e:
            logging.error(f"Could not load image: {e}", exc_info=True)
            messagebox.showerror("Image Load Error", f"Could not load image: {e}")
            self.clear_proof_image_display()

    def get_full_remote_path(self) -> Union[str, None]:
        if not self.active_issuer_data:
            return None
        ftp_root = self.config.ftp_path.strip()
        if not ftp_root:
            self.root.after(
                0,
                lambda: messagebox.showerror(
                    "Configuration Error",
                    "FTP Web Root Path is not set in Settings."))
            return None
        if not ftp_root.startswith("/"):
            ftp_root = "/" + ftp_root
        try:
            image_url = self.active_issuer_data.get("imageBaseUrl", "")
            parsed_url = urlparse(image_url)
            url_path_part = parsed_url.path
        except Exception:
            self.root.after(
                0,
                lambda: messagebox.showerror(
                    "Configuration Error",
                    "The Image Base URL is invalid."))
            return None
        full_path = Path(ftp_root) / url_path_part.lstrip("/")
        return full_path.as_posix()

    def handle_save_and_upload_threaded(self):
        self._sync_config_from_ui()
        self.save_and_upload_button.config(state="disabled", text="Working...")
        threading.Thread(target=self._save_and_upload_worker, daemon=True).start()

    def _save_and_upload_worker(self):
        host = self.config.ftp_host
        user = self.config.ftp_user
        password = ""
        if self.config.hardened_security:
            password = self.crypto_manager.load_ftp_password(self.active_issuer_id)
        else:
            try:
                password = base64.b64decode(self.config.ftp_pass_b64).decode("utf-8")
            except Exception:
                pass
        test_result = self.ftp_manager.test_connection(host, user, password)
        if test_result != "Success":
            self.root.after(
                0,
                lambda: messagebox.showerror(
                    "Connection Failed",
                    f"Could not connect to the FTP server. Please check your settings.\n\nError: {test_result}"))
            self.root.after(
                0, self.save_and_upload_button.config, {
                    "state": "normal", "text": "✔️ Save Settings & Upload Public Files"})
            return
        if self.active_issuer_id in self.all_issuer_data:
            self.all_issuer_data[self.active_issuer_id]["settings"] = self._gather_settings_data_from_config(
            )
            self.settings_manager.save_app_data(self.all_issuer_data)
            logging.info("FTP settings saved successfully after test.")
        self._upload_public_files_worker()
        self.root.after(
            0, self.save_and_upload_button.config, {
                "state": "disabled", "text": "✔️ Saved & Uploaded!"})

    def _get_active_ftp_settings(self) -> Union[dict, None]:
        if not self.active_issuer_id or not self.active_issuer_data:
            return None
        password = ""
        if self.config.hardened_security:
            password = self.crypto_manager.load_ftp_password(self.active_issuer_id)
            if password is None:
                self.root.after(
                    0,
                    lambda: messagebox.showerror(
                        "FTP Error",
                        "Hardened Security is ON, but the FTP password was not found in the secure OS storage."))
                return None
        else:
            try:
                password = base64.b64decode(self.config.ftp_pass_b64).decode("utf-8")
            except Exception:
                pass
        return {
            "host": self.config.ftp_host,
            "user": self.config.ftp_user,
            "path": self.config.ftp_path,
            "password": password}

    def _upload_public_files_worker(self):
        full_image_path_str = self.get_full_remote_path()
        if not full_image_path_str:
            return
        target_dir_for_public_files = str(Path(full_image_path_str).parent)
        ftp_settings = self._get_active_ftp_settings()
        if not ftp_settings:
            return
        json_filepath = APP_DATA_DIR / INFO_FILENAME
        logo_filepath = (
            self.logo_path if self.logo_path and self.logo_path.exists() else None)
        if not json_filepath.exists():
            logging.error(f"Upload failed: {json_filepath.name} not found.")
            self.root.after(
                0, lambda: messagebox.showerror(
                    "File Not Found", f"Could not find required file: {
                        json_filepath.name}"))
            return
        ftp_settings_for_upload = ftp_settings.copy()
        ftp_settings_for_upload["path"] = target_dir_for_public_files
        logging.info(
            f"Attempting to upload '{
                json_filepath.name}' to FTP directory: {target_dir_for_public_files}")
        json_result = self.ftp_manager.upload_file(
            json_filepath, json_filepath.name, ftp_settings_for_upload)
        if "successful" not in json_result.lower():
            logging.error(f"FTP upload failed for JSON file. Reason: {json_result}")
            self.root.after(
                0, lambda: messagebox.showerror(
                    "FTP Error (JSON)", json_result))
            return
        logging.info(f"Successfully uploaded '{json_filepath.name}'.")
        if logo_filepath:
            logging.info(
                f"Attempting to upload '{
                    logo_filepath.name}' to FTP directory: {target_dir_for_public_files}")
            logo_result = self.ftp_manager.upload_file(
                logo_filepath, logo_filepath.name, ftp_settings_for_upload)
            if "successful" not in logo_result.lower():
                logging.error(f"FTP upload failed for logo file. Reason: {logo_result}")
                self.root.after(
                    0, lambda: messagebox.showerror(
                        "FTP Error (Logo)", logo_result))
                return
            logging.info(f"Successfully uploaded '{logo_filepath.name}'.")
            self.root.after(0, lambda: messagebox.showinfo(
                "Upload Complete", f"Successfully uploaded:\n\n- {json_filepath.name}\n- {logo_filepath.name}"))
        else:
            self.root.after(0, lambda: messagebox.showinfo(
                "Upload Complete", f"Successfully uploaded:\n\n- {json_filepath.name}"))
        self.root.after(100, self.check_system_status)

    def _upload_single_file(self, local_path: Path):
        full_remote_path = self.get_full_remote_path()
        if not full_remote_path:
            return (
                False,
                "Could not determine the full FTP remote path. Check your settings.")
        ftp_settings = self._get_active_ftp_settings()
        if not ftp_settings:
            return False, "Could not get FTP settings."
        ftp_settings["path"] = full_remote_path
        result = self.ftp_manager.upload_file(local_path, local_path.name, ftp_settings)
        is_success = "successful" in result.lower()
        if self.config.enable_audit_trail and self.license_manager.is_feature_enabled(
                "audit"):
            event_type = "UPLOAD_SUCCESS" if is_success else "UPLOAD_FAILURE"
            log_details = {"filename": local_path.name, "result_message": result}
            self.crypto_manager.log_event(
                self.active_issuer_id,
                self.active_issuer_data["priv_key_pem"],
                event_type,
                log_details)
        return is_success, result

    def upload_proof_file_threaded(self):
        if (not self.prepared_upload_path or self.upload_button_state ==
                UploadButtonState.UPLOADING):
            return
        self.upload_button_state = UploadButtonState.UPLOADING
        self.update_upload_button_display()
        threading.Thread(
            target=self._run_and_show_upload_result,
            args=(
                self.prepared_upload_path,
            ),
            daemon=True).start()

    def _run_and_show_upload_result(self, local_path: Path):
        is_success, result = self._upload_single_file(local_path)
        self.upload_button_state = (
            UploadButtonState.SUCCESS if is_success else UploadButtonState.FAILURE)
        if not is_success:
            self.root.after(0, lambda: messagebox.showerror("FTP Upload Error", result))
        else:
            try:
                local_path.unlink()
                logging.info(
                    f"Successfully cleaned up temporary file: {
                        local_path.name}")
            except Exception as e:
                logging.warning(
                    f"Could not remove temporary file {
                        local_path.name}: {e}")
        self.root.after(0, self.update_upload_button_display)

    def handle_auto_sense_threaded(self):
        host = self.ftp_host_var.get()
        user = self.ftp_user_var.get()
        password = self.ftp_pass_var.get()
        if not all([host, user, password]):
            messagebox.showwarning(
                "Missing Info",
                "Please fill in the FTP Host, Username, and Password fields before using Auto-Sense.")
            return
        self.sense_button.config(state="disabled", text="Sensing...")
        self.ftp_path_entry.config(state="disabled")
        threading.Thread(
            target=self._sense_ftp_root_worker, args=(
                host, user, password), daemon=True).start()

    def _sense_ftp_root_worker(self, host, user, password):
        COMMON_WEB_ROOTS = ["public_html", "htdocs", "httpdocs", "www", "html"]
        try:
            with ftplib.FTP(host, timeout=15) as ftp:
                ftp.login(user, password)
                try:
                    ftp.cwd("/")
                except ftplib.error_perm:
                    pass
                dir_list = ftp.nlst()
                found_root = None
                for root_name in COMMON_WEB_ROOTS:
                    if root_name in dir_list:
                        found_root = f"/{root_name}/"
                        break
                if found_root:
                    self.root.after(0, self.on_auto_sense_success, found_root)
                else:
                    self.root.after(
                        0,
                        self.on_auto_sense_failure,
                        "Could not find a common web root directory. Please enter it manually.")
        except ftplib.all_errors as e:
            error_message = f"FTP Error: {e}\nPlease check your credentials and host."
            self.root.after(0, self.on_auto_sense_failure, error_message)
        except Exception as e:
            error_message = f"An unexpected error occurred: {e}"
            self.root.after(0, self.on_auto_sense_failure, error_message)

    def on_auto_sense_success(self, found_path):
        self.ftp_path_var.set(found_path)
        messagebox.showinfo(
            "Path Found!",
            f"Successfully found web root: {found_path}\n\nThe application will now automatically save your settings and upload your public files.")
        self.handle_save_and_upload_threaded()

    def on_auto_sense_failure(self, error_message):
        self.sense_button.config(state="normal", text="🔎 Auto-Sense")
        self.ftp_path_entry.config(state="normal")
        if hasattr(self, "save_and_upload_button"):
            self.save_and_upload_button.config(state="normal")
        messagebox.showerror("Auto-Sense Failed", error_message)

    def check_system_status(self):
        if not self.active_issuer_id:
            return
        self.system_is_verified = False
        self.check_status_button.config(state="disabled")
        self.status_message_label.config(text="Checking...", bootstyle=WARNING)
        self.status_details_label.config(
            text=f"Fetching: {
                self.active_issuer_data['infoUrl']}")
        self.set_status_logo(None)
        self.active_issuer_contact_info = {}
        self.update_manage_frame_display()
        threading.Thread(target=self._check_status_worker, daemon=True).start()

    def _check_status_worker(self):
        info_url = self.active_issuer_data["infoUrl"]

        def update_status(msg, style, details=""):
            self.status_message_label.config(text=msg, bootstyle=style)
            self.status_details_label.config(text=details)
        try:
            response = requests.get(info_url, timeout=10)
            response.raise_for_status()
            online_data = response.json()
            priv_key = serialization.load_pem_private_key(
                self.active_issuer_data["priv_key_pem"].encode("utf-8"), password=None)
            local_pub_key_pem = (
                priv_key.public_key().public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo).decode("utf-8"))
            if online_data.get("publicKeyPem") != local_pub_key_pem:
                self.root.after(
                    0,
                    update_status,
                    "❌ PUBLIC KEY MISMATCH!",
                    DANGER,
                    "Key on server doesn't match local key.")
                return
            self.active_issuer_contact_info = online_data.get("contactInfo", {})
            logo_pil = None
            if logo_url := online_data.get("logoUrl"):
                try:
                    with requests.get(logo_url, timeout=5, stream=True) as logo_response:
                        logo_response.raise_for_status()
                        image_data = io.BytesIO()
                        downloaded_size = 0
                        for chunk in logo_response.iter_content(chunk_size=8192):
                            downloaded_size += len(chunk)
                            if downloaded_size > MAX_LOGO_SIZE_BYTES:
                                raise ValueError(
                                    f"Logo file download aborted, size exceeds limit of {
                                        MAX_LOGO_SIZE_BYTES / 1024**2:.1f} MB.")
                            image_data.write(chunk)
                        image_data.seek(0)
                        logo_pil = Image.open(image_data)
                except Exception as e:
                    logging.error(
                        f"Failed to load logo from {logo_url}: {e}",
                        exc_info=True)
            self.root.after(0, self.set_status_logo, logo_pil)
            self.root.after(
                0,
                update_status,
                "✅ System Online & Verified",
                SUCCESS,
                "Your public key is accessible and correct.")
            self.system_is_verified = True
            self.root.after(0, self.update_issuer_qr_display)
            self.root.after(0, self.update_manage_frame_display)

        except requests.exceptions.RequestException as e:
            logging.error(f"Network error checking system status: {e}", exc_info=True)

            if isinstance(e, requests.exceptions.HTTPError):

                ui_details = f"Server returned an error ({
                    e.response.status_code}). Please ensure '{INFO_FILENAME}' is uploaded and accessible."
            else:

                ui_details = "Connection failed. Please check your internet connection and the server URL in your Identity settings."

            self.root.after(
                0,
                update_status,
                "⚠️ OFFLINE OR CONFIG ERROR!",
                DANGER,
                ui_details)

        except (json.JSONDecodeError, KeyError) as e:

            logging.error(f"Invalid JSON checking system status: {e}", exc_info=True)

            ui_details = f"The '{INFO_FILENAME}' file on your server appears to be corrupt or is missing required data."
            self.root.after(
                0,
                update_status,
                "⚠️ INVALID PUBLIC FILE!",
                DANGER,
                ui_details)

        finally:
            if self.active_issuer_id:
                self.root.after(0, self.check_status_button.config, {"state": "normal"})

    def _validate_https_prefix(self, v): return v.startswith("https://")

    def _validate_image_url_prefix(
        self, v): return not self.current_root_url or v.startswith(
        self.current_root_url)

    def sanitize_filename(self, f): return "".join(
        c for c in f if c not in '<>:"/\\|?*').strip()

    def toggle_password_visibility(self): self.ftp_pass_entry.config(
        show="" if self.show_pass_var.get() else "*")

    def on_ftp_settings_change(self, *args):
        if hasattr(self, "save_and_upload_button"):
            self.save_and_upload_button.config(state="normal")

    def update_upload_button_display(self):
        text, style, state = self.upload_button_state.value
        final_style = style
        if (self.config.ftp_auto_upload and self.upload_button_state ==
                UploadButtonState.INITIAL):
            final_style = "success-outline"
        self.upload_button.config(text=text, bootstyle=final_style, state=state)

    def reset_upload_button_state(self):
        self.upload_button_state = UploadButtonState.INITIAL
        self.update_upload_button_display()
        self.last_signed_payload = None
        return True

    def set_status_logo(self, pil_image):
        self.original_status_logo_pil = pil_image
        if pil_image:
            display_logo = pil_image.resize(
                (120, 64), self.image_processor.resample_method)
        else:
            display_logo = Image.new("RGB", (120, 64), "lightgray")
        img_tk = ImageTk.PhotoImage(display_logo)
        self.status_logo_label.config(image=img_tk)
        self.status_logo_label.image = img_tk

    def export_issuer_qr(self):
        if not self.issuer_qr_image_pil:
            return
        file_path_str = filedialog.asksaveasfilename(
            defaultextension=".png", initialfile=f"issuer_{
                self.active_issuer_id}_qr.png", title="Save Issuer Public Key QR")
        if file_path_str:
            self.issuer_qr_image_pil.save(file_path_str)

    def email_issuer_qr(self):
        if not self.issuer_qr_image_pil:
            return
        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tf:
            temp_path = Path(tf.name)
            self.issuer_qr_image_pil.save(temp_path)
        name = self.active_issuer_data.get("name", "My Issuer")
        subject = f"LegatoLink Authoroty ID for {name}"
        body = f"Hello,\n\nAttached is my LegatoLink Authoroty ID, you maysuse the legatolink on your app to scan the attached QR code.\n\nInfo URL: {
            self.active_issuer_data.get(
                'infoUrl', 'N/A')}\n\nBest regards,\n{name}"
        webbrowser.open(
            f"mailto:?subject={
                requests.utils.quote(subject)}&body={
                requests.utils.quote(body)}")
        messagebox.showinfo(
            "Email Client Opened",
            f"Please attach the following file to your email:\n\n{temp_path}")

    def print_issuer_qr(self):
        if not self.issuer_qr_image_pil:
            return
        try:
            with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tf:
                self.issuer_qr_image_pil.save(tf.name)
                if sys.platform == "win32":
                    os.startfile(tf.name, "print")
                elif sys.platform == "darwin":
                    subprocess.call(["open", "-a", "Preview", tf.name])
                else:
                    subprocess.call(["xdg-open", tf.name])
        except Exception as e:
            logging.error(f"Could not open image for printing: {e}", exc_info=True)
            messagebox.showerror(
                "Printing Error",
                f"Could not open image for printing: {e}")

    def update_image_base_url_proposal(self, *args):
        try:
            parsed = urlparse(self.url_path_var.get())
            if parsed.scheme and parsed.netloc:
                root = f"{parsed.scheme}://{parsed.netloc}/"
                self.current_root_url = root
                self.image_base_url_var.set(root)
                self.image_base_url_example_label.config(
                    text=f"Example: {root}certificates/")
            else:
                self.current_root_url = ""
        except Exception:
            self.current_root_url = ""

    def _validate_summary_length(self, event=None):
        current_text = self.message_text.get("1.0", "end-1c")
        current_length = len(current_text)
        if current_length > MAX_SUMMARY_CHARS:
            truncated_text = current_text[:MAX_SUMMARY_CHARS]
            cursor_pos = self.message_text.index(ttk.INSERT)
            self.message_text.delete("1.0", "end")
            self.message_text.insert("1.0", truncated_text)
            self.message_text.mark_set(ttk.INSERT, cursor_pos)
            current_length = MAX_SUMMARY_CHARS
        self.char_count_label.config(text=f"{current_length} / {MAX_SUMMARY_CHARS}")
        self.char_count_label.config(
            bootstyle="danger" if current_length >= MAX_SUMMARY_CHARS else "secondary")

    def create_status_panel(self):
        self.status_frame = ttk.LabelFrame(
            self.root, text="System Status", padding="10")
        self.status_frame.pack(fill="x", padx=10, pady=(10, 0))
        logo_frame = ttk.Frame(self.status_frame)
        logo_frame.pack(side="left", padx=(0, 15))
        self.status_logo_label = ttk.Label(logo_frame)
        self.status_logo_label.pack()
        self.set_status_logo(None)
        info_frame = ttk.Frame(self.status_frame)
        info_frame.pack(side="left", fill="x", expand=True)
        self.status_message_label = ttk.Label(
            info_frame, text="Starting up...", font=(
                "Helvetica", 10, "bold"), bootstyle=PRIMARY)
        self.status_message_label.pack(anchor="w")
        self.status_details_label = ttk.Label(
            info_frame,
            text="The system will check if your public info is online and valid.",
            wraplength=650)
        self.status_details_label.pack(anchor="w", pady=(5, 0))
        self.check_status_button = ttk.Button(
            self.status_frame,
            text="Check Status Now",
            command=self.check_system_status,
            state="disabled",
            bootstyle=SECONDARY)
        self.check_status_button.pack(side="right", anchor="s", padx=(10, 0))
        license_status_text = (
            f"Pro License: {
                self.license_manager.customer_info}" if self.license_manager.is_licensed else "Pro License: Not Active")
        license_status_style = SUCCESS if self.license_manager.is_licensed else WARNING
        self.pro_status_label = ttk.Label(
            info_frame,
            text=license_status_text,
            bootstyle=license_status_style)
        self.pro_status_label.pack(anchor="w", pady=(5, 0))
        ttk.Separator(self.root, orient=HORIZONTAL).pack(fill="x", padx=10, pady=5)

    def create_main_ui(self):
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill="both", expand=True)
        self.notebook = ttk.Notebook(main_frame, bootstyle="primary")
        self.notebook.pack(fill="both", expand=True)
        tabs_info = [
            {"text": " 1. Issuer Identity ", "method": self.create_identity_tab, "pro_feature": None},
            {"text": " 2. Sign Document ", "method": self.create_signer_tab, "pro_feature": None},
            {"text": " 3. Settings & Uploads ", "method": self.create_settings_and_uploads_tab, "pro_feature": None},
            {"text": " 4. Batch Processing ", "method": self.create_batch_signing_tab, "pro_feature": "batch"},
            {"text": " 5. Audit Trail ", "method": self.create_audit_viewer_tab, "pro_feature": "audit"},
            {"text": " 6. Guide ", "method": self.create_guide_tab, "pro_feature": None},
            {"text": " 7. Backup & Security ", "method": self.create_backup_and_security_tab, "pro_feature": None},
            {"text": " 8. About ", "method": self.create_about_tab, "pro_feature": None},
        ]
        for info in tabs_info:
            tab_frame = ttk.Frame(self.notebook, padding="10")
            is_pro = info["pro_feature"] is not None
            is_enabled = ((self.license_manager.is_feature_enabled(
                info["pro_feature"]) and PRO_FEATURES_AVAILABLE) if is_pro else True)
            if is_pro and not is_enabled:
                tab_text = f"💎 {info['text']}"
                self.notebook.add(tab_frame, text=tab_text, state="disabled")
                pro_label_frame = ttk.Frame(tab_frame, padding=20)
                pro_label_frame.pack(fill="both", expand=True)
                ttk.Label(pro_label_frame, text=f"This is a Professional Feature",
                          font="-weight bold -size 14").pack(pady=(20, 5))
                ttk.Label(
                    pro_label_frame,
                    text="Please purchase a Pro license to enable this functionality.",
                    bootstyle="secondary").pack()
                ttk.Button(pro_label_frame, text="Visit our Website to Upgrade", bootstyle="success",
                           command=lambda: webbrowser.open("https://www.example.com/pricing")).pack(pady=20)
            else:
                self.notebook.add(tab_frame, text=info["text"])
                info["method"](tab_frame)

    def _clear_logo(self):
        """Clears the selected logo and resets the display."""
        self.logo_path = None
        self.logo_display_label.config(image=None)
        self.logo_display_label.image = None
        self.logo_display_label.grid_remove()
        self.logo_text_frame.grid(row=0, column=0, sticky="nsew")
        logging.info("User cleared the logo selection.")

    def _browse_for_logo(self):
        filepath = filedialog.askopenfilename(
            title="Select Your Logo Image", filetypes=[
                ("Image Files", "*.png *.jpg *.jpeg"), ("All files", "*.*")])
        if not filepath:
            return

        source_path = Path(filepath)
        if source_path.stat().st_size > MAX_LOGO_SIZE_BYTES:
            messagebox.showerror(
                "File Too Large",
                f"The selected logo exceeds the {
                    MAX_LOGO_SIZE_BYTES /
                    1024:.0f}KB size limit.")
            return

        try:
            image_to_process = Image.open(source_path)
            width, height = image_to_process.size
            if (width * height) > MAX_LOGO_PIXELS:
                ratio = (MAX_LOGO_PIXELS / (width * height)) ** 0.5
                new_width = int(width * ratio)
                new_height = int(height * ratio)
                messagebox.showinfo(
                    "Logo Resized",
                    f"Your logo was larger than the recommended dimensions ({width}x{height}).\n\nIt has been automatically resized to {new_width}x{new_height} to ensure optimal performance.")
                image_to_process = image_to_process.resize(
                    (new_width, new_height), Image.Resampling.LANCZOS)

            logo_extension = source_path.suffix
            standardized_logo_path = (APP_DATA_DIR /
                                      f"{STANDARDIZED_LOGO_BASENAME}{logo_extension}")
            if logo_extension.lower() in [".jpg", ".jpeg"]:
                if image_to_process.mode in ["RGBA", "P"]:
                    image_to_process = image_to_process.convert("RGB")
                image_to_process.save(standardized_logo_path, "jpeg", quality=95)
            elif logo_extension.lower() == ".png":
                image_to_process.save(standardized_logo_path, "png")
            else:
                image_to_process.save(standardized_logo_path)
            self.logo_path = standardized_logo_path
            logging.info(f"Logo selected and saved to {self.logo_path}")

            display_img = Image.open(self.logo_path)
            display_img.thumbnail((250, 250), Image.Resampling.LANCZOS)
            logo_photo = ImageTk.PhotoImage(display_img)
            self.logo_display_label.config(image=logo_photo)
            self.logo_display_label.image = logo_photo
            self.logo_text_frame.grid_remove()
            self.logo_display_label.grid(row=0, column=0, sticky="nsew")
        except Exception as e:
            logging.error(f"Failed to process logo file: {e}", exc_info=True)
            messagebox.showerror(
                "File Error",
                f"Could not process the selected logo file.\nPlease ensure it is a valid image.\n\nError: {e}")
            self._clear_logo()

    def _update_wraplength(self, event, label_widget):
        """
        A helper function to dynamically set a label's wraplength
        based on its parent widget's configured width.
        """

        padding = 20
        label_widget.config(wraplength=event.width - padding)

    def create_identity_tab(self, parent_frame):
        self.setup_frame = ttk.LabelFrame(
            parent_frame, text="🔑 Create Your Issuer Identity", padding=15)
        self.setup_frame.pack(fill="x", pady=(0, 10))
        self.setup_frame.grid_columnconfigure(0, weight=0)
        self.setup_frame.grid_columnconfigure(1, weight=1)

        logo_panel = ttk.Frame(self.setup_frame)
        logo_panel.grid(row=0, column=0, sticky="n", padx=(0, 20))
        logo_container = ttk.LabelFrame(logo_panel, text="Your Logo (Optional)")
        logo_container.pack()

        self.logo_placeholder_frame = ttk.Frame(logo_container, width=250, height=250)
        self.logo_placeholder_frame.pack(padx=10, pady=10)
        self.logo_placeholder_frame.grid_propagate(False)
        self.logo_placeholder_frame.grid_rowconfigure(0, weight=1)
        self.logo_placeholder_frame.grid_columnconfigure(0, weight=1)

        self.logo_text_frame = ttk.Frame(self.logo_placeholder_frame)
        self.logo_text_frame.grid(row=0, column=0, sticky="nsew")
        self.logo_text_frame.grid_rowconfigure((0, 1), weight=1)
        self.logo_text_frame.grid_columnconfigure(0, weight=1)
        ttk.Label(
            self.logo_text_frame,
            text="No Logo Selected",
            bootstyle="secondary").pack(
            expand=True)
        ttk.Label(
            self.logo_text_frame,
            text="Recommended: 400x184 pixels",
            bootstyle="secondary").pack(
            expand=True)

        self.logo_display_label = ttk.Label(
            self.logo_placeholder_frame, anchor="center")
        logo_button_frame = ttk.Frame(logo_container)
        logo_button_frame.pack(pady=(0, 10), fill='x', padx=5)
        logo_button_frame.grid_columnconfigure((0, 1), weight=1)

        ttk.Button(
            logo_button_frame,
            text="🖼️ Browse...",
            command=self._browse_for_logo,
            bootstyle="outline").grid(
            row=0,
            column=0,
            sticky='ew',
            padx=(
                0,
                2))
        ttk.Button(logo_button_frame, text="🗑️ Clear Logo", command=self._clear_logo,
                   bootstyle="outline-danger").grid(row=0, column=1, sticky='ew', padx=(2, 0))

        right_panel = ttk.Frame(self.setup_frame)
        right_panel.grid(row=0, column=1, sticky="new")
        ttk.Label(right_panel,
                  text="Enter your name or organisation",
                  font="-weight bold").pack(anchor="w")
        ttk.Label(
            right_panel,
            text="(This will be used to generates your permanent  ID and identifies you as authority)",
            bootstyle="info").pack(
            anchor="w",
            pady=(
                0,
                5))
        self.name_entry = ttk.Entry(right_panel)
        self.name_entry.pack(fill="x", pady=(0, 15))

        ttk.Label(right_panel,
                  text="Enter the adress of your web server",
                  font="-weight bold").pack(anchor="w")
        ttk.Label(
            right_panel,
            text="(this is where your public Legato ID will be storeed e.g., https://your-site.com/)",
            bootstyle="info").pack(
            anchor="w",
            pady=(
                0,
                5))
        vcmd_https = (self.root.register(self._validate_https_prefix), "%P")
        self.url_path_entry = ttk.Entry(
            right_panel,
            textvariable=self.url_path_var,
            validate="key",
            validatecommand=vcmd_https)
        self.url_path_var.set("https://")
        self.url_path_entry.pack(fill="x", pady=(0, 15))

        ttk.Label(right_panel,
                  text="Chose the folder on your server where signed Document will be placed",
                  font="-weight bold").pack(anchor="w")

        helper_text_frame = ttk.Frame(right_panel)
        helper_text_frame.pack(fill="x", pady=(0, 5))

        ttk.Label(
            helper_text_frame,
            text="(This will be used to store your signed documents)",
            bootstyle="info").pack(
            side="left")

        self.image_base_url_example_label = ttk.Label(
            helper_text_frame, text="e.g: [...]", bootstyle="secondary")
        self.image_base_url_example_label.pack(side="right")

        vcmd_img_prefix = (self.root.register(self._validate_image_url_prefix), "%P")
        self.image_base_url_entry = ttk.Entry(
            right_panel,
            textvariable=self.image_base_url_var,
            validate="key",
            validatecommand=vcmd_img_prefix)
        self.image_base_url_entry.pack(fill="x", pady=(0, 15))

        self.url_path_var.trace_add("write", self.update_image_base_url_proposal)

        optional_frame = ttk.LabelFrame(
            right_panel, text="Optional Public Contact Info", padding=10)
        optional_frame.pack(fill="x", pady=(5, 15))
        optional_frame.grid_columnconfigure(1, weight=1)
        ttk.Label(
            optional_frame,
            text="Email:").grid(
            row=0,
            column=0,
            sticky="w",
            padx=(
                0,
                10),
            pady=2)
        self.email_entry = ttk.Entry(optional_frame)
        self.email_entry.grid(row=0, column=1, sticky="ew")
        ttk.Label(
            optional_frame,
            text="Phone:").grid(
            row=1,
            column=0,
            sticky="w",
            padx=(
                0,
                10),
            pady=2)
        self.phone_entry = ttk.Entry(optional_frame)
        self.phone_entry.grid(row=1, column=1, sticky="ew")
        ttk.Label(
            optional_frame,
            text="Address:").grid(
            row=2,
            column=0,
            sticky="w",
            padx=(
                0,
                10),
            pady=2)
        self.address_entry = ttk.Entry(optional_frame)
        self.address_entry.grid(row=2, column=1, sticky="ew")

        ttk.Separator(
            self.setup_frame).grid(
            row=1,
            column=0,
            columnspan=2,
            sticky="ew",
            pady=15)
        ttk.Button(
            self.setup_frame,
            text="Generate and Save Identity",
            command=self.create_and_save_identity,
            bootstyle=SUCCESS).grid(
            row=2,
            column=0,
            columnspan=2,
            sticky="ew",
            ipady=5)

        self.manage_frame = ttk.LabelFrame(
            parent_frame, text="🔑 Your Active Issuer Identity", padding="15")
        self.manage_frame.grid_columnconfigure(0, weight=0)
        self.manage_frame.grid_columnconfigure(1, weight=1)
        self.manage_frame.grid_rowconfigure(0, weight=0)
        self.issuer_qr_display_label = ttk.Label(self.manage_frame)
        self.issuer_qr_display_label.grid(row=0, column=0, sticky="n", padx=(0, 20))
        right_panel_manage = ttk.Frame(self.manage_frame)
        right_panel_manage.grid(row=0, column=1, sticky="new")
        info_box = ttk.Frame(right_panel_manage)
        info_box.pack(fill="x", pady=(0, 15), anchor="n")
        info_box.grid_columnconfigure(1, weight=1)
        ttk.Label(info_box, text="Issuer ID:").grid(row=0, column=0, sticky="w", pady=2)
        self.id_label = ttk.Label(info_box, text="N/A", font="-weight bold")
        self.id_label.grid(row=0, column=1, sticky="w", padx=5, pady=2)
        ttk.Label(info_box, text="Name:").grid(row=1, column=0, sticky="w", pady=2)
        self.name_label = ttk.Label(info_box, text="N/A", font="-weight bold")
        self.name_label.grid(row=1, column=1, sticky="w", padx=5, pady=2)
        ttk.Label(info_box, text="Info URL:").grid(row=2, column=0, sticky="nw", pady=2)
        self.url_label = ttk.Label(info_box, text="N/A", wraplength=450)
        self.url_label.grid(row=2, column=1, sticky="w", padx=5, pady=2)
        contact_box = ttk.LabelFrame(
            right_panel_manage,
            text="Public Contact Info (from server)",
            padding=10)
        contact_box.pack(fill="x", pady=(0, 15), anchor="n")
        contact_box.grid_columnconfigure(1, weight=1)
        ttk.Label(contact_box, text="Email:").grid(row=0, column=0, sticky="w", pady=2)
        self.email_label_val = ttk.Label(contact_box, text="N/A", wraplength=400)
        self.email_label_val.grid(row=0, column=1, sticky="w", padx=5, pady=2)
        ttk.Label(contact_box, text="Phone:").grid(row=1, column=0, sticky="w", pady=2)
        self.phone_label_val = ttk.Label(contact_box, text="N/A", wraplength=400)
        self.phone_label_val.grid(row=1, column=1, sticky="w", padx=5, pady=2)
        ttk.Label(
            contact_box,
            text="Address:").grid(
            row=2,
            column=0,
            sticky="nw",
            pady=2)
        self.address_label_val = ttk.Label(contact_box, text="N/A", wraplength=400)
        self.address_label_val.grid(row=2, column=1, sticky="w", padx=5, pady=2)
        btn_frame = ttk.Frame(right_panel_manage)
        btn_frame.pack(fill="x", pady=(5, 0), anchor="n")
        btn_frame.grid_columnconfigure(list(range(4)), weight=1)
        ttk.Button(
            btn_frame,
            text="📤 Export QR",
            command=self.export_issuer_qr,
            bootstyle=OUTLINE).grid(
            row=0,
            column=0,
            sticky="ew",
            padx=(
                0,
                2))
        ttk.Button(
            btn_frame,
            text="✉️ Email QR",
            command=self.email_issuer_qr,
            bootstyle=OUTLINE).grid(
            row=0,
            column=1,
            sticky="ew",
            padx=(
                2,
                2))
        ttk.Button(
            btn_frame,
            text="🖨️ Print QR",
            command=self.print_issuer_qr,
            bootstyle=OUTLINE).grid(
            row=0,
            column=2,
            sticky="ew",
            padx=(
                2,
                2))
        ttk.Button(
            btn_frame,
            text="🗑️ Delete ID-entity",
            command=self.delete_identity,
            bootstyle=DANGER).grid(
            row=0,
            column=3,
            sticky="ew",
            padx=(
                2,
                0))

    def create_signer_tab(self, parent_frame):
        self.encoder_frame = ttk.LabelFrame(
            parent_frame, text="🖊️ Sign a New Certificate", padding="10")
        self.encoder_frame.pack(fill="both", expand=True)

        self.encoder_frame.grid_columnconfigure(
            (0, 1), weight=1, uniform="signer_columns")
        self.encoder_frame.grid_rowconfigure(2, weight=1)

        input_area_frame = ttk.Frame(self.encoder_frame)
        input_area_frame.grid(row=0, column=0, columnspan=2, sticky="ew")
        input_area_frame.grid_columnconfigure(1, weight=1)

        summary_frame = ttk.Frame(input_area_frame)
        summary_frame.grid(row=0, column=1, sticky="nsew")
        summary_frame.grid_columnconfigure(0, weight=1)
        summary_frame.grid_rowconfigure(1, weight=1)

        ttk.Label(
            summary_frame,
            text="Certificate Summary:").grid(
            row=0,
            column=0,
            sticky="w")
        self.message_text = ttk.Text(summary_frame, height=3, wrap="word")
        self.message_text.grid(row=1, column=0, sticky="nsew")

        self.browse_button = ttk.Button(
            input_area_frame,
            text="📄 Select Image...",
            command=self.browse_and_set_proof_file,
            bootstyle="primary-outline")
        self.browse_button.grid(row=0, column=0, sticky="ns", padx=(0, 10))

        status_line_frame = ttk.Frame(input_area_frame)
        status_line_frame.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(5, 0))

        self.char_count_label = ttk.Label(
            status_line_frame,
            text=f"0 / {MAX_SUMMARY_CHARS}",
            bootstyle="secondary")
        self.char_count_label.pack(side="right")

        self.doc_id_helper_label = ttk.Label(
            status_line_frame,
            text="No Image selected for fingerprinting.",
            bootstyle="secondary",
            anchor="w")
        self.doc_id_helper_label.pack(side="left", fill="x", expand=True)

        self.message_text.bind("<KeyRelease>", self._validate_summary_length)
        self._validate_summary_length()

        self.generate_qr_button = ttk.Button(
            self.encoder_frame,
            text="✨ Fingerprint, Sign & Save",
            command=self.generate_document_qr,
            bootstyle=PRIMARY,
            state="disabled")
        self.generate_qr_button.grid(
            row=1, column=0, sticky="ew", ipady=5, padx=(
                0, 5), pady=10)

        self.upload_button = ttk.Button(
            self.encoder_frame,
            text="🚀 Upload Fingerprinted Image",
            command=self.upload_proof_file_threaded,
            state="disabled")
        self.upload_button.grid(
            row=1,
            column=1,
            sticky="ew",
            ipady=5,
            padx=(
                5,
                0),
            pady=10)

        proof_lf = ttk.LabelFrame(self.encoder_frame, text="Fingerprinted Image Proof")
        proof_lf.grid(row=2, column=0, sticky="nsew", padx=(0, 5))
        proof_lf.grid_columnconfigure(0, weight=1)
        proof_lf.grid_rowconfigure(1, weight=1)

        self.auto_upload_indicator_label = ttk.Label(
            proof_lf, text="", bootstyle="success", anchor="e")
        self.auto_upload_indicator_label.grid(row=0, column=0, sticky="ew", padx=5)

        self.proof_image_display_label = ttk.Label(
            proof_lf, relief="flat", anchor="center")
        self.proof_image_display_label.grid(
            row=1, column=0, sticky="nsew", padx=5, pady=5)

        qr_lf = ttk.LabelFrame(self.encoder_frame, text="Generated LegatoKey")
        qr_lf.grid(row=2, column=1, sticky="nsew", padx=(5, 0))

        self.qr_display_label = ttk.Label(qr_lf, relief="flat", anchor="center")
        self.qr_display_label.pack(fill="both", expand=True, padx=5, pady=5)

    def create_batch_signing_tab(self, parent_frame):
        parent_frame.grid_rowconfigure(1, weight=1)
        parent_frame.grid_columnconfigure(0, weight=1)
        control_frame = ttk.Frame(parent_frame)
        control_frame.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        ttk.Button(
            control_frame,
            text="📂 Load Data File...",
            command=self._handle_load_data_file,
            bootstyle=PRIMARY).pack(
            side="left",
            padx=(
                0,
                10))
        self.batch_file_label = ttk.Label(
            control_frame,
            text="No file loaded.",
            bootstyle="secondary")
        self.batch_file_label.pack(side="left", anchor="w")
        coldata = [{"text": "Status", "stretch": False, "width": 150}, {
            "text": "Proof File Path", "stretch": True}, {"text": "Certificate Summary", "stretch": True}]
        self.batch_tree = Tableview(
            parent_frame,
            coldata=coldata,
            paginated=False,
            searchable=False,
            bootstyle=PRIMARY)
        self.batch_tree.grid(row=1, column=0, sticky="nsew")
        self.batch_tree.view.tag_configure("SOURCE_ERROR", background="lightcoral")
        self.batch_tree.view.tag_configure("SUCCESS", background="lightgreen")
        self.batch_tree.view.tag_configure("FAILURE", background="lightcoral")
        self.batch_tree.view.tag_configure("PROCESSING", background="lightyellow")
        action_frame = ttk.Frame(parent_frame)
        action_frame.grid(row=2, column=0, sticky="ew", pady=(10, 0))
        action_frame.grid_columnconfigure(0, weight=1)
        self.process_batch_button = ttk.Button(
            action_frame,
            text="▶️ Process Batch",
            command=self._handle_process_batch,
            state="disabled")
        self.process_batch_button.grid(row=0, column=1, sticky="e")
        self.batch_progress = ttk.Progressbar(action_frame, mode="determinate")
        self.batch_progress.grid(row=0, column=0, sticky="ew", padx=(0, 10))

    def create_audit_viewer_tab(self, parent_frame):
        parent_frame.grid_rowconfigure(1, weight=1)
        parent_frame.grid_columnconfigure(0, weight=1)
        control_frame = ttk.Frame(parent_frame)
        control_frame.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        ttk.Button(
            control_frame,
            text="🔄 Refresh Audit Trail",
            command=self._handle_refresh_audit,
            bootstyle=PRIMARY).pack(
            side="left",
            padx=(
                0,
                10))
        self.audit_status_label = ttk.Label(
            control_frame,
            text="Load an identity to view the audit trail.",
            bootstyle="secondary")
        self.audit_status_label.pack(side="left", anchor="w")
        coldata = [
            {
                "text": "Chain ✓", "stretch": False, "width": 80}, {
                "text": "Timestamp (UTC)", "stretch": False, "width": 200}, {
                "text": "Event Type", "stretch": False, "width": 150}, {
                    "text": "Details", "stretch": True}]
        self.audit_tree = Tableview(
            parent_frame,
            coldata=coldata,
            paginated=True,
            pagesize=50,
            searchable=True,
            bootstyle=INFO)
        self.audit_tree.grid(row=1, column=0, sticky="nsew")
        self.audit_tree.view.tag_configure("VALID", background="lightgreen")
        self.audit_tree.view.tag_configure("INVALID_SIG", background="lightcoral")
        self.audit_tree.view.tag_configure("BROKEN_CHAIN", background="orange")

    def create_settings_and_uploads_tab(self, parent_frame):
        parent_frame.grid_rowconfigure(1, weight=0)
        parent_frame.grid_columnconfigure(0, weight=1)
        top_columns_container = ttk.Frame(parent_frame)
        top_columns_container.grid(row=0, column=0, sticky="new")
        top_columns_container.grid_columnconfigure(
            (0, 1), weight=1, uniform="settings_group")

        connection_frame = ttk.LabelFrame(
            top_columns_container,
            text="🚀 Connection & Uploads",
            padding=15)
        connection_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 5), pady=(0, 10))
        connection_frame.grid_columnconfigure(1, weight=1)
        ttk.Label(connection_frame,
                  text="Step 1: Enter FTP Server Credentials",
                  font="-weight bold").grid(row=0,
                                            column=0,
                                            columnspan=3,
                                            sticky="w",
                                            pady=(0,
                                                  10))
        ttk.Label(
            connection_frame,
            text="Username:").grid(
            row=1,
            column=0,
            sticky="w",
            padx=(
                0,
                10),
            pady=4)
        self.ftp_user_entry = ttk.Entry(
            connection_frame, textvariable=self.ftp_user_var)
        self.ftp_user_entry.grid(
            row=1,
            column=1,
            columnspan=2,
            sticky="ew",
            pady=4,
            ipady=2)
        ttk.Label(
            connection_frame,
            text="Password:").grid(
            row=2,
            column=0,
            sticky="w",
            padx=(
                0,
                10),
            pady=4)
        self.ftp_pass_entry = ttk.Entry(
            connection_frame,
            textvariable=self.ftp_pass_var,
            show="*")
        self.ftp_pass_entry.grid(row=2, column=1, sticky="ew", pady=4, ipady=2)
        ttk.Checkbutton(
            connection_frame,
            text="Show",
            variable=self.show_pass_var,
            command=self.toggle_password_visibility,
            bootstyle="toolbutton").grid(
            row=2,
            column=2,
            sticky="w",
            padx=5)
        ttk.Separator(connection_frame).grid(
            row=3, column=0, columnspan=3, sticky="ew", pady=15)
        ttk.Label(connection_frame,
                  text="Step 2: Set FTP Address & Path",
                  font="-weight bold").grid(row=4,
                                            column=0,
                                            columnspan=3,
                                            sticky="w",
                                            pady=(0,
                                                  10))
        ttk.Label(
            connection_frame,
            text="FTP Host:").grid(
            row=5,
            column=0,
            sticky="w",
            padx=(
                0,
                10),
            pady=4)
        self.ftp_host_entry = ttk.Entry(
            connection_frame, textvariable=self.ftp_host_var)
        self.ftp_host_entry.grid(
            row=5,
            column=1,
            columnspan=2,
            sticky="ew",
            pady=4,
            ipady=2)
        ttk.Label(
            connection_frame,
            text="(Pre-filled from your URL. Please verify.)",
            bootstyle="secondary").grid(
            row=6,
            column=1,
            columnspan=2,
            sticky="w",
            padx=5)
        ttk.Label(
            connection_frame, text="Web Root Path:").grid(
            row=7, column=0, sticky="w", padx=(
                0, 10), pady=(
                15, 4))
        path_entry_frame = ttk.Frame(connection_frame)
        path_entry_frame.grid(row=7, column=1, columnspan=2, sticky="ew", pady=(15, 4))
        self.ftp_path_entry = ttk.Entry(
            path_entry_frame, textvariable=self.ftp_path_var)
        self.ftp_path_entry.pack(
            side="left",
            fill="x",
            expand=True,
            ipady=2,
            padx=(
                0,
                5))
        self.sense_button = ttk.Button(
            path_entry_frame,
            text="🔎 Auto-Sense",
            command=self.handle_auto_sense_threaded,
            bootstyle="outline-info")
        self.sense_button.pack(side="left")
        ttk.Label(
            connection_frame,
            text="(e.g., /public_html/ or use Auto-Sense)",
            bootstyle="secondary").grid(
            row=8,
            column=1,
            columnspan=2,
            sticky="w",
            padx=5)
        ttk.Separator(connection_frame).grid(
            row=9, column=0, columnspan=3, sticky="ew", pady=15)
        ttk.Label(connection_frame,
                  text="Step 3: Finalize Setup",
                  font="-weight bold").grid(row=10,
                                            column=0,
                                            columnspan=3,
                                            sticky="w",
                                            pady=(0,
                                                  10))
        self.save_and_upload_button = ttk.Button(
            connection_frame,
            text="✔️ Save Settings & Upload Public Files",
            command=self.handle_save_and_upload_threaded,
            bootstyle=PRIMARY,
            state="disabled")
        self.save_and_upload_button.grid(
            row=11, column=0, columnspan=3, sticky="ew", ipady=5)

        right_container = ttk.Frame(top_columns_container)
        right_container.grid(row=0, column=1, sticky="nsew", padx=(5, 0))

        proof_qr_frame = ttk.LabelFrame(
            right_container,
            text="⚙️ Signing & Saving Options",
            padding=15)
        proof_qr_frame.pack(fill="x", expand=False, pady=(0, 10))
        self.auto_upload_check = ttk.Checkbutton(
            proof_qr_frame,
            text="Automatically Upload Figerprinted Images After Signing",
            variable=self.ftp_auto_upload_var,
            bootstyle="success-round-toggle",
            command=self.on_auto_upload_toggle,
            state="disabled")
        self.auto_upload_check.pack(anchor="w", pady=(5, 10))
        self.randomize_proof_name_checkbox = ttk.Checkbutton(
            proof_qr_frame,
            text="Salt Proof File Name",
            variable=self.randomize_proof_name_var,
            bootstyle="round-toggle",
            command=self.save_settings)
        self.randomize_proof_name_checkbox.pack(anchor="w", pady=(5, 10))
        self.make_local_copy_checkbox = ttk.Checkbutton(
            proof_qr_frame,
            text="Save a Local Copy of Signed Proofs",
            variable=self.make_local_copy_var,
            bootstyle="round-toggle",
            command=lambda: (
                self.toggle_proof_path_state(),
                self.save_settings()))
        self.make_local_copy_checkbox.pack(anchor="w", pady=(5, 2))
        self.proof_path_frame = ttk.Frame(proof_qr_frame)
        self.proof_path_frame.pack(fill="x", expand=True, padx=20, pady=(0, 15))
        ttk.Label(self.proof_path_frame, text="Proof Save Location:").pack(anchor="w")
        self.proof_path_entry = ttk.Entry(
            self.proof_path_frame,
            textvariable=self.proof_save_path_var,
            state="disabled")
        self.proof_path_entry.pack(side="left", fill="x", expand=True, padx=(0, 5))
        self.proof_path_browse_btn = ttk.Button(
            self.proof_path_frame,
            text="...",
            state="disabled",
            width=3,
            command=self.browse_for_proof_save_path)
        self.proof_path_browse_btn.pack(side="left")

        ttk.Label(
            proof_qr_frame,
            text="Automatic QR Code Save Location:").pack(
            anchor="w",
            pady=(
                10,
                2))
        qr_path_frame = ttk.Frame(proof_qr_frame)
        qr_path_frame.pack(fill="x", expand=True)
        ttk.Entry(
            qr_path_frame,
            textvariable=self.qr_save_path_var,
            state="readonly").pack(
            side="left",
            fill="x",
            expand=True,
            padx=(
                0,
                5))
        ttk.Button(
            qr_path_frame,
            text="...",
            width=3,
            command=self.browse_for_qr_save_path).pack(
            side="left")

        watermark_frame = ttk.LabelFrame(
            right_container,
            text="🖼️ Watermark Options (Pro Feature)",
            padding=15)
        watermark_frame.pack(fill="x", expand=False, pady=(10, 0))
        is_watermark_licensed = self.license_manager.is_feature_enabled("watermark")
        text_watermark_frame = ttk.Frame(watermark_frame)
        text_watermark_frame.pack(fill="x", pady=(5, 10))
        self.apply_watermark_checkbox = ttk.Checkbutton(
            text_watermark_frame,
            text="Apply Text Watermark:",
            variable=self.apply_watermark_var,
            bootstyle="round-toggle",
            command=lambda: (
                self.toggle_watermark_state(),
                self.save_settings()),
            state="disabled" if not is_watermark_licensed else "normal")
        self.apply_watermark_checkbox.pack(side="left", padx=(0, 10))
        self.watermark_entry = ttk.Entry(
            text_watermark_frame,
            textvariable=self.watermark_text_var,
            width=30)
        self.watermark_entry.pack(side="left", fill="x", expand=True)
        self.watermark_entry.bind("<FocusOut>", lambda e: self.save_settings())
        self.apply_logo_watermark_checkbox = ttk.Checkbutton(
            watermark_frame,
            text="Apply Your Logo as Watermark",
            variable=self.apply_logo_watermark_var,
            bootstyle="round-toggle",
            command=self.save_settings,
            state="disabled" if not is_watermark_licensed else "normal")
        self.apply_logo_watermark_checkbox.pack(anchor="w", pady=5)
        if not is_watermark_licensed:
            ttk.Label(
                watermark_frame,
                text="Purchase a Pro license to enable watermarking.",
                bootstyle="info").pack(
                anchor="w",
                pady=(
                    5,
                    0))

        security_frame = ttk.LabelFrame(
            parent_frame,
            text="💎 Advanced Security & Logging",
            padding=15)
        security_frame.grid(row=1, column=0, sticky="ew", pady=(10, 0))
        security_frame.grid_columnconfigure((0, 1), weight=1, uniform="security_group")
        security_left_col = ttk.Frame(security_frame)
        security_left_col.grid(row=0, column=0, sticky="new", padx=(0, 10))
        self.pro_security_checkbox = ttk.Checkbutton(
            security_left_col,
            text="Enable Hardened Security (OS Keychain)",
            variable=self.hardened_security_var,
            bootstyle="primary-round-toggle",
            state="disabled",
            command=self.save_issuer_identity)
        self.pro_security_checkbox.pack(anchor="w", fill="x", pady=(5, 5))
        ttk.Label(
            security_left_col,
            text="RECOMMENDED. Moves private key and FTP password to your OS's secure keychain.",
            wraplength=400,
            bootstyle="secondary").pack(
            anchor="w")
        security_right_col = ttk.Frame(security_frame)
        security_right_col.grid(row=0, column=1, sticky="new", padx=(10, 0))
        is_audit_licensed = self.license_manager.is_feature_enabled("audit")
        self.enable_audit_trail_checkbox = ttk.Checkbutton(
            security_right_col,
            text="Enable Audit Trail (Pro Feature)",
            variable=self.enable_audit_trail_var,
            bootstyle="info-round-toggle",
            state="disabled" if not is_audit_licensed else "normal",
            command=self.save_settings)
        self.enable_audit_trail_checkbox.pack(anchor="w", fill="x", pady=(5, 5))
        ttk.Label(
            security_right_col,
            text="Creates a cryptographically signed log of all signing and upload events.",
            wraplength=400,
            bootstyle="secondary").pack(
            anchor="w")
        if not is_audit_licensed:
            ttk.Label(
                security_right_col,
                text="Purchase a Pro license to enable this.",
                bootstyle="info").pack(
                anchor="w",
                pady=(
                    5,
                    0))

        self._update_ftp_dependent_widgets_state()

    def create_guide_tab(self, parent_frame):
        """Creates the new 'Guide' tab with workflow instructions."""

        import textwrap

        parent_frame.grid_columnconfigure(0, weight=1)
        parent_frame.grid_rowconfigure(0, weight=1)

        guide_text = ScrolledText(
            parent_frame,
            padding=(
                20,
                20,
                0,
                20),
            hbar=False,
            autohide=True,
            wrap='word')
        guide_text.pack(fill="both", expand=True)

        inner_text_widget = guide_text.text

        inner_text_widget.tag_configure("h1", font="-size 14 -weight bold", spacing3=15)
        inner_text_widget.tag_configure(
            "h2", font="-size 11 -weight bold", spacing1=20, spacing3=5)
        inner_text_widget.tag_configure(
            "p",
            font="-size 10",
            lmargin1=10,
            lmargin2=10,
            spacing3=10)

        guide_content = [
            ("Day-to-Day Legato Key Workflow\n", "h1"),
            (
                """
                    Once you've created your legacy document (certificate, valuation letter, photos, etc.), follow these steps:
                    """, "p"
            ),
            ("Step 1: Select your image 'proof'\n", "h2"),
            (
                """
                    Choose your supporting image (photo of the instrument, a scan of the certificate letter), it's fingerprinted will be linked to the LegatoKey.
                    """, "p"
            ),
            ("Step 2: Write a short summary of your document\n", "h2"),
            (
                """
                    For example:
                    -"We [Your Name] certify that the violin examined and reproduced on our certificate and its digital counterpart is, in our opinion,
                    an instrument by [Name of the Maker], authentic in all its major parts and  measuring 35.5 cm."
                    -"Valuation issued to Count Ignazio Alessandro Cozio di Salabue etc..."
                    This summary will be securely encrypted and embedded in the LegatoKey and cannot be changed.
                    """, "p"
            ),
            ("Step 3: Click 'Fingerprint, Sign & Save'\n", "h2"),
            (
                """
                    This creates your secure LegatoKey. If 'Automatic Upload' is enabled in  Settings,
                    the file will upload to your web server automatically. If not, click the Upload button to send it manually.
                    """, "p"
            ),
            ("Step 4: Print the LegatoKey\n", "h2"),
            (
                """
                    You can now print the generated LegatoKey (QR code) onto a label envelope or directly onto the document.
                    """, "p"
            )
        ]

        for text, tag in guide_content:

            dedented_text = textwrap.dedent(text).strip()

            lines = dedented_text.splitlines()

            for i, line in enumerate(lines):

                rejoined_line = " ".join(line.split())

                inner_text_widget.insert("end", rejoined_line, tag)

                if i < len(lines) - 1:
                    inner_text_widget.insert("end", "\n")

            inner_text_widget.insert("end", "\n")

    def create_backup_and_security_tab(self, parent_frame):
        """Creates the 'Backup & Security' tab with a two-column layout."""

        parent_frame.grid_columnconfigure((0, 1), weight=1, uniform="backup_cols")
        parent_frame.grid_rowconfigure(0, weight=1)

        left_column = ttk.Frame(parent_frame)
        left_column.grid(row=0, column=0, sticky="nsew", padx=(0, 10))

        right_column = ttk.Frame(parent_frame)
        right_column.grid(row=0, column=1, sticky="nsew", padx=(10, 0))

        practices_frame = ttk.LabelFrame(
            left_column, text="🔐 Security Best Practices", padding=15)
        practices_frame.pack(fill="x", pady=(0, 15), anchor='n')

        ttk.Label(practices_frame, text="⚠️ IMPORTANT BACKUP NOTICE",
                  bootstyle="warning", font="-weight bold").pack(anchor="w")

        notice_label = ttk.Label(
            practices_frame,
            text="Your private key file (`abracadabra...key`) and your settings (`opn_czami_settings.json`) are your digital identity. If you lose them, you lose the ability to create new LegatoKeys. You MUST create a secure, offline backup.",
            justify="left")
        notice_label.pack(fill='x', anchor="w", pady=(2, 15))
        practices_frame.bind(
            '<Configure>',
            lambda e: self._update_wraplength(
                e,
                notice_label))

        backup_frame = ttk.LabelFrame(
            practices_frame,
            text="Create Secure Encrypted Backup",
            padding=15)
        backup_frame.pack(fill="x", pady=(10, 20), anchor='n')
        backup_frame.grid_columnconfigure(1, weight=1)

        ttk.Label(
            backup_frame,
            text="Backup Password:").grid(
            row=0,
            column=0,
            sticky="w",
            padx=(
                0,
                10),
            pady=5)
        self.backup_pass_var = ttk.StringVar()
        self.backup_pass_entry = ttk.Entry(
            backup_frame, textvariable=self.backup_pass_var, show="*")
        self.backup_pass_entry.grid(row=0, column=1, sticky="ew", pady=5)
        self.backup_show_pass_var = ttk.BooleanVar(value=False)
        ttk.Checkbutton(
            backup_frame,
            text="Show",
            variable=self.backup_show_pass_var,
            bootstyle="toolbutton",
            command=lambda: self.backup_pass_entry.config(
                show="" if self.backup_show_pass_var.get() else "*")).grid(
            row=0,
            column=2,
            padx=5)
        self.create_backup_button = ttk.Button(
            backup_frame,
            text="📦 Create Secure Backup...",
            command=self.handle_create_backup)
        self.create_backup_button.grid(
            row=1, column=0, columnspan=3, sticky="ew", pady=10)

        if not PYZIPPER_AVAILABLE:
            self.backup_pass_entry.config(state="disabled")
            self.create_backup_button.config(state="disabled")
            ttk.Label(backup_frame,
                      text="Requires 'pyzipper'",
                      bootstyle="danger",
                      font="-size 8").grid(row=2,
                                           column=0,
                                           columnspan=3)

        ttk.Label(practices_frame, text="Essential Security Rules",
                  font="-weight bold").pack(anchor="w", pady=(10, 2))
        ttk.Label(
            practices_frame,
            text="• Guard Your Private Key: Treat it like a master password.\n• Never Share Key Files: Do not email or upload your private key file.\n• Regular Backups: You are responsible for maintaining secure backups.\n• Use Strong Passwords: Protect backup files with strong, unique passwords.",
            justify="left").pack(
            anchor="w",
            pady=2)

        tech_security_frame = ttk.LabelFrame(
            right_column, text="🛡️ Built-in Security Features", padding=15)
        tech_security_frame.pack(fill="x", expand=False, anchor='n')

        security_features = [
            ("Industry-Standard Encryption", "All server communications use robust Transport Layer Security (TLS 1.2+) to protect data in transit."),
            ("Secure Credential Storage", "Your private key and passwords can be stored in the OS Keychain, never in plain text files, when Hardened Security is enabled."),
            ("Modern Cryptography", "Utilizes NIST-approved algorithms, including RSA-2048 for digital signatures and SHA-256 for data integrity."),
            ("Local Key Processing", "Your private key never leaves your computer. All signing operations happen locally."),
            ("Tamper Detection", "Each LegatoKey includes a cryptographic signature that detects any unauthorized changes to its content and proof."),
            ("Audit Trail (Pro)", "When enabled, a blockchain-like audit file is created, logging each key creation. Any attempt to tamper with this evidence is detected and reported.")
        ]

        for i, (title, description) in enumerate(security_features):
            padding_top = 15 if i > 0 else 0
            item_frame = ttk.Frame(tech_security_frame)
            item_frame.pack(fill='x', anchor='w', pady=(padding_top, 0))
            ttk.Label(item_frame, text=title,
                      font="-weight bold").pack(anchor="w", pady=(0, 2))
            desc_label = ttk.Label(item_frame, text=description, justify="left")
            desc_label.pack(fill='x', anchor="w", padx=(10, 0))
            item_frame.bind(
                '<Configure>',
                lambda e,
                w=desc_label: self._update_wraplength(
                    e,
                    w))

    def create_about_tab(self, parent_frame):
        """Creates the 'About' tab with a three-column license/info section."""
        parent_frame.drop_target_register("DND_Files")
        parent_frame.dnd_bind("<<Drop>>", self.handle_license_drop)

        outer_container = ttk.Frame(parent_frame)
        outer_container.pack(fill="both", expand=True, padx=20, pady=20)

        header_frame = ttk.Frame(outer_container)
        header_frame.pack(fill="x", pady=(0, 15), anchor='n')
        ttk.Label(header_frame, text="Op’n-Czami", font="-size 24 -weight bold").pack()
        ttk.Label(
            header_frame,
            text="Legato-Key Certification Authority Dashboard",
            font="-size 12",
            bootstyle="secondary").pack(
            pady=(
                5,
                0))
        ttk.Label(
            header_frame,
            text=f"Version {APP_VERSION}",
            font="-size 10",
            bootstyle="info").pack(
            pady=(
                10,
                0))
        ttk.Separator(outer_container, orient="horizontal").pack(fill="x", pady=15)

        info_frame = ttk.Frame(outer_container)
        info_frame.pack(fill="x", pady=(0, 15), anchor='n')
        info_frame.grid_columnconfigure((0, 1, 2), weight=1, uniform="info_cols")
        info_frame.grid_rowconfigure(0, weight=1)

        description_frame = ttk.LabelFrame(
            info_frame, text="About This Application", padding=15)
        description_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        description_text = ("Op'n Cezami is a professional-grade, open-source signing tool for creating tamper-proof, cryptographically signed digital certificates. Crafted by a luthier expert with a computer science background, every design choice reflects the real-world needs. Part of the Legato Key ecosystem for issuing linked physical + digital certificates that anyone can verify.")

        description_label = ttk.Label(
            description_frame,
            text=description_text,
            justify="left")
        description_label.pack(fill="x")
        description_frame.bind(
            '<Configure>',
            lambda e,
            w=description_label: self._update_wraplength(
                e,
                w))

        license_frame = ttk.LabelFrame(
            info_frame, text="Our Open Core License", padding=15)
        license_frame.grid(row=0, column=1, sticky="nsew", padx=(5, 5))
        license_text = ("The core application is free and open-source (licensed under the LGPL), including for commercial use. However, certain advanced features require a Professional license. This hybrid model allows us to provide a powerful free tool while maintaining a sustainable project.")

        open_source_license_label = ttk.Label(
            license_frame, text=license_text, justify="left")
        open_source_license_label.pack(fill="x")
        license_frame.bind(
            '<Configure>',
            lambda e,
            w=open_source_license_label: self._update_wraplength(
                e,
                w))

        drop_zone_frame = ttk.LabelFrame(
            info_frame, text="✨ Professional License Status", padding=15)
        drop_zone_frame.grid(row=0, column=2, sticky="nsew", padx=(10, 0))

        self.drop_zone_label = ttk.Label(
            drop_zone_frame, font="-size 11", justify="center", anchor="center"
        )
        self.drop_zone_label.pack(fill="both", expand=True, pady=10)
        self.update_pro_license_status_display()
        drop_zone_frame.bind(
            '<Configure>',
            lambda e,
            w=self.drop_zone_label: self._update_wraplength(
                e,
                w))

        support_frame = ttk.LabelFrame(
            outer_container, text="Support & Contact", padding=15)
        support_frame.pack(fill="x", pady=(0, 15), anchor='n')
        support_text = (
            "For technical support, feature requests, or security inquiries, please contact legato@ruederome.com")
        support_label = ttk.Label(
            support_frame,
            text=support_text,
            justify="left",
            wraplength=850)
        support_label.pack(fill="x")

        tech_info_frame = ttk.LabelFrame(
            outer_container, text="Technical Information", padding=15)
        tech_info_frame.pack(fill="x", pady=(0, 15), anchor='n')

        ttk.Label(
            tech_info_frame,
            text="Platform Support: Windows 10+, macOS 10.14+, Linux (Ubuntu 18.04+) | Image File Formats: JPEG, PNG | Batch File Formats: CSV, XLSX",
            justify="left",
            bootstyle="secondary",
        ).pack(
            anchor="w")

        footer_frame = ttk.Frame(outer_container)
        footer_frame.pack(fill="x", pady=(25, 0), side="bottom")
        footer_label = ttk.Label(
            footer_frame,
            text="© 2025 Frédéric Levi Mazloum. All rights reserved.",
            font="-size 8",
            bootstyle="secondary")
        footer_label.pack()


if __name__ == "__main__":

    if sys.platform == "win32":
        import ctypes
        from ctypes import windll
        try:
            windll.shcore.SetProcessDpiAwareness(2)
        except (AttributeError, OSError):
            try:
                windll.user32.SetProcessDPIAware()
            except Exception as e:
                logging.error(f"Could not set DPI awareness: {e}")
        myappid = "com.mazloumlevif.opnczami.final.v3"
        windll.shell32.SetCurrentProcessExplicitAppUserModelID(myappid)

    from tkinterdnd2 import DND_FILES, TkinterDnD

    class DndTtkWindow(ttk.Window, TkinterDnD.DnDWrapper):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.TkdndVersion = TkinterDnD._require(self)

    logging.info("================ Application Starting ================")
    root = DndTtkWindow(themename="litera")
    style = ttk.Style()
    app = IssuerApp(root)
    if sys.platform == "win32":
        icon_path = resource_path("icon.ico")

        if icon_path.exists():
            root.update_idletasks()
            hwnd = windll.user32.GetParent(root.winfo_id())
            ICON_SMALL, ICON_BIG, WM_SETICON, LR_LOADFROMFILE = 0, 1, 0x0080, 0x0010

            h_icon_small = windll.user32.LoadImageW(
                None, str(icon_path), 1, 16, 16, LR_LOADFROMFILE)
            if h_icon_small:
                windll.user32.SendMessageW(hwnd, WM_SETICON, ICON_SMALL, h_icon_small)

            h_icon_big = windll.user32.LoadImageW(
                None, str(icon_path), 1, 32, 32, LR_LOADFROMFILE)
            if h_icon_big:
                windll.user32.SendMessageW(hwnd, WM_SETICON, ICON_BIG, h_icon_big)
    root.mainloop()

    logging.info("================ Application Closed ================\n")
