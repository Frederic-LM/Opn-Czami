# ftp_manager.py
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

import ftplib
import logging
import posixpath
import time
from functools import wraps
from pathlib import Path
from urllib.parse import urlparse

from models.config import FTP_TIMEOUT_SECONDS, FTP_MAX_RETRIES, FTP_RETRY_DELAY

# For auto sens
COMMON_WEB_ROOTS = ["public_html", "htdocs", "httpdocs", "www", "html"]


def ftp_retry(operation_name: str):
    """
    Nice FTP decorator that 
        - Does NOT retry authentication errors (530) or permission errors (550)
        - Uses exponential backoff: 2s, 4s, 6s between retries
        - Logs warnings on transient failures, errors on permanent failures

    Args:
        operation_name: Human-readable name for logging (e.g., "connection test", "upload")

    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            last_error = None

            for attempt in range(1, FTP_MAX_RETRIES + 1):
                try:
                    return func(*args, **kwargs)

                except ftplib.error_perm as e:
                    error_code = str(e)
                    if "530" in error_code:
                        # Authentication failure - we are done
                        return False, "FTP Login Failed (Error 530): Please check username and password."
                    elif "550" in error_code:
                        # Permission denied - same
                        return False, f"Permission Denied (Error 550): {e}"
                    else:
                        # Other permission errors - also don't retry
                        last_error = f"FTP Permission Error: {e}"
                        logging.error(f"{last_error} during {operation_name}")
                        return False, last_error

                except ftplib.all_errors as e:
                    last_error = f"FTP Error: {e}"
                    logging.warning(f"{last_error} during {operation_name} (attempt {attempt}/{FTP_MAX_RETRIES})")
                    if attempt < FTP_MAX_RETRIES:
                        time.sleep(FTP_RETRY_DELAY * attempt)
                        continue

                except Exception as e:
                    last_error = f"Unexpected error: {e}"
                    logging.error(f"{last_error} during {operation_name} (attempt {attempt}/{FTP_MAX_RETRIES})", exc_info=True)
                    if attempt < FTP_MAX_RETRIES:
                        time.sleep(FTP_RETRY_DELAY * attempt)
                        continue

            # Game over
            return False, f"{operation_name.capitalize()} failed after {FTP_MAX_RETRIES} attempts. Last error: {last_error}"

        return wrapper
    return decorator

class FTPManager:
    """Manager for global FTP/FTPS communications and path calculations"""

    @ftp_retry("connection test")
    def test_connection(self, host: str, user: str, password: str) -> tuple[bool, str]:
        """
        Tests the FTP connection with the provided credentials.
        Returns a tuple (success, message).
        """
        with ftplib.FTP_TLS(host, timeout=FTP_TIMEOUT_SECONDS) as ftp:
            ftp.login(user, password)
            ftp.set_pasv(True)
            ftp.prot_p()
            ftp.quit()
        return True, "Success"

    @ftp_retry("web root auto-detection")
    def find_web_root(self, host: str, user: str, password: str) -> tuple[bool, str]:
        """
        Guess for nontechsavie user the the web root directory of there FTP server.
        """
        with ftplib.FTP_TLS(host, timeout=FTP_TIMEOUT_SECONDS) as ftp:
            ftp.login(user, password)
            ftp.set_pasv(True)
            ftp.prot_p()
            dir_list = ftp.nlst()

            # Uses the list of common web roots defined at the top of the file
            if found_root := next((f"/{root}/" for root in COMMON_WEB_ROOTS if root in dir_list), None):
                return True, found_root
            else:
                return False, "Could not find a common web root. Please enter it manually."

    def calculate_remote_path(self, ftp_root: str, image_base_url: str) -> tuple[bool, str, str]:
        """
        Calculates the full remote path for uploads based on configuration.
        """
        logging.info("FTPManager: Calculating Upload Path")

        if not ftp_root:
            return False, "", "FTP Root path is not set in settings."
        if not image_base_url:
            return False, "", "Image Base URL is not set for the active issuer."
        
        try:
            image_base_url_path = urlparse(image_base_url).path
            full_path = posixpath.join(ftp_root, image_base_url_path.lstrip('/\\'))
            normalized_path = posixpath.normpath(full_path)
            normalized_root = posixpath.normpath(ftp_root)

            if not normalized_path.startswith(normalized_root):
                err_msg = "Path traversal detected: The Image Base URL attempts to go outside the FTP Web Root."
                return False, "", err_msg
            
            logging.info(f"FTPManager: Final remote path is '{normalized_path}'")
            return True, normalized_path, ""

        except Exception as e:
            err_msg = f"Error calculating full remote path: {e}"
            logging.error(err_msg, exc_info=True)
            return False, "", err_msg

    @ftp_retry("file upload")
    def upload_file(self, local_path: Path, remote_dir: str, remote_filename: str, ftp_settings: dict) -> tuple[bool, str]:
        """Uploads a single file. Returns (success_bool, message_str)."""
        host, user, password = ftp_settings.get("host"), ftp_settings.get("user"), ftp_settings.get("password")
        if not all([host, user, password, remote_dir]):
            return False, "FTP settings are incomplete."

        logging.info(f"FTP: Attempting to upload '{local_path.name}' to remote dir '{remote_dir}'")

        with ftplib.FTP_TLS(timeout=FTP_TIMEOUT_SECONDS) as ftp:
            ftp.connect(host)
            ftp.login(user, password)
            ftp.set_pasv(True)
            ftp.prot_p()

            # Navigate to target directory, creating directories as needed
            path_parts = remote_dir.strip('/').split('/')
            current_path = "/"
            for part in path_parts:
                if not part:
                    continue
                current_path = posixpath.join(current_path, part)
                try:
                    ftp.cwd(current_path)
                except ftplib.error_perm:
                    logging.info(f"FTP: Directory '{current_path}' not found, attempting to create.")
                    ftp.mkd(current_path)
                    ftp.cwd(current_path)

            ftp.cwd(remote_dir)  # Ensure we are in the correct final directory
            logging.info(f"FTP: Now in target directory. Uploading '{remote_filename}'...")
            with local_path.open("rb") as f:
                ftp.storbinary(f"STOR {remote_filename}", f)

        success_msg = f"Successfully uploaded {remote_filename} to {remote_dir}."
        logging.info(success_msg)
        return True, success_msg