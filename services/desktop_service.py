# services/desktop_service.py
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

"""
DesktopService - Manages OS-level interactions.

Responsibility: Handle operating system interactions like printing documents,
sending emails, and other desktop operations. Decouples UI components from
OS-level dependencies.

This service provides a clean interface for:
- Printing QR codes and documents
- Sending emails with attachments
- Opening files/URLs in system applications

Dependencies: None (only standard library OS operations)
"""

import logging
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Tuple, Optional


class DesktopService:
    """
    Manages OS-level operations (printing, email, file opening).

    Decouples UI components from system-level dependencies, providing
    a clean interface for desktop operations.
    """

    def __init__(self):
        """Initialize DesktopService."""
        self.logger = logging.getLogger(__name__)

    def print_image(self, image_path: Path) -> Tuple[bool, str]:
        """
        Print an image file.

        Args:
            image_path: Path to the image file to print

        Returns:
            Tuple[success: bool, message: str]
        """
        try:
            if not image_path or not image_path.exists():
                return False, f"Image file not found: {image_path}"

            self.logger.info(f"[DESKTOP] Printing image: {image_path}")

            if sys.platform == "win32":
                # Windows: Use print verb
                import os
                os.startfile(str(image_path), "print")
            elif sys.platform == "darwin":
                # macOS: Use lp command
                subprocess.run(["lp", str(image_path)], check=True)
            else:
                # Linux: Use lp command
                subprocess.run(["lp", str(image_path)], check=True)

            self.logger.info(f"[DESKTOP] Image sent to printer: {image_path}")
            return True, f"Image sent to printer successfully"

        except Exception as e:
            error_msg = f"Failed to print image: {str(e)}"
            self.logger.error(f"[DESKTOP] {error_msg}", exc_info=True)
            return False, error_msg

    def send_email(self, recipient: str, subject: str, body: str,
                   attachment_path: Optional[Path] = None) -> Tuple[bool, str]:
        """
        Send an email with optional attachment.

        Args:
            recipient: Email address of recipient
            subject: Email subject line
            body: Email message body
            attachment_path: Optional path to attachment file

        Returns:
            Tuple[success: bool, message: str]
        """
        try:
            if not recipient or "@" not in recipient:
                return False, "Invalid email address"

            self.logger.info(f"[DESKTOP] Preparing email to: {recipient}")

            # Build mailto URI
            mailto_uri = f"mailto:{recipient}?subject={subject.replace(' ', '%20')}"

            # On Windows, we can't easily attach files via mailto, so provide instructions
            if sys.platform == "win32":
                import webbrowser
                webbrowser.open(mailto_uri)
                msg = f"Email client opened. Please manually attach the file if needed."
            else:
                # On Linux/macOS, try to use mail command
                try:
                    if attachment_path and attachment_path.exists():
                        # Use mail command with attachment
                        subprocess.run(
                            ["mail", "-s", subject, "-a", str(attachment_path), recipient],
                            input=body.encode(),
                            check=True
                        )
                    else:
                        subprocess.run(
                            ["mail", "-s", subject, recipient],
                            input=body.encode(),
                            check=True
                        )
                    msg = f"Email sent to {recipient}"

                except (subprocess.SubprocessError, FileNotFoundError) as e:
                    # Fallback to web browser mailto if 'mail' command missing or fails
                    self.logger.warning(f"[DESKTOP] 'mail' command failed (falling back to browser): {e}")
                    import webbrowser
                    webbrowser.open(mailto_uri)
                    msg = "Email client opened (fallback)"

            self.logger.info(f"[DESKTOP] Email operation completed: {msg}")
            return True, msg

        except Exception as e:
            error_msg = f"Failed to send email: {str(e)}"
            self.logger.error(f"[DESKTOP] {error_msg}", exc_info=True)
            return False, error_msg

    def open_file(self, file_path: Path) -> Tuple[bool, str]:
        """
        Open a file with the system default application.

        Args:
            file_path: Path to the file to open

        Returns:
            Tuple[success: bool, message: str]
        """
        try:
            if not file_path or not file_path.exists():
                return False, f"File not found: {file_path}"

            self.logger.info(f"[DESKTOP] Opening file: {file_path}")

            if sys.platform == "win32":
                import os
                os.startfile(str(file_path))
            elif sys.platform == "darwin":
                subprocess.run(["open", str(file_path)], check=True)
            else:
                subprocess.run(["xdg-open", str(file_path)], check=True)

            self.logger.info(f"[DESKTOP] File opened: {file_path}")
            return True, f"File opened successfully"

        except Exception as e:
            error_msg = f"Failed to open file: {str(e)}"
            self.logger.error(f"[DESKTOP] {error_msg}", exc_info=True)
            return False, error_msg

    def open_url(self, url: str) -> Tuple[bool, str]:
        """
        Open a URL in the system default browser.

        Args:
            url: URL to open

        Returns:
            Tuple[success: bool, message: str]
        """
        try:
            if not url:
                return False, "URL cannot be empty"

            self.logger.info(f"[DESKTOP] Opening URL: {url}")

            import webbrowser
            webbrowser.open(url)

            self.logger.info(f"[DESKTOP] URL opened: {url}")
            return True, f"URL opened in browser"

        except Exception as e:
            error_msg = f"Failed to open URL: {str(e)}"
            self.logger.error(f"[DESKTOP] {error_msg}", exc_info=True)
            return False, error_msg
