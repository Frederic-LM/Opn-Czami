# models/app_state.py
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
AppState - Central mutable state container for the application.

Responsibility: Hold all mutable application state in a single, centralized
dataclass. This makes it easy to understand what state exists, how it changes,
and to pass it through the application without hidden side effects.

The AppState is the single source of truth for:
- Configuration (AppConfig)
- Active issuer information
- Signing state (prepared upload, last payload)
- Generated images (QR codes, status logos)
- UI state (verification status)
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Any, Optional
from PIL import Image


@dataclass
class AppState:
    """
    Central mutable state container for the application.

    All services read and write to this shared state object. This makes:
    - State changes explicit and traceable
    - Testing easier (mock state instead of mocking entire services)
    - Threading safer (single point of state access)
    - UI updates clearer (state change → UI update)

    Services should:
    - Read needed state values in their methods
    - Modify state through the controller, not directly
    - Never hold mutable references to state data
    """

    # --- Identity and Configuration ---
    active_issuer_id: Optional[str] = None
    """Current active issuer ID, or None if no issuer is active"""

    active_issuer_data: Dict[str, Any] = field(default_factory=dict)
    """Full data dict for the active issuer (from database)"""

    all_issuer_data: Dict[str, Any] = field(default_factory=dict)
    """All issuers data from the database"""

    config: Any = None  # AppConfig - type hint avoided to prevent circular imports
    """Current application configuration"""

    # --- System State ---
    system_is_verified: bool = False
    """Whether system compatibility has been verified"""

    # --- Signing Workflow State ---
    prepared_upload_path: Optional[Path] = None
    """Path to prepared image for uploading (signing workflow)"""

    last_signed_payload: Optional[str] = None
    """The last payload that was signed (for audit/verification)"""

    # --- Generated Images (UI Display) ---
    lkey_image_pil: Optional[Image.Image] = None
    """PIL Image of the last generated .lky certificate"""

    qr_image_pil: Optional[Image.Image] = None
    """PIL Image of the last generated QR code"""

    issuer_qr_image_pil: Optional[Image.Image] = None
    """PIL Image of the issuer's QR code"""

    original_status_logo_pil: Optional[Image.Image] = None
    """PIL Image of the original status logo (before watermarking)"""

    # --- Contact Information ---
    active_issuer_contact_info: Dict[str, Any] = field(default_factory=dict)
    """Contact information for the active issuer"""

    # --- Dashboard State ---
    last_compatibility_results: list = field(default_factory=list)
    """Results from last server compatibility check"""

    # --- Helper Methods ---
    @property
    def is_issuer_active(self) -> bool:
        """Check if an issuer is currently active."""
        return self.active_issuer_id is not None

    @property
    def is_signing_prepared(self) -> bool:
        """Check if an image is prepared for signing."""
        return self.prepared_upload_path is not None

    def clear_issuer_state(self):
        """Clear all issuer-specific state (when switching issuers or deleting)."""
        self.active_issuer_id = None
        self.active_issuer_data = {}
        self.active_issuer_contact_info = {}
        self.system_is_verified = False

    def clear_signing_state(self):
        """Clear signing workflow state after signing is complete."""
        self.prepared_upload_path = None
        self.last_signed_payload = None
        self.lkey_image_pil = None
        self.qr_image_pil = None

    def __repr__(self) -> str:
        """String representation for debugging."""
        issuer_str = f"issuer={self.active_issuer_id}" if self.is_issuer_active else "no_issuer"
        signing_str = f"signing_prepared" if self.is_signing_prepared else "no_signing"
        return f"<AppState {issuer_str} {signing_str}>"
