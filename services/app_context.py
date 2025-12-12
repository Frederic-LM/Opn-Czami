# services/app_context.py
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
AppContext - Dependency injection container for application services.

Service Dependencies:
- Low-level managers (SettingsManager, SecureStorage, etc.)
  These manage system resources and configuration
- High-level services (SigningService, CertificateService, etc.)

The AppContext is created once in main.py and passed to OpnCzamiLogic,
which uses it to delegate business logic to appropriate services.
"""

import logging
from pathlib import Path
from typing import TYPE_CHECKING

# Import all managers
from models.settings_manager import SettingsManager
from models.secure_storage import SecureStorage
from models.cryptography_service import CryptographyService
from models.ftp_manager import FTPManager
from models.image_processor import ImageProcessor
from models.license_manager import LicenseManager
from models.identity_manager import IdentityManager
from models.config import (
    ISSUER_DB_FILE,
    KEYRING_SERVICE_NAME,
    APP_DATA_DIR,
    SCRIPT_DIR,
)
from models.utils import resource_path

# Import all services
from services.signing_service import SigningService
from services.certificate_service import CertificateService
from services.desktop_service import DesktopService
from services.backup_service import BackupService
from services.verification_service import SystemVerificationService
from services.deployment_service import ServerDeploymentService
from services.identity_service import IdentityService
from services.path_manager import PathManager
from services.event_bus import EventBus

if TYPE_CHECKING:
    from models.app_state import AppState
    from ui.app import OpnCzamiApp


class AppContext:
    """
    Dependency injection container for all application services and managers.

    Creates all stateless services and managers once during startup and
    provides them to the controller and other components that need them.

    Usage:
        app_state = AppState()
        app_context = AppContext(app_state, app_ui)
        # Now use: app_context.signing_service, app_context.certificate_service, etc.

    """

    def __init__(self, app_state: "AppState", ui_callback: "OpnCzamiApp"):
        """
        Initialize the application context with all services and managers.

        Args:
            app_state: Central mutable state container
            ui_callback: UI callback interface for sending updates to the UI
        """
        self.app_state = app_state
        self.ui_callback = ui_callback
        self.logger = logging.getLogger(__name__)

        self.logger.info("[CONTEXT] Initializing application context")

        # ====================================================================
        # LAYER 0: Event Bus (Core Infrastructure)
        # Central publish/subscribe mechanism for decoupling components

        self.event_bus = EventBus()
        """Event bus for decoupled communication between components"""

        # ====================================================================
        # LAYER 1: Low-Level Managers
        # These manage system resources, configuration, and basic operations

        self.logger.debug("[CONTEXT] Creating low-level managers")

        self.path_manager = PathManager()
        """Manager for centralized path management (data, assets, resources)"""

        self.settings_manager = SettingsManager(ISSUER_DB_FILE)
        """Manager for loading/saving application settings"""

        self.secure_storage = SecureStorage(KEYRING_SERVICE_NAME, APP_DATA_DIR)
        """Manager for secure storage of secrets (keys, passwords)"""

        self.cryptography_service = CryptographyService()
        """Utility service for cryptographic operations (signing, hashing, verification)"""

        self.ftp_manager = FTPManager()
        """Manager for FTP operations (upload, download, delete)"""

        self.image_processor = ImageProcessor(resource_path("checkmark.png"))
        """Processor for image manipulation (watermarking, QR generation)"""

        self.license_manager = LicenseManager(SCRIPT_DIR, APP_DATA_DIR)
        """Manager for license validation and feature flags"""

        self.identity_manager = IdentityManager(self.secure_storage, self.settings_manager)
        """Manager for issuer identity creation and management"""

        # ====================================================================
        # LAYER 2: High-Level Services
        
        self.logger.debug("[CONTEXT] Creating high-level services")

        self.signing_service = SigningService(
            crypto_manager=self.secure_storage,
            cryptography_service=self.cryptography_service,
            image_processor=self.image_processor,
            license_manager=self.license_manager,
        )
        """Service for document signing workflow"""

        self.certificate_service = CertificateService(
            ftp_manager=self.ftp_manager,
            ui_callback=ui_callback,
        )
        """Service for certificate lifecycle management (upload, remove, delete)"""

        self.desktop_service = DesktopService()
        """Service for OS-level operations (print, email, open files/URLs)"""

        self.backup_service = BackupService(app_context=self)
        """Service for secure backup creation and restoration"""

        self.verification_service = SystemVerificationService(app_context=self)
        """Service for system status verification and server compatibility checks"""

        self.deployment_service = ServerDeploymentService(app_context=self)
        """Service for server deployment and configuration"""

        self.identity_service = IdentityService(app_context=self)
        """Service for identity lifecycle management"""

        # ====================================================================
        # LAYER 3: Issuer-Dependent Services (Initialized Later)
        # These are initialized when an issuer is loaded via reinitialize_services_for_issuer()

        self.insights_db = None
        """InsightsDB instance for certificate tracking (initialized when issuer is loaded)"""

        self.pro_handler = None
        """ProFeatures handler for pro-specific functionality (initialized when issuer is loaded)"""

        self.logger.info("[CONTEXT] Application context initialized successfully")

    def reinitialize_services_for_issuer(self, insights_db=None, pro_handler=None):
        """
        Reinitialize services that depend on the active issuer.

        This is called after loading a new issuer to connect the services
        with the issuer-specific dependencies (InsightsDB, ProHandler, Config, etc.).

        Note: SigningService is now stateless - it doesn't need updates here.

        Args:
            insights_db: InsightsDB instance for the active issuer
            pro_handler: ProFeatures handler for the active issuer
        """
        self.logger.debug("[CONTEXT] Reinitializing services for active issuer")

        self.certificate_service.insights_db = insights_db
        self.certificate_service.pro_handler = pro_handler  
        self.certificate_service.active_issuer_data = self.app_state.active_issuer_data
        self.certificate_service.config = self.app_state.config

        self.logger.debug("[CONTEXT] Services reinitialized for active issuer")

    def __repr__(self) -> str:
        """String representation for debugging."""
        return (
            f"<AppContext "
            f"services={5} "  # identity, signing, certificate, desktop + crypto
            f"managers={8} "  # All the low-level managers
            f"state={self.app_state}>"
        )
