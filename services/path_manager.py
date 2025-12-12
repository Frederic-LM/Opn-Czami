# services/path_manager.py
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

"""Centralized path management for the application."""

import logging
from pathlib import Path
from typing import Union

from models.config import APP_DATA_DIR, APP_DOCS_DIR, SCRIPT_DIR


class PathManager:
    """Provides all file paths used by the application."""

    def __init__(self):
        """Initialize PathManager."""
        self.logger = logging.getLogger(__name__)

    # =========================================================================
    # APPLICATION DATA PATHS
    # =========================================================================

    @property
    def app_data_dir(self) -> Path:
        """Root application data directory."""
        return Path(APP_DATA_DIR)

    @property
    def logs_dir(self) -> Path:
        """Application logs directory."""
        path = self.app_data_dir / "logs"
        path.mkdir(parents=True, exist_ok=True)
        return path

    @property
    def temp_dir(self) -> Path:
        """Temporary files directory."""
        path = self.app_data_dir / "temp_upload"
        path.mkdir(parents=True, exist_ok=True)
        return path

    @property
    def insights_db_path(self) -> Path:
        """Path to insights database file."""
        return self.app_data_dir / "insights.db"

    # =========================================================================
    # DOCUMENT OUTPUT PATHS
    # =========================================================================

    @property
    def documents_dir(self) -> Path:
        """Root documents directory for exports and backups."""
        return Path(APP_DOCS_DIR)

    @property
    def legato_keys_export_dir(self) -> Path:
        """Directory for exported Legato Keys (.lky files)."""
        path = self.documents_dir / "Legato_Keys"
        path.mkdir(parents=True, exist_ok=True)
        return path

    @property
    def backups_dir(self) -> Path:
        """Directory for identity and key backups."""
        path = self.documents_dir / "Backups"
        path.mkdir(parents=True, exist_ok=True)
        return path

    # =========================================================================
    # ASSET PATHS (Static Resources)
    # =========================================================================

    @property
    def assets_dir(self) -> Path:
        """Assets directory for images and icons."""
        possible_locations = [
            Path(SCRIPT_DIR) / "assets",
            Path(SCRIPT_DIR).parent / "assets",
            Path(__file__).parent.parent / "assets",
        ]

        for location in possible_locations:
            if location.exists():
                return location

        return Path(SCRIPT_DIR) / "assets"

    @property
    def worldmap_image_path(self) -> Path:
        """Path to worldmap.png asset."""
        return self.assets_dir / "worldmap.png"

    @property
    def checkmark_image_path(self) -> Path:
        """Path to checkmark.png asset."""
        return self.assets_dir / "checkmark.png"

    # =========================================================================
    # PRO FEATURES PATHS
    # =========================================================================

    @property
    def pro_features_dir(self) -> Path:
        """Pro features directory."""
        return Path(SCRIPT_DIR) / "pro_features"

    @property
    def geoip_database_path(self) -> Path:
        """
        Path to GeoIP database (GeoLite2-City.mmdb).

        Location depends on platform (satisfies MaxMind licensing):
        - Windows bundled exe: next to exe in dist/
        - macOS bundled .app: OpnCzami.app/Contents/Resources/
        - Development: script root
        """
        import sys

        if sys.platform == "darwin" and getattr(sys, "frozen", False):
            return Path(SCRIPT_DIR) / "GeoLite2-City.mmdb"

        return Path(SCRIPT_DIR).parent / "GeoLite2-City.mmdb"

    @property
    def geojson_resources_dir(self) -> Path:
        """Directory for GeoJSON resources."""
        return self.pro_features_dir / "resources"

    @property
    def countries_geojson_path(self) -> Path:
        """Path to countries.geojson (tries new location first)."""
        new_location = self.geojson_resources_dir / "countries.geojson"
        if new_location.exists():
            return new_location

        return self.pro_features_dir / "countries.geo.json"

    # =========================================================================
    # UTILITY METHODS
    # =========================================================================

    def ensure_directory_exists(self, path: Union[Path, str]) -> Path:
        """Create directory if it doesn't exist."""
        path_obj = Path(path)
        try:
            path_obj.mkdir(parents=True, exist_ok=True)
            return path_obj
        except Exception as e:
            self.logger.error(f"[PATH_MANAGER] Failed to create directory {path}: {e}")
            raise

    def file_exists(self, path: Union[Path, str]) -> bool:
        """Check if a file exists."""
        return Path(path).exists()

    def log_paths(self) -> None:
        """Log all managed paths for debugging."""
        self.logger.debug("[PATH_MANAGER] Application Paths:")
        self.logger.debug(f"  App Data: {self.app_data_dir}")
        self.logger.debug(f"  Logs: {self.logs_dir}")
        self.logger.debug(f"  Temp: {self.temp_dir}")
        self.logger.debug(f"  Documents: {self.documents_dir}")
        self.logger.debug(f"  Legato Keys Export: {self.legato_keys_export_dir}")
        self.logger.debug(f"  Assets: {self.assets_dir}")
        self.logger.debug(f"  Worldmap: {self.worldmap_image_path}")
        self.logger.debug(f"  GeoIP DB: {self.geoip_database_path}")
