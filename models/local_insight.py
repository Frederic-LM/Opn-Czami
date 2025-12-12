# models/local_insight.py
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
LocalInsight - Analytics based on local database (InsightsDB).

Responsibility: Load and display certificate analytics where the local database
is the source of truth. This is available to all users (free and pro).

This handler loads cached certificate data from the local InsightsDB and
notifies the UI with the results. It does NOT fetch data from FTP servers.

Features (all FREE):
- Load local certificates from InsightsDB
- Display certificate table
- Show "Local: X certificates, Y scans" message

Pro-only features are in OnlineInsights (formerly AnalyticsHandler).
"""

import logging
import threading


class LocalInsight:
    """
    Handles analytics based on local database (InsightsDB).

    Local database is the source of truth for:
    - Certificate list and status
    - Scan counts (from local tracking)
    - Certificate metadata

    This is available to ALL users (free and pro).
    """

    def __init__(self, logic_instance):
        """
        Initialize LocalInsight.

        Args:
            logic_instance: Reference to OpnCzamiLogic
        """
        self.logic = logic_instance
        self._analytics_lock = threading.Lock()
        self._analytics_ready = False
        self._current_cert_stats = []

    def _get_pro_tabs(self):
        """Helper to get ProFeatureTabs instance for UI callbacks."""
        if hasattr(self.logic.ui_callback, 'tabs') and isinstance(self.logic.ui_callback.tabs, dict):
            return self.logic.ui_callback.tabs.get("pro")
        return None

    def load_cached_analytics(self):
        """
        Load certificate analytics from local database.

        This is the FREE dashboard functionality - loads data from InsightsDB.
        Called when user opens the Dashboard tab or refreshes it.

        Available to: All users (free and pro)
        """
        try:
            # Use InsightsDB from logic layer (already initialized per issuer)
            if not self.logic.insights_db:
                logging.debug("[LOCAL_INSIGHT] InsightsDB not initialized, skipping cache load")
                return

            # Query database for cached certificate stats
            cert_stats = self.logic.insights_db.get_certificate_stats()

            # Always build and display, even if empty
            row_data = self._build_table_rows_from_cert_stats(cert_stats) if cert_stats else []

            # Store cert_stats for later access (thread-safe)
            with self._analytics_lock:
                self._current_cert_stats = cert_stats if cert_stats else []
                self._analytics_ready = True

            db_stats = self.logic.insights_db.get_database_statistics()
            # Count only non-deleted certificates (local = total - deleted)
            total_certs = db_stats.get('total_certificates', 0)
            deleted = db_stats.get('deleted', 0)
            num_certs = total_certs - deleted
            total_scans = db_stats.get('total_scans', 0)

            # Always notify UI, even if empty
            msg = f"Local: {num_certs} certificate(s), {total_scans} scan(s)" if num_certs > 0 else "No certificates yet. Create a new identity or sign a document."
            logging.debug(f"[LOCAL_INSIGHT] Loaded {num_certs} certificates, {total_scans} scans")

            # Call callback on ProFeatureTabs instance (stored in app.tabs["pro"])
            pro_tabs = self._get_pro_tabs()
            if pro_tabs:
                pro_tabs.on_dashboard_refresh_complete(
                    row_data,
                    msg,
                    "info"
                )
                logging.info("[LOCAL_INSIGHT] UI callback completed")
            else:
                logging.error(f"[LOCAL_INSIGHT] Failed to get pro_tabs reference for callback")

        except Exception as e:
            logging.error(f"[LOCAL_INSIGHT] Failed to load cached analytics: {e}", exc_info=True)

    def _build_table_rows_from_cert_stats(self, cert_stats):
        """Convert cert_stats from InsightsDB into row data for table display"""
        row_data = []
        for cert in cert_stats:
            # Convert from InsightsDB schema:
            # filename, upload_status, date_created, date_uploaded, total_scans, last_scan, top_city, top_country
            # Table columns: Certificate, Status, Signed On, Upload On, Scans, City

            # Remove .lky extension from filename for cleaner display
            filename = cert['filename']
            if filename.endswith('.lky'):
                filename = filename[:-4]

            # Format dates (remove time part if present, keep only date)
            signed_on = cert.get('date_created', '—') or '—'
            if signed_on != '—':
                # Handle both 'T' separator (ISO format) and space separator
                signed_on = signed_on.split('T')[0] if 'T' in signed_on else signed_on.split(' ')[0]

            upload_on = cert.get('date_uploaded', '—') or '—'
            if upload_on != '—':
                # Handle both 'T' separator (ISO format) and space separator
                upload_on = upload_on.split('T')[0] if 'T' in upload_on else upload_on.split(' ')[0]

            row_data.append([
                filename,
                cert['upload_status'] or '—',
                signed_on,
                upload_on,
                str(cert['total_scans']),
                cert.get('top_city', 'N/A') or 'N/A'
            ])
        # Sort by scan count (descending) - scans is now at index 4
        try:
            row_data.sort(key=lambda x: int(x[4]), reverse=True)
        except (ValueError, IndexError):
            pass
        return row_data
