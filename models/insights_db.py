# insights_db.py
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

import sqlite3
import logging
import threading
from pathlib import Path
from datetime import datetime, timezone
from typing import List, Dict, Union

class InsightsDB:
    """
    Manages the new Insights database schema for certificate tracking and analytics.

    Schema:
    - certificates: Master table of all certificates (local + discovered)
    - certificate_scans: Individual scan events from analytics logs
    - sync_state: Tracks sync progress

    All timestamps are in UTC ISO format.
    """

    def __init__(self, db_path: Path):
        """
        Initialize InsightsDB and create schema if needed.

        Args:
            db_path: Path to insights.db file
        """
        self.db_path = db_path
        self.conn = None
        self._write_lock = threading.Lock()  # Protect write operations
        self._initialize_db()

    def _initialize_db(self):
        """Create database and tables if they don't exist."""
        # check_same_thread=False allows background threads to use the connection
        # (safe for read operations, protected by internal SQLite locking for writes)
        self.conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        cursor = self.conn.cursor()

        # Certificates master table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS certificates (
                cert_id TEXT PRIMARY KEY,
                filename TEXT NOT NULL UNIQUE,
                date_created TEXT NOT NULL,           -- UTC ISO format
                date_uploaded TEXT,                   -- UTC ISO format (NULL if PENDING)
                upload_status TEXT NOT NULL,          -- PENDING, ONLINE, DISCOVERED
                total_scans INTEGER DEFAULT 0,
                last_scan TEXT,                       -- UTC ISO format
                top_city TEXT,                        -- Most common city from scans
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Scan events from analytics logs
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS certificate_scans (
                scan_id INTEGER PRIMARY KEY AUTOINCREMENT,
                cert_id TEXT NOT NULL,
                scan_datetime TEXT NOT NULL,          -- UTC ISO format
                ip_anonymized TEXT,                   -- /24 block (e.g., 92.89.145.0)
                country TEXT,
                city TEXT,                            -- City from GeoIP lookup
                FOREIGN KEY (cert_id) REFERENCES certificates(cert_id)
            )
        """)

        # Sync tracking
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS sync_state (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                last_line_processed INTEGER DEFAULT 0,
                last_sync TEXT,                       -- UTC ISO format
                last_sync_status TEXT DEFAULT 'PENDING'
            )
        """)

        # Initialize sync_state if empty
        cursor.execute("SELECT COUNT(*) FROM sync_state")
        if cursor.fetchone()[0] == 0:
            cursor.execute("""
                INSERT INTO sync_state (id, last_sync_status)
                VALUES (1, 'INITIALIZED')
            """)

        # Create indexes for performance
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_cert_status ON certificates(upload_status)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_scan_cert ON certificate_scans(cert_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_scan_datetime ON certificate_scans(scan_datetime)")

        self.conn.commit()
        logging.info(f"InsightsDB initialized at {self.db_path}")

    def _get_utc_now(self) -> str:
        """Get current UTC timestamp in ISO format."""
        return datetime.now(timezone.utc).isoformat()

    # ========================================================================
    # CERTIFICATE OPERATIONS
    # ========================================================================

    def create_certificate(self, filename: str, date_created: str = None) -> str:
        """
        Create a new certificate (PENDING status).

        Args:
            filename: Certificate filename
            date_created: UTC ISO timestamp (uses now if None)

        Returns:
            cert_id (SHA256 hash of filename)
        """
        from models.secure_storage import SecureStorage

        cert_id = SecureStorage.generate_id_from_name(filename)
        if date_created is None:
            date_created = self._get_utc_now()

        # Thread-safe write operation
        with self._write_lock:
            cursor = self.conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO certificates
                (cert_id, filename, date_created, upload_status, created_at)
                VALUES (?, ?, ?, ?, ?)
            """, (cert_id, filename, date_created, 'PENDING', self._get_utc_now()))
            self.conn.commit()

        logging.info(f"[INSIGHTS] Created certificate: {filename} (status: PENDING)")
        return cert_id

    def mark_online(self, filename: str) -> bool:
        """
        Mark certificate as ONLINE (uploaded to server).

        Args:
            filename: Certificate filename

        Returns:
            True if successful
        """
        from models.secure_storage import SecureStorage

        cert_id = SecureStorage.generate_id_from_name(filename)

        # Thread-safe write operation
        with self._write_lock:
            cursor = self.conn.cursor()
            cursor.execute("""
                UPDATE certificates
                SET upload_status = 'ONLINE', date_uploaded = ?
                WHERE cert_id = ?
            """, (self._get_utc_now(), cert_id))

            if cursor.rowcount > 0:
                self.conn.commit()
                logging.info(f"[INSIGHTS] Marked online: {filename}")
                return True
        return False

    def mark_deployed(self, filename: str) -> bool:
        """Deprecated: use mark_online() instead."""
        return self.mark_online(filename)

    def mark_certificate_pending(self, filename: str) -> bool:
        """
        Mark certificate as PENDING (not yet uploaded).

        Used when resetting upload status or preparing for re-upload.

        Args:
            filename: Certificate filename

        Returns:
            True if successful, False otherwise
        """
        from models.secure_storage import SecureStorage

        cert_id = SecureStorage.generate_id_from_name(filename)
        cursor = self.conn.cursor()

        try:
            cursor.execute("""
                UPDATE certificates
                SET upload_status = 'PENDING'
                WHERE cert_id = ?
            """, (cert_id,))

            if cursor.rowcount > 0:
                self.conn.commit()
                logging.info(f"[INSIGHTS] Marked as PENDING: {filename}")
                return True
            else:
                logging.warning(f"[INSIGHTS] Certificate not found for marking PENDING: {filename}")
                return False
        except Exception as e:
            logging.error(f"[INSIGHTS] Error marking certificate pending: {e}", exc_info=True)
            self.conn.rollback()
            return False

    def mark_certificate_deleted(self, filename: str) -> bool:
        """
        Mark certificate as DELETED (removed from server).

        Used when deleting certificates from the server.

        Args:
            filename: Certificate filename

        Returns:
            True if successful, False otherwise
        """
        from models.secure_storage import SecureStorage

        cert_id = SecureStorage.generate_id_from_name(filename)
        cursor = self.conn.cursor()

        try:
            cursor.execute("""
                UPDATE certificates
                SET upload_status = 'DELETED'
                WHERE cert_id = ?
            """, (cert_id,))

            if cursor.rowcount > 0:
                self.conn.commit()
                logging.info(f"[INSIGHTS] Marked as DELETED: {filename}")
                return True
            else:
                logging.warning(f"[INSIGHTS] Certificate not found for marking DELETED: {filename}")
                return False
        except Exception as e:
            logging.error(f"[INSIGHTS] Error marking certificate deleted: {e}", exc_info=True)
            self.conn.rollback()
            return False

    def get_all_certificate_scans(self) -> List[Dict]:
        """
        Retrieve all certificate scan events.

        Returns list of dicts with keys: scan_id, cert_id, scan_datetime,
        ip_anonymized, country, city

        Returns:
            List of scan dictionaries, empty list if none found
        """
        cursor = self.conn.cursor()

        try:
            cursor.execute("""
                SELECT
                    scan_id,
                    cert_id,
                    scan_datetime,
                    ip_anonymized,
                    country,
                    city
                FROM certificate_scans
                ORDER BY scan_datetime DESC
            """)

            rows = cursor.fetchall()
            return [dict(row) for row in rows] if rows else []
        except Exception as e:
            logging.error(f"[INSIGHTS] Error retrieving all certificate scans: {e}", exc_info=True)
            return []

    def get_top_certificates_by_scan_count(self, limit: int = 4) -> List[Dict]:
        """
        Retrieve top certificates by number of scans.

        Used for dashboard to show most-accessed certificates.

        Args:
            limit: Maximum number of certificates to return (default 4)

        Returns:
            List of certificate dicts with keys: filename, scan_count,
            ordered by scan_count descending
        """
        cursor = self.conn.cursor()

        try:
            cursor.execute("""
                SELECT
                    c.filename,
                    COUNT(cs.scan_id) as scan_count
                FROM certificates c
                LEFT JOIN certificate_scans cs ON c.cert_id = cs.cert_id
                GROUP BY c.cert_id, c.filename
                ORDER BY scan_count DESC
                LIMIT ?
            """, (limit,))

            rows = cursor.fetchall()
            return [dict(row) for row in rows] if rows else []
        except Exception as e:
            logging.error(f"[INSIGHTS] Error retrieving top certificates by scan count: {e}", exc_info=True)
            return []

    def get_certificate(self, filename: str) -> Dict:
        """Get certificate details by filename."""
        from models.secure_storage import SecureStorage

        cert_id = SecureStorage.generate_id_from_name(filename)
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM certificates WHERE cert_id = ?", (cert_id,))
        row = cursor.fetchone()
        return dict(row) if row else None

    def certificate_exists(self, filename: str) -> bool:
        """Check if certificate exists in DB."""
        from models.secure_storage import SecureStorage

        cert_id = SecureStorage.generate_id_from_name(filename)
        cursor = self.conn.cursor()
        cursor.execute("SELECT 1 FROM certificates WHERE cert_id = ?", (cert_id,))
        return cursor.fetchone() is not None

    # ========================================================================
    # ANALYTICS IMPORT (Main refactored flow)
    # ========================================================================

    def import_analytics_events(self, analytics_entries: List[Dict]) -> int:
        """
        Import analytics entries from log into the database.

        This keeps the same flow as before:
        - analytics_entries already have: timestamp, ip, certificate_filename, country, ip_anonymized
        - We now insert into the new schema instead of the old one

        Args:
            analytics_entries: List of dicts with keys:
                - timestamp (UTC ISO format)
                - ip (original IP)
                - certificate_filename
                - country (already extracted)
                - ip_anonymized (already anonymized)

        Returns:
            Number of new scan events imported
        """
        from models.secure_storage import SecureStorage

        imported_count = 0
        cursor = self.conn.cursor()

        for entry in analytics_entries:
            cert_name = entry['certificate_filename']
            cert_id = SecureStorage.generate_id_from_name(cert_name)
            timestamp = entry['timestamp']
            ip = entry['ip']
            ip_anonymized = entry['ip_anonymized']
            country = entry.get('country', 'UNKNOWN')
            city = entry.get('city', 'UNKNOWN')

            # logging.info(f"[INSIGHTS] ===== PROCESSING ENTRY =====")  # Commented - verbose per-entry logging
            # logging.info(f"[INSIGHTS] Input: cert_name='{cert_name}' cert_id='{cert_id}'")  # Commented
            # logging.info(f"[INSIGHTS] Input: timestamp='{timestamp}' ip='{ip}' ip_anonymized='{ip_anonymized}'")  # Commented
            # logging.info(f"[INSIGHTS] Input: country='{country}' city='{city}'")  # Commented

            # CHECK 1: Does certificate exist?
            logging.debug(f"[INSIGHTS] CHECK 1: Checking if certificate exists with cert_id='{cert_id}'")
            cursor.execute("SELECT rowid, filename, upload_status FROM certificates WHERE cert_id = ?", (cert_id,))
            existing_cert = cursor.fetchone()

            if existing_cert:
                cert_rowid = existing_cert[0]
                stored_filename = existing_cert[1]
                stored_status = existing_cert[2]
                logging.debug(f"[INSIGHTS] CHECK 1 RESULT: FOUND - rowid={cert_rowid} filename='{stored_filename}' status='{stored_status}'")
            else:
                logging.debug(f"[INSIGHTS] CHECK 1 RESULT: NOT FOUND - Creating new DISCOVERED certificate")
                cursor.execute("""
                    INSERT INTO certificates
                    (cert_id, filename, date_created, upload_status, created_at)
                    VALUES (?, ?, ?, ?, ?)
                """, (
                    cert_id,
                    cert_name,
                    timestamp,
                    'DISCOVERED',
                    self._get_utc_now()
                ))
                logging.debug(f"[INSIGHTS] CHECK 1 ACTION: INSERTED new certificate with cert_id='{cert_id}'")
                existing_cert = (cert_id, cert_name, 'DISCOVERED')

            # Now get the actual rowid for the certificate (either existing or just inserted)
            cursor.execute("SELECT rowid FROM certificates WHERE cert_id = ?", (cert_id,))
            cert_rowid_result = cursor.fetchone()
            cert_rowid = cert_rowid_result[0] if cert_rowid_result else None
            logging.debug(f"[INSIGHTS] Certificate rowid for cert_id='{cert_id}': {cert_rowid}")

            # CHECK 2: Does this exact scan already exist?
            logging.debug(f"[INSIGHTS] CHECK 2: Checking if scan exists with cert_id='{cert_id}' timestamp='{timestamp}' ip_anonymized='{ip_anonymized}'")
            cursor.execute("""
                SELECT rowid FROM certificate_scans
                WHERE cert_id = ? AND scan_datetime = ? AND ip_anonymized = ?
            """, (cert_id, timestamp, ip_anonymized))

            existing_scan = cursor.fetchone()

            if existing_scan:
                scan_rowid = existing_scan[0]
                logging.debug(f"[INSIGHTS] CHECK 2 RESULT: FOUND - scan rowid={scan_rowid}")
                logging.debug(f"[INSIGHTS] CHECK 2 ACTION: UPDATING scan with country='{country}' city='{city}'")
                cursor.execute("""
                    UPDATE certificate_scans
                    SET country = ?, city = ?
                    WHERE rowid = ?
                """, (country, city, scan_rowid))
                logging.debug(f"[INSIGHTS] CHECK 2 ACTION: UPDATE COMPLETE")
            else:
                logging.debug(f"[INSIGHTS] CHECK 2 RESULT: NOT FOUND - Creating new scan")
                logging.debug(f"[INSIGHTS] CHECK 2 ACTION: INSERTING scan with cert_id='{cert_id}' timestamp='{timestamp}' ip_anonymized='{ip_anonymized}' country='{country}' city='{city}'")
                cursor.execute("""
                    INSERT INTO certificate_scans
                    (cert_id, scan_datetime, ip_anonymized, country, city)
                    VALUES (?, ?, ?, ?, ?)
                """, (
                    cert_id,
                    timestamp,
                    ip_anonymized,
                    country,
                    city
                ))
                logging.info(f"[INSIGHTS] CHECK 2 ACTION: INSERT COMPLETE")

            imported_count += 1
            logging.info(f"[INSIGHTS] ===== END PROCESSING ENTRY (imported_count={imported_count}) =====\n")

        # Update scan counts, last scan times, and top city for all certificates
        cursor.execute("""
            UPDATE certificates
            SET
                total_scans = (
                    SELECT COUNT(*) FROM certificate_scans
                    WHERE cert_id = certificates.cert_id
                ),
                last_scan = (
                    SELECT MAX(scan_datetime) FROM certificate_scans
                    WHERE cert_id = certificates.cert_id
                ),
                top_city = (
                    SELECT city FROM certificate_scans
                    WHERE cert_id = certificates.cert_id
                    GROUP BY city
                    ORDER BY COUNT(*) DESC
                    LIMIT 1
                )
            WHERE cert_id IN (SELECT DISTINCT cert_id FROM certificate_scans)
        """)

        self.conn.commit()
        logging.info(f"[INSIGHTS] Imported {imported_count} scan events")
        return imported_count

    # ========================================================================
    # DASHBOARD QUERIES
    # ========================================================================

    def get_certificate_stats(self) -> List[Dict]:
        """
        Get all certificates with scan statistics for dashboard.

        Returns:
            List of dicts with: filename, upload_status, date_created, date_uploaded,
                               total_scans, last_scan, top_country, top_city
        """
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT
                filename,
                upload_status,
                date_created,
                date_uploaded,
                total_scans,
                last_scan,
                top_city,
                (SELECT country FROM certificate_scans
                 WHERE cert_id = certificates.cert_id
                 ORDER BY scan_datetime DESC LIMIT 1) as top_country
            FROM certificates
            ORDER BY date_created DESC
        """)

        return [dict(row) for row in cursor.fetchall()]

    def get_database_statistics(self) -> Dict:
        """
        Get overall database statistics.

        Returns:
            Dict with keys: total_certificates, deployed, pending, discovered, deleted,
                           total_scans, unique_ip_blocks, unique_countries, unscanned
        """
        cursor = self.conn.cursor()

        stats = cursor.execute("""
            SELECT
                COUNT(*) as total_certificates,
                COUNT(CASE WHEN upload_status = 'ONLINE' THEN 1 END) as online,
                COUNT(CASE WHEN upload_status = 'PENDING' THEN 1 END) as pending,
                COUNT(CASE WHEN upload_status = 'DISCOVERED' THEN 1 END) as discovered,
                COUNT(CASE WHEN upload_status = 'DELETED' THEN 1 END) as deleted,
                COUNT(CASE WHEN total_scans = 0 THEN 1 END) as unscanned,
                SUM(total_scans) as total_scans,
                (SELECT COUNT(DISTINCT ip_anonymized) FROM certificate_scans) as unique_ip_blocks,
                (SELECT COUNT(DISTINCT country) FROM certificate_scans) as unique_countries
            FROM certificates
        """).fetchone()

        return {
            'total_certificates': stats[0] or 0,
            'online': stats[1] or 0,
            'pending': stats[2] or 0,
            'discovered': stats[3] or 0,
            'deleted': stats[4] or 0,
            'unscanned': stats[5] or 0,
            'total_scans': stats[6] or 0,
            'unique_ip_blocks': stats[7] or 0,
            'unique_countries': stats[8] or 0
        }

    def get_scan_locations_for_cert(self, cert_filename: str) -> Dict[str, int]:
        """
        Get location (country) breakdown for a certificate.

        Args:
            cert_filename: Certificate filename

        Returns:
            Dict of {country: scan_count}
        """
        from models.secure_storage import SecureStorage

        cert_id = SecureStorage.generate_id_from_name(cert_filename)
        logging.info(f"[SCAN_LOC] get_scan_locations_for_cert('{cert_filename}') -> cert_id='{cert_id}'")

        cursor = self.conn.cursor()

        cursor.execute("""
            SELECT country, COUNT(*) as count
            FROM certificate_scans
            WHERE cert_id = ?
            GROUP BY country
            ORDER BY count DESC
        """, (cert_id,))

        result = {row['country']: row['count'] for row in cursor.fetchall()}
        logging.info(f"[SCAN_LOC] Query returned: {result}")
        return result

    # ========================================================================
    # UTILITY & MAINTENANCE
    # ========================================================================

    def clear_all_data(self):
        """Clear all data (for testing/reset)."""
        cursor = self.conn.cursor()
        cursor.execute("DELETE FROM certificate_scans")
        cursor.execute("DELETE FROM certificates")
        cursor.execute("UPDATE sync_state SET last_line_processed = 0, last_sync_status = 'RESET'")
        self.conn.commit()
        logging.info("[INSIGHTS] Database cleared")

    def close(self):
        """Close database connection."""
        if self.conn:
            self.conn.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
