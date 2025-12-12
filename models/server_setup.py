"""
Server Setup Module - Shared Infrastructure for All Users

This module handles server-side file generation and deployment for BOTH free and pro users:
- .htaccess file generation and upload (CORE: URL rewriting for all users)
- insights.php generation and upload (LOGGING: Free users can enable/disable, Pro users view analytics in app)
- .insights-config.json (Controls whether server logging is active)
- FTP-based file deployment to LKY folder

KEY ARCHITECTURE:
=================
✓ Server files are IDENTICAL for free and pro users
✓ Logging capability is FREE (all users can enable/disable server logging)
✓ Analytics DASHBOARD is PRO-ONLY (processing/visualization in the app)
✓ Differentiation happens in the APP, not on the server

LICENSING MODEL:
================
- logging_enabled=true: Server actively logs certificate views (can be enabled by any user)
- logging_enabled=false: Server ignores logging requests (default for new identities)
- Pro license: Unlocks analytics dashboard to process/view/export the logs

IMPORTANT: The server-side components are OPEN SOURCE!
============================================
The .htaccess and insights.php files are provided as open-source
code under the MIT License. You can find the source files in:

    ./server_side/apache/          (for Apache servers)
    ./server_side/nginx/           (for Nginx configuration examples)
    ./server_side/README.md        (comprehensive documentation)

This provides:
✓ Transparency - Inspect exactly what runs on your server
✓ Security - Community can audit for vulnerabilities
✓ Customization - Adapt the code to your needs
✓ Portability - Use with different web servers
✓ Clear Licensing - Separates open-source server code from closed-source client

See ./server_side/README.md for details, customization examples, and troubleshooting.
"""

import logging
import ftplib
from io import BytesIO
from typing import Tuple
from urllib.parse import urlparse
from datetime import datetime


class ServerSetup:
    """Handles server setup operations for certificate hosting"""

    def __init__(self, logic_instance):
        """
        Initialize ServerSetup with logic instance

        Args:
            logic_instance: Main logic instance for accessing settings
        """
        self.logic = logic_instance

    def generate_and_upload_htaccess(self, is_pro: bool = False) -> tuple[bool, str]:
        """
        Generate .htaccess and upload to LKY file directory (FOR ALL USERS)

        .htaccess is CORE INFRASTRUCTURE required for all users:
        - Enables URL rewriting for extension-less certificate URLs
        - Protects insight logs from direct HTTP access
        - Routes requests through insights.php for optional logging

        Args:
            is_pro: Deprecated parameter (ignored). .htaccess is always identical for all users.

        Returns:
            (success, message)
        """
        try:
            from io import BytesIO
            import ftplib

            ftp_settings = self.logic.get_ftp_settings_for_connection()
            if not ftp_settings:
                return False, "FTP settings not configured"

            # Get LKY directory from imageBaseUrl
            image_base_url = self.logic.active_issuer_data.get("imageBaseUrl", "")
            if not image_base_url:
                return False, "Image Base URL not configured"

            # CRITICAL FIX: Always generate the full .htaccess with routing rules
            # This is REQUIRED for all users (free and pro) for extension-less URLs to work.
            # The "insights" feature (pro) controls analytics logging enablement (.insights-config.json),
            # NOT whether the URL rewriting infrastructure is deployed.
            htaccess_content = r"""# ============================================================================
# Op'n-Czami Insights (QR Log Analytics) - Apache Configuration
#
# This .htaccess file enables URL rewriting for certificate view tracking.
# It protects the analytics.log file and routes requests through insights.php
#
# License: MIT (See LICENSE file)
# ============================================================================

# Enable the rewrite engine
RewriteEngine On

# ============================================================================
# SECURITY: Deny direct access to insights log file
# ============================================================================
<Files "insights.log">
    Order allow,deny
    Deny from all
</Files>

# Deny access to archived insight logs
<FilesMatch "^insights-\d{4}-\d{2}\.log$">
    Order allow,deny
    Deny from all
</FilesMatch>

# Deny access to metadata files
<Files ".insights-*">
    Order allow,deny
    Deny from all
</Files>

# ============================================================================
# URL REWRITING LOGIC
# ============================================================================

# 1) If the request is a real file, do NOT rewrite
RewriteCond %{REQUEST_FILENAME} -f
RewriteRule ^ - [L]

# 2) If the request is a real directory, do NOT rewrite
RewriteCond %{REQUEST_FILENAME} -d
RewriteRule ^ - [L]

# 3) DIRECT .lky FILES: Serve as-is (NO PHP, NO logging)
RewriteRule ^(.+)\.lky$ - [L]

# 4) EXTENSION-LESS REQUESTS → insights.php
#    /certificat/mycert → insights.php?file=mycert
RewriteRule ^(.*)$ insights.php?file=$1 [QSA,L]

# ============================================================================
# OPTIONAL: Compression (improves performance)
# ============================================================================
<IfModule mod_deflate.c>
    AddOutputFilterByType DEFLATE text/plain
    AddOutputFilterByType DEFLATE text/html
    AddOutputFilterByType DEFLATE application/json
</IfModule>

# ============================================================================
# OPTIONAL: Cache headers for .lky files (can improve performance)
# ============================================================================
<FilesMatch "\.(lky)$">
    Header set Cache-Control "public, max-age=86400"
</FilesMatch>
"""

            logging.info(f"Generated .htaccess (full routing rules for all users)")

            # Upload .htaccess
            htaccess_bytes = htaccess_content.encode('utf-8')
            success, msg = self._upload_htaccess_to_lky_folder(ftp_settings, htaccess_bytes, image_base_url)
            return success, msg

        except Exception as e:
            logging.error(f"Failed to generate/upload .htaccess: {e}", exc_info=True)
            return False, f"Error: {str(e)}"

    def _upload_htaccess_to_lky_folder(self, ftp_settings, content_bytes, image_base_url):
        """Upload .htaccess to LKY folder (for direct file serving + logging)"""
        try:
            from models.ftp_manager import FTPManager
            ftp_mgr = FTPManager()

            success, msg = ftp_mgr.upload_file(
                content_bytes,
                image_base_url,
                ".htaccess",
                ftp_settings
            )
            return success, msg
        except Exception as e:
            logging.error(f"Failed to upload .htaccess: {e}")
            return False, f"Upload failed: {str(e)}"

    def generate_and_upload_insights_php(self) -> tuple[bool, str]:
        """
        Generate insights.php and upload to LKY file directory (FOR ALL USERS - LOGGING IS FREE)

        Uploads the SAME insights.php for all users. The logging capability is FREE.
        Whether logging is active is controlled by .insights-config.json:

        LOGGING (FREE):
        - logging_enabled = true: Server logs certificate views (any user can enable)
        - logging_enabled = false: Server ignores logging requests (default)

        ANALYTICS DASHBOARD (PRO-ONLY):
        - Pro users: Can view/process/export logs via the app dashboard
        - Free users: Can enable logging on server, but no in-app visualization

        Returns:
            (success, message)
        """
        try:
            import ftplib

            ftp_settings = self.logic.get_ftp_settings_for_connection()
            if not ftp_settings:
                return False, "FTP settings not configured"

            image_base_url = self.logic.active_issuer_data.get("imageBaseUrl", "")
            if not image_base_url:
                return False, "Image Base URL not configured"

            # Generate insights.php with monthly log rotation (QR Insights)
            insights_php = '''<?php
// insights.php - QR Insights (Certificate View Analytics) with Monthly Rotation
//
// Automatically rotates logs monthly:
// Month 1: analytics.log (fills with events)
// Month 2: analytics-2025-10.log (archive), analytics.log (new file)
//
// Format: "YYYY-MM-DD HH:MM:SS | IP | certificate_filename\\n"
// Filters: Skips test/debug requests (opnczami_*, __opnczami_*, file_that*)

// Perform log rotation if needed
function rotate_analytics_log_if_needed() {
    $current_month = date('Y-m');  // e.g. "2025-10"
    $lock_file = '.insights-rotation.lock';
    $metadata_file = '.insights-metadata.json';

    // Read metadata to check last rotation month
    $metadata = array();
    if (file_exists($metadata_file)) {
        $content = @file_get_contents($metadata_file);
        if ($content) {
            $metadata = json_decode($content, true) ?: array();
        }
    }

    $last_rotation_month = isset($metadata['last_rotation_month']) ? $metadata['last_rotation_month'] : null;

    // Check if rotation needed
    if ($last_rotation_month !== $current_month) {
        // Try to acquire lock (non-blocking)
        $lock_handle = @fopen($lock_file, 'c');
        if ($lock_handle && flock($lock_handle, LOCK_EX | LOCK_NB)) {
            try {
                // Double-check inside lock (another process might have rotated)
                $metadata = array();
                if (file_exists($metadata_file)) {
                    $content = @file_get_contents($metadata_file);
                    if ($content) {
                        $metadata = json_decode($content, true) ?: array();
                    }
                }
                $last_rotation_month = isset($metadata['last_rotation_month']) ? $metadata['last_rotation_month'] : null;

                // If still different month, perform rotation
                if ($last_rotation_month !== $current_month) {
                    // Archive old log (if it exists)
                    if (file_exists('insights.log') && filesize('insights.log') > 0) {
                        $prev_month = date('Y-m', strtotime('first day of last month'));
                        $archive_log = 'insights-' . $prev_month . '.log';
                        @rename('insights.log', $archive_log);
                    }

                    // Create new empty log
                    @touch('insights.log');

                    // Update metadata
                    $metadata['last_rotation_month'] = $current_month;
                    $metadata['last_rotation_time'] = date('Y-m-d H:i:s');
                    @file_put_contents($metadata_file, json_encode($metadata));
                }
            } finally {
                flock($lock_handle, LOCK_UN);
                fclose($lock_handle);
            }
        }
    }
}

// Append event to log (thread-safe)
function append_analytics_event($ip, $filename) {
    // Sanitize inputs
    $ip = trim($ip);
    $filename = trim($filename);

    // Basic validation
    if (empty($ip) || empty($filename)) {
        return false;
    }

    // Build event line
    $timestamp = date('Y-m-d H:i:s');
    $event = $timestamp . ' | ' . $ip . ' | ' . $filename . "\\n";

    // Append with file locking
    $retries = 3;
    for ($i = 0; $i < $retries; $i++) {
        $handle = @fopen('insights.log', 'a');
        if ($handle) {
            if (flock($handle, LOCK_EX)) {
                fwrite($handle, $event);
                flock($handle, LOCK_UN);
                fclose($handle);
                return true;
            }
            fclose($handle);
        }
        if ($i < $retries - 1) {
            usleep(50000);  // 50ms delay before retry
        }
    }

    return false;
}

// Perform rotation check
rotate_analytics_log_if_needed();

// Get filename from GET parameter
$file = basename($_GET['file'] ?? '');
if (empty($file)) {
    http_response_code(400);
    exit('Bad request');
}

// Skip logging for test/debug requests (these should not appear in analytics)
// These patterns indicate compatibility checks, keystore tests, or internal checks
$skip_patterns = [
    'opnczami_',     // Compatibility check: opnczami_compat_check_*
    '__opnczami_',   // Internal test: __opnczami_check
    'file_that'      // Invalid file: file_that_does_not_exist
];

$is_test_request = false;
foreach ($skip_patterns as $pattern) {
    if (strpos($file, $pattern) === 0) {
        $is_test_request = true;
        break;
    }
}

// Skip logging for direct .lky file access (served directly by .htaccess)
// Only log extension-less URLs that go through insights.php
$is_direct_lky_access = substr($file, -4) === '.lky';

// Get IP (support X-Forwarded-For for proxies)
$ip = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'] ?? 'unknown';
if (strpos($ip, ',') !== false) {
    $ip = explode(',', $ip)[0];
}
$ip = trim($ip);

// Record the event only if:
// 1. This is NOT a test request AND
// 2. This is NOT a direct .lky file access (only extension-less URLs)
if (!$is_test_request && !$is_direct_lky_access) {
    append_analytics_event($ip, $file);
}

// Serve the .lky file
// Always append .lky - the .htaccess handles both patterns
$filepath = $file . '.lky';
if (!file_exists($filepath)) {
    // File not found - don't set image header since we're returning error
    http_response_code(404);
    exit('File not found');
}

// File exists - set proper content type for serving
header('Content-Type: image/jpeg');
readfile($filepath);
?>
'''

            logging.info("Generated insights.php")

            # Upload insights.php
            insights_bytes = insights_php.encode('utf-8')
            success, msg = self._upload_file_to_lky_folder(ftp_settings, insights_bytes, "insights.php", image_base_url)
            return success, msg

        except Exception as e:
            logging.error(f"Failed to generate/upload insights.php: {e}", exc_info=True)
            return False, f"Error: {str(e)}"

    def generate_and_upload_insights_config(self) -> tuple[bool, str]:
        """
        Generate .insights-config.json and upload to LKY file directory (PRO ONLY)

        This config file controls whether insights.php logs visitor data or not.

        Returns:
            (success, message)
        """
        try:
            import json

            ftp_settings = self.logic.get_ftp_settings_for_connection()
            if not ftp_settings:
                return False, "FTP settings not configured"

            image_base_url = self.logic.active_issuer_data.get("imageBaseUrl", "")
            if not image_base_url:
                return False, "Image Base URL not configured"

            # Check if QR Insights is enabled in the configuration
            insights_enabled = self.logic.active_issuer_data.get("settings", {}).get("enable_analytics_logging", True)

            # Generate insights config
            insights_config = {
                "insights_enabled": insights_enabled,
                "config_generated": datetime.now().isoformat(),
                "description": "Op'n-Czami QR Insights Configuration"
            }

            config_json = json.dumps(insights_config, indent=2)
            logging.info(f"Generated .insights-config.json (insights_enabled={insights_enabled})")

            # Upload config file
            config_bytes = config_json.encode('utf-8')
            success, msg = self._upload_file_to_lky_folder(ftp_settings, config_bytes, ".insights-config.json", image_base_url)
            return success, msg

        except Exception as e:
            logging.error(f"Failed to generate/upload insights config: {e}", exc_info=True)
            return False, f"Error: {str(e)}"

    def _upload_htaccess_to_lky_folder(self, ftp_settings: dict, file_bytes: bytes, image_base_url: str) -> tuple[bool, str]:
        """Upload .htaccess to LKY folder"""
        return self._upload_file_to_lky_folder(ftp_settings, file_bytes, ".htaccess", image_base_url)

    def _upload_file_to_lky_folder(self, ftp_settings: dict, file_bytes: bytes, filename: str, image_base_url: str) -> tuple[bool, str]:
        """Upload file to LKY folder via FTP using ftp_manager (creates directories as needed)"""
        try:
            from pathlib import Path
            from io import BytesIO
            import tempfile

            # Calculate remote directory
            is_success, remote_dir, error_msg = self.logic.ftp_manager.calculate_remote_path(
                ftp_root=self.logic.config.ftp_path,
                image_base_url=image_base_url
            )
            if not is_success:
                return False, error_msg

            # Write bytes to temporary file
            with tempfile.NamedTemporaryFile(delete=False, suffix=filename) as tmp_file:
                tmp_file.write(file_bytes)
                tmp_path = Path(tmp_file.name)

            try:
                # Use ftp_manager.upload_file() - it handles directory creation
                is_success, msg = self.logic.ftp_manager.upload_file(tmp_path, remote_dir, filename, ftp_settings)
                return is_success, msg
            finally:
                # Clean up temp file
                if tmp_path.exists():
                    tmp_path.unlink()

        except Exception as e:
            logging.error(f"Error uploading {filename}: {e}", exc_info=True)
            return False, f"Error: {str(e)}"

    # ========================================================================
    # SERVER COMPATIBILITY CHECKS
    # ========================================================================

    def check_server_compatibility_threaded(self, ui_callback=None):
        """
        Runs a comprehensive, non-blocking check of the remote server's
        compatibility for analytics and .lky file serving.

        Args:
            ui_callback: Optional callback object with on_server_check_complete(results) method
        """
        import threading
        self.ui_callback = ui_callback
        thread = threading.Thread(target=self._run_compatibility_checks, daemon=True)
        thread.start()

    def _run_compatibility_checks(self):
        """Worker thread that performs all compatibility checks."""
        import requests

        results = []

        ftp_settings = self.logic.get_ftp_settings_for_connection()
        image_base_url = self.logic.active_issuer_data.get("imageBaseUrl", "").rstrip('/') if self.logic.active_issuer_data else ""

        if not ftp_settings or not image_base_url:
            results.append(('Configuration', False, 'FTP or Image Base URL is not configured.'))
            if hasattr(self, 'ui_callback') and self.ui_callback:
                self.ui_callback.on_server_check_complete(results)
            return

        try:
            # --- 1. FTP Connection Check (using FTPManager) ---
            try:
                ftp_ok, ftp_msg = self.logic.ftp_manager.test_connection(
                    ftp_settings.get('host'),
                    ftp_settings.get('user'),
                    ftp_settings.get('password')
                )
                results.append(('FTP Connection', ftp_ok, 'Connected' if ftp_ok else ftp_msg))
                if not ftp_ok:
                    raise Exception("FTP connection failed, aborting further checks.")
            except Exception as e:
                results.append(('FTP Connection', False, str(e)))
                if hasattr(self, 'ui_callback') and self.ui_callback:
                    self.ui_callback.on_server_check_complete(results)
                return

            # --- 2. PHP Execution Check ---
            try:
                php_check_url = f"{image_base_url}/insights.php?file=__opnczami_check"
                res = requests.get(php_check_url, timeout=10, verify=True)
                is_php_running = "text/html" in res.headers.get('Content-Type', '') and res.status_code == 404
                if "<?php" in res.text:
                    results.append(('PHP', False, 'PHP not executing (check server configuration)'))
                elif is_php_running:
                    results.append(('PHP', True, 'Installed and working'))
                else:
                    results.append(('PHP', False, f'Unable to verify (HTTP {res.status_code})'))
            except Exception as e:
                results.append(('PHP', False, 'Not accessible'))

            # --- 3. URL Rewriting Check (.htaccess) ---
            try:
                # Try to access a non-existent file through URL rewriting
                rewrite_check_url = f"{image_base_url}/__opnczami_check"
                res = requests.get(rewrite_check_url, timeout=10, verify=True)
                if res.status_code == 404:
                    # 404 from PHP means URL rewriting worked
                    results.append(('.htaccess', True, 'Configured and working'))
                elif res.status_code == 301 or res.status_code == 302:
                    results.append(('.htaccess', False, 'Redirecting instead of rewriting'))
                else:
                    results.append(('.htaccess', False, f'Unable to verify (HTTP {res.status_code})'))
            except Exception as e:
                results.append(('.htaccess', False, 'Not accessible'))

            # --- 4. Log Protection Check ---
            try:
                log_url = f"{image_base_url}/insights.log"
                res = requests.get(log_url, timeout=10, verify=True)
                if res.status_code == 403:
                    results.append(('Log Protection', True, 'Properly protected'))
                elif res.status_code == 200:
                    results.append(('Log Protection', False, 'Not protected (publicly accessible)'))
                elif res.status_code == 404:
                    results.append(('Log Protection', True, 'Will be protected (not created yet)'))
                else:
                    results.append(('Log Protection', False, f'Unable to verify (HTTP {res.status_code})'))
            except Exception as e:
                results.append(('Log Protection', False, 'Not accessible'))

        finally:
            logging.info(f"Server compatibility check complete: {results}")
            if hasattr(self, 'ui_callback') and self.ui_callback:
                self.ui_callback.on_server_check_complete(results)

