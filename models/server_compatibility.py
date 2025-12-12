# models/server_compatibility.py
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

"""
Server Compatibility Checker for QR Insights and Analytics

Performs 4 critical compatibility tests on the user's server:
1. FTP Connection - Can we connect and upload files?
2. PHP Execution - Is PHP 7.0+ installed and working?
3. URL Rewriting (.htaccess) - Does the server support extension-less URLs?
4. Log File Protection - Are analytics logs protected from public access?

This module is OPEN SOURCE - inspect the code to understand what it tests.
See ./server_side/README.md for detailed server setup requirements.
"""

import logging
import requests
from typing import List, Tuple, Optional


class ServerCompatibility:
    """Checks server compatibility for analytics and certificate serving."""

    def __init__(self, ftp_manager=None):
        """
        Initialize compatibility checker.

        Args:
            ftp_manager: FTPManager instance for testing connections
        """
        self.ftp_manager = ftp_manager

    def check_compatibility(
        self,
        ftp_settings: dict,
        image_base_url: str
    ) -> List[Tuple[str, bool, str]]:
        """
        Runs all 4 compatibility checks on the remote server.

        Args:
            ftp_settings: Dictionary with host, user, password
            image_base_url: Base URL where certificates are served from

        Returns:
            List of tuples: [(test_name, passed, message), ...]
            Example: [('FTP Connection', True, 'Connected'), ...]
        """
        results = []

        if not ftp_settings or not image_base_url:
            results.append(
                ('Configuration', False, 'FTP or Image Base URL is not configured.')
            )
            return results

        # 1. FTP Connection Check
        results.append(self._check_ftp_connection(ftp_settings))

        # If FTP fails, skip other checks (can't deploy files)
        if not results[0][1]:
            logging.warning("FTP connection failed, skipping other compatibility checks")
            return results

        # 2. PHP Execution Check
        results.append(self._check_php_execution(image_base_url))

        # 3. URL Rewriting Check (.htaccess)
        results.append(self._check_url_rewriting(image_base_url))

        # 4. Log File Protection Check
        results.append(self._check_log_protection(image_base_url))

        return results

    def _check_ftp_connection(self, ftp_settings: dict) -> Tuple[str, bool, str]:
        """
        TEST 1: FTP Connection Check
        Verifies that FTP credentials work and we can connect to the server.
        """
        try:
            if not self.ftp_manager:
                return (
                    'FTP Connection',
                    False,
                    'FTP Manager not available'
                )

            ftp_ok, ftp_msg = self.ftp_manager.test_connection(
                ftp_settings.get('host'),
                ftp_settings.get('user'),
                ftp_settings.get('password')
            )

            if ftp_ok:
                return ('FTP Connection', True, 'Connected')
            else:
                return ('FTP Connection', False, ftp_msg)

        except Exception as e:
            logging.error(f"FTP connection check failed: {e}")
            return ('FTP Connection', False, str(e))

    def _check_php_execution(self, image_base_url: str) -> Tuple[str, bool, str]:
        """
        TEST 2: PHP Execution Check
        Verifies that the server is running PHP 7.0+ and can execute scripts.

        What we test:
        - Request insights.php with a test file parameter
        - Check if PHP is executing (not just serving as text)
        - Verify we get a 404 (expected for non-existent file)

        Why this matters:
        - Analytics logging requires PHP execution
        - If PHP isn't running, scripts are served as raw text
        """
        try:
            php_check_url = f"{image_base_url.rstrip('/')}/insights.php?file=__opnczami_check"
            logging.info(f"PHP check: {php_check_url}")

            res = requests.get(php_check_url, timeout=10, verify=True)

            # If response contains "<?php" tag, PHP isn't executing
            if "<?php" in res.text:
                return (
                    'PHP Execution',
                    False,
                    'PHP not executing (check server configuration)'
                )

            # PHP is executing if we get HTML response with 404
            is_php_running = "text/html" in res.headers.get('Content-Type', '') and res.status_code == 404

            if is_php_running:
                return ('PHP Execution', True, 'Installed and working')
            else:
                return (
                    'PHP Execution',
                    False,
                    f'Unable to verify (HTTP {res.status_code})'
                )

        except requests.Timeout:
            return ('PHP Execution', False, 'Server not responding (timeout)')
        except Exception as e:
            logging.error(f"PHP execution check failed: {e}")
            return ('PHP Execution', False, 'Not accessible')

    def _check_url_rewriting(self, image_base_url: str) -> Tuple[str, bool, str]:
        """
        TEST 3: URL Rewriting Check (.htaccess)
        Verifies that the server supports extension-less URLs via .htaccess rewriting.

        What we test:
        - Request a non-existent file without extension: /__opnczami_check
        - If .htaccess is working, this gets routed to insights.php
        - PHP responds with 404 (file not found)
        - If .htaccess isn't working, we get 404/not found directly

        Why this matters:
        - Analytics URLs use extension-less format: /certificate123
        - Without rewriting, URLs need extensions: /certificate123.lky
        - Fallback mechanism available: serves .lky files directly

        Compatibility:
        - ✓ Apache with mod_rewrite enabled
        - ✗ Nginx, IIS (don't support .htaccess)
        - ✗ Apache with mod_rewrite disabled
        """
        try:
            rewrite_check_url = f"{image_base_url.rstrip('/')}/__opnczami_check"
            logging.info(f"URL Rewriting check: {rewrite_check_url}")

            res = requests.get(rewrite_check_url, timeout=10, verify=True)

            if res.status_code == 404:
                # 404 from PHP means URL rewriting worked
                return ('.htaccess Rewriting', True, 'Configured and working')
            elif res.status_code in [301, 302]:
                return (
                    '.htaccess Rewriting',
                    False,
                    'Redirecting instead of rewriting'
                )
            else:
                return (
                    '.htaccess Rewriting',
                    False,
                    f'Unable to verify (HTTP {res.status_code})'
                )

        except requests.Timeout:
            return ('.htaccess Rewriting', False, 'Server not responding (timeout)')
        except Exception as e:
            logging.error(f"URL rewriting check failed: {e}")
            return ('.htaccess Rewriting', False, 'Not accessible')

    def _check_log_protection(self, image_base_url: str) -> Tuple[str, bool, str]:
        """
        TEST 4: Log File Protection Check
        Verifies that analytics.log (and insights.log) are protected from public access.

        What we test:
        - Try to access /insights.log directly
        - Should get 403 (Forbidden) if protected
        - Should NOT get 200 (OK) - that would be a security issue

        Why this matters:
        - Log files contain visitor IPs and analytics data
        - They should never be publicly readable
        - .htaccess should deny access via <Files> directive

        Security implications:
        - ✓ 403 Forbidden = Properly protected
        - ✓ 404 Not Found = Will be protected when created
        - ✗ 200 OK = Security warning! Logs are publicly accessible
        """
        try:
            log_url = f"{image_base_url.rstrip('/')}/insights.log"
            logging.info(f"Log protection check: {log_url}")

            res = requests.get(log_url, timeout=10, verify=True)

            if res.status_code == 403:
                return ('Log File Protection', True, 'Properly protected')
            elif res.status_code == 404:
                return ('Log File Protection', True, 'Will be protected (not created yet)')
            elif res.status_code == 200:
                return (
                    'Log File Protection',
                    False,
                    'WARNING: Log file is publicly accessible! Add .htaccess protection.'
                )
            else:
                return (
                    'Log File Protection',
                    False,
                    f'Unable to verify (HTTP {res.status_code})'
                )

        except requests.Timeout:
            return ('Log File Protection', False, 'Server not responding (timeout)')
        except Exception as e:
            logging.error(f"Log protection check failed: {e}")
            return ('Log File Protection', False, 'Not accessible')

