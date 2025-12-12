# exceptions.py
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


class OpnCzamiException(Exception):
    """Base exception for all custom errors in the application."""
    pass

class SettingsError(OpnCzamiException):
    """Raised for errors related to loading or saving the settings file."""
    pass

class KeystoreError(OpnCzamiException):
    """Raised for errors interacting with the OS keystore (keyring)."""
    pass

class FileAccessError(OpnCzamiException):
    """Raised for errors when a required file is missing or unreadable."""
    pass

class HashCalculationError(OpnCzamiException):
    """Raised for errors during file hash calculation."""
    pass
class AuditLogError(OpnCzamiException):
    """Raised for errors reading from or writing to the audit log."""
    pass