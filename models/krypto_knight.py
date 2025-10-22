# models/Krypto_knight.py
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
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
import base58

from .exceptions import KeystoreError
from .crypto_manager import CryptoManager
from .config import APP_DATA_DIR, KEY_FILENAME_TEMPLATE


class KryptoKnight:
    """
    Op'n-Czamy's dedicated signing authority.
    The *only* class permitted to handle Kryptonite  (private keys):p .
    Provides both raw-byte and Base58-encoded Ed25519 signatures.
    """

    def __init__(self, crypto_manager: CryptoManager):
        self.crypto_manager = crypto_manager

    def sign(
        self,
        issuer_id: str,
        key_location_str: str,
        data_to_sign: bytes,
        encode: str = "b58",
    ) -> str | bytes:
        """
        Signs arbitrary data using the issuer's private key.

        Args:
            issuer_id: The ID of the key to use.
            key_location_str: Where the private key is stored.
            data_to_sign: Raw bytes to sign.
            encode: Output format — 'b58' for Base58 string, 'raw' for bytes.

        Returns:
            Base58 string (default) or raw signature bytes.
        """
        key_path = APP_DATA_DIR / KEY_FILENAME_TEMPLATE.format(issuer_id=issuer_id)
        
        private_key_pem = None
        priv_key = None
        
        try:
            private_key_pem = self.crypto_manager.get_private_key(
                key_location_str, issuer_id, key_path
            )
            if not private_key_pem:
                raise KeystoreError(f"KryptoKnight could not retrieve the private key for issuer {issuer_id}")

            priv_key = serialization.load_pem_private_key(
                private_key_pem.encode("utf-8"),
                password=None,
            )

            if not isinstance(priv_key, ed25519.Ed25519PrivateKey):
                 raise KeystoreError("Unsupported key type: is your private key corrupted? Seek assistance and retrieve your backup.")

            signature_bytes = priv_key.sign(data_to_sign)

            if encode == "raw":
                return signature_bytes
            elif encode == "b58":
                return base58.b58encode(signature_bytes).decode("utf-8")
            else:
                raise ValueError(f"Unsupported encoding mode: {encode}")
                
        finally:
            # Attempt to Men in Black the Kryptonite from memory.
            # Not bullet proof because of Python garbage collector.
            private_key_pem = None
            priv_key = None