# services/signing_service.py
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
SigningService - Manages the business process of signing documents.

Responsibility: Handle the complete workflow of signing a document to create
a .lky (LegatorKey) file with embedded QR code. This includes image processing,
LKY assembly, signing, QR generation, file management, and database logging.

This service implements the core certificate creation business logic, delegating
to low-level managers for cryptographic operations and file I/O.

Dependencies:
- SecureStorage: Key management and retrieval
- CryptographyService: Low-level crypto operations (signing, hashing)
- ImageProcessor: QR code and watermark generation
- InsightsDB: Certificate tracking and logging
- Pro handlers: Optional watermarking (if licensed)
"""

import base45
import cbor2
import datetime
import io
import json
import logging
import random
import shutil
import string
import zlib
from pathlib import Path
from typing import Tuple, Union, Dict

from PIL import Image

from models.exceptions import KeystoreError
from models.cryptography_service import CryptographyService
from models.config import APP_DATA_DIR, KEY_FILENAME_TEMPLATE, FEATURE_WATERMARK
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
import base58


class SigningService:
    """
    Manages the complete workflow of signing a document.

    Handles:
    1. Image preparation (loading, watermarking)
    2. LKY file assembly (image + payload + signature)
    3. QR code generation
    4. File saving and state management
    5. Database logging
    6. Auto-upload to FTP

    Stateless service: All state is passed as method parameters, not stored
    in instance variables. This ensures the service can be used safely
    without requiring state synchronization.
    """

    def __init__(self, crypto_manager, cryptography_service, image_processor, license_manager):
        """
        Initialize SigningService with only stateless dependencies.

        Args:
            crypto_manager: SecureStorage instance for key retrieval
            cryptography_service: CryptographyService instance for signing operations
            image_processor: ImageProcessor instance for QR generation
            license_manager: LicenseManager instance for feature checks
        """
        self.crypto_manager = crypto_manager
        self.cryptography_service = cryptography_service
        self.image_processor = image_processor
        self.license_manager = license_manager

    def _sign_data(self, issuer_id: str, key_location_str: str, data_to_sign: bytes, encode: str = 'b58') -> Union[str, bytes]:
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
                raise KeystoreError(f"Could not retrieve the private key for issuer {issuer_id}")

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
            # Attempt to clear sensitive data from memory
            # IMPORTANT: This is best-effort only due to Python's garbage collector
            # - Local variable reassignment helps, but doesn't guarantee immediate deallocation
            # - Data may remain in memory until GC runs
            # - Memory dumps from debuggers could still expose the key
            #
            # For maximum security in production:
            # - Run on dedicated hardware with memory encryption
            # - Use OS-level keystore (preferred method, used elsewhere in codebase)
            # - Consider using memory-locking features at the OS level
            #
            # This is acknowledged limitation, not a security failure.
            private_key_pem = None
            priv_key = None

    def sign_document(self,
                      image_path: Path,
                      details: dict,
                      config: 'AppConfig',
                      active_issuer_id: str,
                      active_issuer_data: dict,
                      insights_db,
                      pro_handler,
                      original_status_logo_pil: Image.Image) -> Tuple[bool, str, Union[Image.Image, None], Union[Image.Image, None], Union[Path, None]]:
        """
        Sign a single document and create its LKY certificate.

        Args:
            image_path: Path to the image file to sign
            details: Dict with signing details {"m": message, "n": document number, etc.}
            config: AppConfig instance with signing settings
            active_issuer_id: Current issuer ID
            active_issuer_data: Current issuer data dict with private key
            insights_db: InsightsDB instance (optional, for certificate logging)
            pro_handler: ProFeatures handler (optional, for watermarking)
            original_status_logo_pil: PIL Image for logo watermarking

        Returns:
            Tuple[success: bool, message: str, final_image: PIL.Image or None, qr_image: PIL.Image or None, lky_file_path: Path or None]
            - success: True if signing completed
            - message: Status message
            - final_image: The processed image that was signed
            - qr_image: The generated QR code image
            - lky_file_path: Path to the saved LKY file for upload
        """
        temp_path = None
        try:
            logging.info(f"[SIGNING] Starting document signing: {image_path}")

            # --- 1. VALIDATION & PREPARATION ---
            self._validate_signing_preconditions(active_issuer_id, active_issuer_data)
            final_image, image_bytes = self._prepare_image_for_signing(
                image_path, config, active_issuer_data, pro_handler, original_status_logo_pil
            )
            filename_stem = self._generate_filename_stem(image_path, config)
            final_filename = f"{filename_stem}.lky"

            logging.info(f"[SIGNING] Prepared image: {final_filename}")

            # --- 2. BUILD & ASSEMBLE LKY FILE ---
            data_to_sign, payload_dict, payload_bytes = self._build_lky_payload(
                image_bytes, final_filename, details
            )
            lky_file_bytes = self._assemble_lky_binary(
                data_to_sign, image_bytes, payload_dict, payload_bytes,
                active_issuer_id, active_issuer_data
            )

            logging.info(f"[SIGNING] LKY file assembled ({len(lky_file_bytes)} bytes)")

            # --- 3. SAVE TEMPORARILY & CALCULATE HASH ---
            temp_dir, temp_path = self._save_to_temp_location(final_filename, lky_file_bytes)
            file_hash_hex = self.crypto_manager.calculate_file_hash(temp_path)

            logging.info(f"[SIGNING] File hash calculated: {file_hash_hex[:16]}...")

            # --- 4. LOG TO INSIGHTS DB ---
            self._log_to_insights_db(final_filename, insights_db)

            # --- 5. GENERATE QR CODE ---
            qr_data = self._build_qr_payload(
                filename_stem, file_hash_hex, details,
                active_issuer_id, active_issuer_data
            )
            # Always use the legatokey.png logo for QR embedding
            qr_image = self._generate_qr_with_legatokey_logo(qr_data)

            logging.info(f"[SIGNING] QR code generated")

            # --- 6. FINALIZE LOCAL SAVE ---
            final_lky_path = self._finalize_save(temp_path, qr_image, config)

            logging.info(f"[SIGNING] Document signed successfully: {final_filename}")
            return True, "Document signed successfully.", final_image, qr_image, final_lky_path

        except (ValueError, KeystoreError) as e:
            logging.error(f"[SIGNING] Validation error: {e}")
            return False, str(e), None, None, None
        except Exception as e:
            logging.error(f"[SIGNING] Unexpected error: {e}", exc_info=True)
            return False, f"Signing failed: {e}", None, None, None
        finally:
            # Clean up temporary file if signing failed or if it still exists
            if temp_path and temp_path.exists():
                try:
                    temp_path.unlink()
                    logging.debug(f"[SIGNING] Cleaned up temporary file: {temp_path}")
                except Exception as e:
                    logging.warning(f"[SIGNING] Could not delete temporary file {temp_path}: {e}")

    # ========================================================================
    # VALIDATION & PREPARATION
    # ========================================================================

    def _validate_signing_preconditions(self, active_issuer_id, active_issuer_data):
        """Check that signing prerequisites are met."""
        if not active_issuer_id:
            raise ValueError("No active issuer identity loaded.")
        if not active_issuer_data.get("priv_key_pem"):
            raise KeystoreError("Private key is unavailable for the active issuer.")

    def _prepare_image_for_signing(self, image_path: Path, config, active_issuer_data,
                                   pro_handler, original_status_logo_pil) -> Tuple[Image.Image, bytes]:
        """
        Load and process image (apply watermarks if configured).

        Args:
            image_path: Path to the image file
            config: AppConfig instance with signing settings
            active_issuer_data: Current issuer data dict
            pro_handler: ProFeatures handler (optional, for watermarking)
            original_status_logo_pil: PIL Image for logo watermarking

        Returns:
            Tuple[processed_PIL_image, jpeg_bytes]
        """
        try:
            source_image = Image.open(image_path)
            processed_image = source_image

            # Apply watermarks if enabled and licensed
            if config.apply_watermark or config.apply_logo_watermark:
                logging.info(f"[SIGNING] Watermark config: apply_text={config.apply_watermark}, apply_logo={config.apply_logo_watermark}")

                if not self.license_manager:
                    logging.warning("[SIGNING] Watermark skipped: license_manager is None")
                elif not self.license_manager.is_feature_enabled(FEATURE_WATERMARK):
                    logging.warning("[SIGNING] Watermark skipped: FEATURE_WATERMARK not enabled in license")
                elif not pro_handler:
                    logging.warning("[SIGNING] Watermark skipped: pro_handler is None")
                else:
                    logging.info("[SIGNING] License and pro_handler OK, applying watermarks...")

                    if config.apply_watermark:
                        logging.info(f"[SIGNING] Applying text watermark: '{config.watermark_text}'")
                        processed_image = pro_handler.image_processor.apply_text_watermark(
                            processed_image, config.watermark_text
                        )

                    if config.apply_logo_watermark:
                        logging.info(f"[SIGNING] Applying logo watermark (logo={'present' if original_status_logo_pil else 'None'})")
                        processed_image = pro_handler.image_processor.apply_logo_watermark(
                            processed_image, original_status_logo_pil
                        )
            else:
                logging.debug("[SIGNING] No watermarks configured")

            # Convert to RGB JPEG
            final_image = processed_image.convert("RGB")
            image_buffer = io.BytesIO()
            final_image.save(image_buffer, format="JPEG", quality=95)

            return final_image, image_buffer.getvalue()

        except Exception as e:
            logging.error(f"[SIGNING] Image preparation failed: {e}")
            raise

    def _generate_filename_stem(self, image_path: Path, config) -> str:
        """
        Generate the base filename for the LKY file.

        Args:
            image_path: Original image path
            config: AppConfig instance with signing settings

        Returns:
            Sanitized filename stem with optional random suffix
        """
        sanitized = self._sanitize_filename(image_path.stem)

        if config.randomize_lkey_name:
            suffix = f"-{''.join(random.choices(string.ascii_lowercase + string.digits, k=4))}"
            return f"{sanitized}{suffix}"

        return sanitized

    def _sanitize_filename(self, filename: str) -> str:
        """Remove problematic characters from filename."""
        return "".join(c if c.isalnum() or c in ('-', '_', '.') else '_' for c in filename)

    # ========================================================================
    # LKY FILE ASSEMBLY
    # ========================================================================

    def _build_lky_payload(self, image_bytes: bytes, filename: str,
                           details: dict) -> Tuple[bytes, dict, bytes]:
        """
        Build the LKY payload (image + JSON metadata).

        Args:
            image_bytes: JPEG image bytes
            filename: LKY filename
            details: Metadata dict {"m": message, "n": doc number, etc.}

        Returns:
            Tuple[data_to_sign, payload_dict, payload_bytes]
        """
        payload_dict = {
            "imgId": filename,
            "message": details.get("m"),
            "docDate": datetime.date.today().isoformat(),
            "docNumber": details.get("n"),
        }
        # Remove None values
        payload_dict = {k: v for k, v in payload_dict.items() if v is not None}

        payload_bytes = json.dumps(payload_dict, separators=(",", ":")).encode("utf-8")
        data_to_sign = image_bytes + payload_bytes

        return data_to_sign, payload_dict, payload_bytes

    def _assemble_lky_binary(self, data_to_sign: bytes, image_bytes: bytes,
                            payload_dict: dict, payload_bytes: bytes,
                            active_issuer_id: str, active_issuer_data: dict) -> bytes:
        """
        Sign the payload and assemble the final LKY binary.

        Args:
            data_to_sign: Image + payload bytes to sign
            image_bytes: Original image bytes
            payload_dict: Metadata dict
            payload_bytes: Serialized metadata bytes
            active_issuer_id: Current issuer ID
            active_issuer_data: Current issuer data dict with private key

        Returns:
            Complete LKY file bytes
        """
        # Sign with private key
        key_location = active_issuer_data.get("priv_key_pem")
        signature_b58 = self._sign_data(
            active_issuer_id, key_location, data_to_sign, encode='b58'
        )

        # Build manifest
        manifest_dict = {
            "signature": signature_b58,
            "issuerId": active_issuer_id,
            "imageLength": len(image_bytes),
            "payloadLength": len(payload_bytes),
            "imageMimeType": "image/jpeg",
        }

        # Assemble final LKY binary
        return self.crypto_manager.assemble_lky_file(image_bytes, payload_dict, manifest_dict)

    # ========================================================================
    # FILE OPERATIONS
    # ========================================================================

    def _save_to_temp_location(self, filename: str, lky_bytes: bytes) -> Tuple[Path, Path]:
        """
        Save LKY to temporary directory for hashing.

        Args:
            filename: LKY filename
            lky_bytes: Complete LKY file bytes

        Returns:
            Tuple[temp_dir_path, file_path]
        """
        from models.config import APP_DATA_DIR

        temp_dir = APP_DATA_DIR / "temp_upload"
        temp_dir.mkdir(exist_ok=True, parents=True)
        temp_path = temp_dir / filename
        temp_path.write_bytes(lky_bytes)

        return temp_dir, temp_path

    def _finalize_save(self, temp_lky_path: Path, qr_image: Image.Image, config) -> Path:
        """
        Move LKY from temp to final location and save QR code.

        Args:
            temp_lky_path: Temporary LKY file path
            qr_image: Generated QR code PIL Image
            config: AppConfig instance with signing settings

        Returns:
            Path to the final saved LKY file
        """
        now = datetime.datetime.now()
        local_save_dir = Path(config.legato_files_save_path) / f"{now.year}" / f"{now.month:02d}"
        local_save_dir.mkdir(parents=True, exist_ok=True)

        # Move LKY from temp to final location
        final_lky_path = local_save_dir / temp_lky_path.name
        logging.info(f"[SIGNING] Copying temp file from {temp_lky_path} to {final_lky_path}")
        shutil.copy(temp_lky_path, final_lky_path)

        # Verify the file was actually copied
        if final_lky_path.exists():
            logging.info(f"[SIGNING] ✓ LKY file successfully saved: {final_lky_path}")
        else:
            logging.error(f"[SIGNING] ✗ FAILED to save LKY file: {final_lky_path}")

        # Save QR code
        qr_save_path = local_save_dir / f"{temp_lky_path.stem}-QR.png"
        logging.info(f"[SIGNING] Saving QR code to: {qr_save_path}")
        qr_image.save(qr_save_path)

        if qr_save_path.exists():
            logging.info(f"[SIGNING] ✓ QR file successfully saved: {qr_save_path}")
        else:
            logging.error(f"[SIGNING] ✗ FAILED to save QR file: {qr_save_path}")

        logging.info(f"[SIGNING] Files saved: {final_lky_path}")
        return final_lky_path

    # ========================================================================
    # QR CODE & PAYLOAD
    # ========================================================================

    def _generate_qr_with_legatokey_logo(self, qr_data: str) -> Image.Image:
        """
        Generate QR code with legatokey.png logo embedded.

        Args:
            qr_data: QR code data string

        Returns:
            PIL Image with QR code and embedded logo
        """
        from models.utils import resource_path

        doc_logo_path = resource_path("legatokey.png")
        document_logo_pil = Image.open(doc_logo_path) if doc_logo_path.exists() else None

        if document_logo_pil:
            logging.info(f"[SIGNING] Embedding legatokey.png logo in QR code")
        else:
            logging.warning(f"[SIGNING] legatokey.png not found, generating QR without logo")

        return self.image_processor.generate_qr_with_logo(qr_data, document_logo_pil, sizing_ratio=0.39)

    def _build_qr_payload(self, filename_stem: str, file_hash_hex: str,
                         details: dict, active_issuer_id: str, active_issuer_data: dict) -> str:
        """
        Build and sign the QR code payload (CBOR/ZLIB/B45 encoded).

        Args:
            filename_stem: LKY filename without extension
            file_hash_hex: SHA256 hash of the LKY file (hex string)
            details: Metadata dict
            active_issuer_id: Current issuer ID
            active_issuer_data: Current issuer data dict with private key

        Returns:
            QR payload string in format "ISSUERID:B45_ENCODED_DATA"
        """
        hash_bytes = bytes.fromhex(file_hash_hex)
        qr_payload_dict = {"i": filename_stem, "h": hash_bytes, **details}

        # CBOR encode
        qr_payload_bytes = cbor2.dumps(qr_payload_dict)

        # ZLIB compress (level 9)
        compressor = zlib.compressobj(level=9, wbits=-15)
        qr_compressed_bytes = compressor.compress(qr_payload_bytes) + compressor.flush()

        # Sign with private key
        key_location = active_issuer_data.get("priv_key_pem")
        qr_signature_bytes = self._sign_data(
            active_issuer_id, key_location, qr_compressed_bytes, encode='raw'
        )

        # B45 encode
        binary_to_encode = qr_compressed_bytes + qr_signature_bytes
        payload_b45 = base45.b45encode(binary_to_encode).decode('ascii')

        return f"{active_issuer_id.upper()}:{payload_b45}"

    # ========================================================================
    # DATABASE LOGGING
    # ========================================================================

    def _log_to_insights_db(self, filename: str, insights_db):
        """
        Log the certificate creation to InsightsDB (if available).

        Args:
            filename: LKY filename
            insights_db: InsightsDB instance (optional, for certificate logging)
        """
        if not insights_db:
            logging.debug("[SIGNING] InsightsDB not available, skipping certificate logging")
            return

        try:
            logging.info(f"[SIGNING] Logging certificate to InsightsDB: {filename}")
            insights_db.create_certificate(filename)
            logging.info(f"[SIGNING] Certificate logged successfully")
        except Exception as e:
            logging.error(f"[SIGNING] Failed to log to InsightsDB: {e}", exc_info=True)
