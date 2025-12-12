"""
lky_parser.py - Parse .lky certificate files
Reads binary .lky format and extracts certificate data (image + metadata)
No signature verification needed (local files are user-trusted)
"""

import struct
import json
import logging
from io import BytesIO
from pathlib import Path
from PIL import Image

logger = logging.getLogger(__name__)


class LkyParseError(Exception):
    """Exception raised when .lky parsing fails"""
    pass


class LkyFile:
    """
    Parse and extract data from .lky certificate files

    Binary Format:
    [JPEG image bytes] + [payload JSON] + [manifest JSON] + [manifest_length: 4 bytes]

    No signature verification (files are local/trusted)
    """

    def __init__(self, file_bytes: bytes):
        """
        Initialize LkyFile parser with raw file bytes

        Args:
            file_bytes: Raw bytes from .lky file (from disk or HTTP)

        Raises:
            LkyParseError: If parsing fails
        """
        self.file_bytes = file_bytes
        self.file_size = len(file_bytes)
        self.image_pil = None
        self.payload = {}
        self.manifest = {}
        self.image_bytes = None

        if not self._parse():
            raise LkyParseError("Failed to parse .lky file")

    def _parse(self) -> bool:
        """
        Reverse-parse .lky binary format from end of file

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            if len(self.file_bytes) < 4:
                logger.error("File too small to be valid .lky")
                return False

            # Step 1: Read manifest length from last 4 bytes (big-endian)
            manifest_length = struct.unpack('>I', self.file_bytes[-4:])[0]

            if manifest_length <= 0 or manifest_length > self.file_size - 4:
                logger.error(f"Invalid manifest length: {manifest_length}")
                return False

            # Step 2: Extract manifest JSON
            manifest_start = len(self.file_bytes) - 4 - manifest_length
            manifest_json_bytes = self.file_bytes[manifest_start:manifest_start + manifest_length]

            try:
                self.manifest = json.loads(manifest_json_bytes.decode('utf-8'))
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse manifest JSON: {e}")
                return False

            # Step 3: Extract payload JSON using length from manifest
            payload_length = self.manifest.get('payloadLength', 0)
            if payload_length <= 0:
                logger.error("Invalid payload length in manifest")
                return False

            payload_start = manifest_start - payload_length
            if payload_start < 0:
                logger.error("Payload section extends before file start")
                return False

            payload_json_bytes = self.file_bytes[payload_start:payload_start + payload_length]

            try:
                self.payload = json.loads(payload_json_bytes.decode('utf-8'))
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse payload JSON: {e}")
                return False

            # Step 4: Extract image bytes
            image_length = self.manifest.get('imageLength', 0)
            if image_length <= 0:
                logger.error("Invalid image length in manifest")
                return False

            if image_length > payload_start:
                logger.error("Image section extends beyond payload start")
                return False

            self.image_bytes = self.file_bytes[:image_length]

            # Validate JPEG magic bytes
            if not self.image_bytes.startswith(b'\xff\xd8'):
                logger.error("Invalid JPEG magic bytes")
                return False

            # Step 5: Load image to PIL
            try:
                self.image_pil = Image.open(BytesIO(self.image_bytes))
                # Verify it's readable
                self.image_pil.verify()
                # Need to reopen since verify() closes the file
                self.image_pil = Image.open(BytesIO(self.image_bytes))
            except Exception as e:
                logger.error(f"Failed to load image: {e}")
                return False

            logger.info(f"Successfully parsed .lky file ({self.file_size} bytes, "
                       f"image: {image_length}, payload: {payload_length}, manifest: {manifest_length})")
            return True

        except Exception as e:
            logger.error(f"Unexpected error parsing .lky: {e}")
            return False

    def get_certificate_data(self) -> dict:
        """
        Return structured certificate metadata

        Returns:
            dict: Certificate information (filename, date, message, etc.)
        """
        return {
            'filename': self.payload.get('imgId', 'Unknown'),
            'message': self.payload.get('message', ''),
            'date_signed': self.payload.get('docDate', ''),
            'document_number': self.payload.get('docNumber', ''),
            'issuer_id': self.manifest.get('issuerId', ''),
            'image_mime_type': self.manifest.get('imageMimeType', 'image/jpeg'),
            'file_size': self.file_size,
            'image_size': self.manifest.get('imageLength', 0),
            'payload_size': self.manifest.get('payloadLength', 0),
            'manifest_size': len(json.dumps(self.manifest, separators=(",", ":")))
        }

    def get_image(self) -> Image.Image:
        """
        Get PIL Image object

        Returns:
            Image.Image: PIL Image of the certificate
        """
        return self.image_pil

    def get_payload(self) -> dict:
        """Get parsed payload JSON"""
        return self.payload

    def get_manifest(self) -> dict:
        """Get parsed manifest JSON"""
        return self.manifest

    def save_image(self, output_path: Path, format: str = 'PNG') -> bool:
        """
        Save extracted image to disk

        Args:
            output_path: Path to save image
            format: Image format (PNG, JPEG, etc.)

        Returns:
            bool: True if successful
        """
        try:
            self.image_pil.save(output_path, format=format)
            logger.info(f"Saved image to {output_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to save image: {e}")
            return False


if __name__ == "__main__":
    """Test script"""
    import sys
    from urllib.request import urlopen

    logging.basicConfig(level=logging.INFO)

    if len(sys.argv) < 2:
        print("Usage: python lky_parser.py <url_or_path>")
        print("Example: python lky_parser.py https://www.ruederome.com/legatolink/CM1924-468-24bx-x9k0.lky")
        sys.exit(1)

    input_source = sys.argv[1]

    try:
        # Load from URL or file
        if input_source.startswith('http://') or input_source.startswith('https://'):
            print(f"Downloading from: {input_source}")
            with urlopen(input_source) as response:
                file_bytes = response.read()
            print(f"Downloaded {len(file_bytes)} bytes")
        else:
            print(f"Loading from: {input_source}")
            with open(input_source, 'rb') as f:
                file_bytes = f.read()
            print(f"Loaded {len(file_bytes)} bytes")

        # Parse
        print("\nParsing .lky file...")
        lky = LkyFile(file_bytes)

        # Display results
        print("\n[OK] Parse successful!")
        print("\nCertificate Data:")
        cert_data = lky.get_certificate_data()
        for key, value in cert_data.items():
            print(f"  {key}: {value}")

        print("\nPayload JSON:")
        print(f"  {json.dumps(lky.get_payload(), indent=2)}")

        print("\nManifest JSON:")
        print(f"  {json.dumps(lky.get_manifest(), indent=2)}")

        # Show image info
        if lky.get_image():
            img = lky.get_image()
            print(f"\nImage Info:")
            print(f"  Size: {img.size}")
            print(f"  Format: {img.format}")
            print(f"  Mode: {img.mode}")

            # Save to temp file
            import tempfile
            with tempfile.NamedTemporaryFile(suffix='.png', delete=False) as tmp:
                temp_path = Path(tmp.name)
            if lky.save_image(temp_path):
                print(f"  Saved to: {temp_path}")

    except LkyParseError as e:
        print(f"\n[ERROR] Parse Error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n[ERROR] Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
