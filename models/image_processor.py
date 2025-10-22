# models/image_processor.py
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
import logging
from pathlib import Path
from typing import Union

from PIL import Image, ImageDraw, ImageFont

try:
    import qrcode
    QRCODE_AVAILABLE = True
except ImportError:
    QRCODE_AVAILABLE = False


class ImageProcessor:
    """ all image manipulation tasks like watermarking and QR code generation."""
    def __init__(self, checkmark_icon_path: Union[Path, None]):
        self.resample_method = Image.Resampling.LANCZOS if hasattr(Image, "Resampling") else Image.LANCZOS
        self.checkmark_icon_pil = None
        if checkmark_icon_path and checkmark_icon_path.exists():
            try:
                self.checkmark_icon_pil = Image.open(checkmark_icon_path).convert("RGBA")
            except Exception as e:
                logging.warning(f"Could not load checkmark icon '{checkmark_icon_path}'. Error: {e}")

    def apply_text_watermark(self, image_pil: Image.Image, text: str, apply: bool) -> Image.Image:
        # Mockup 
        if apply:
            logging.warning("Text watermarking is a Pro feature.")
        return image_pil

    def apply_logo_watermark(self, image_pil: Image.Image, logo_pil: Union[Image.Image, None], apply: bool) -> Image.Image:
        # Mockup
        if apply:
            logging.warning("Logo watermarking is a Pro feature.")
        return image_pil

    def overlay_checkmark(self, background_pil: Image.Image, scale_ratio: float = 0.8) -> Image.Image:
        if not background_pil or not self.checkmark_icon_pil: return background_pil
        background = background_pil.copy().convert("RGBA")
        overlay = self.checkmark_icon_pil
        target_width = int(background.width * scale_ratio)
        target_height = int(target_width * (overlay.height / overlay.width))
        overlay_resized = overlay.resize((target_width, target_height), self.resample_method)
        offset = ((background.width - overlay_resized.width) // 2, (background.height - overlay_resized.height) // 2)
        background.paste(overlay_resized, offset, mask=overlay_resized)
        return background

    def generate_qr_with_logo(self, data: str, logo_pil: Union[Image.Image, None], box_size: int = 10, sizing_ratio: float = 0.28) -> Image.Image:
        if not QRCODE_AVAILABLE:
            logging.error("The 'qrcode' library is required to generate QR codes.")
            return Image.new('RGB', (200, 200), color = 'red')

        qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_H, box_size=box_size, border=4)
        qr.add_data(data)
        qr.make(fit=True)
        qr_img = qr.make_image(fill_color="black", back_color="white").convert("RGBA")
        if logo_pil:
            logo_resized = logo_pil.copy().convert("RGBA")
            logo_max_size = (int(qr_img.width * sizing_ratio), int(qr_img.height * sizing_ratio))
            logo_resized.thumbnail(logo_max_size, self.resample_method)
            pos = ((qr_img.width - logo_resized.width) // 2, (qr_img.height - logo_resized.height) // 2)
            qr_img.paste(logo_resized, pos, mask=logo_resized)
        return qr_img.convert("RGB")

