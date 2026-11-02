"""从图片或剪贴板读取验证器二维码。"""

from __future__ import annotations

import base64
import io
from pathlib import Path

import zxingcpp
from PIL import Image, ImageGrab, UnidentifiedImageError

_IMAGE_SUFFIXES = {".png", ".jpg", ".jpeg", ".bmp", ".gif", ".webp", ".tif", ".tiff"}

# 公开测试向量对应的二维码，只用于确认解码库可用。
_SAMPLE_TEXT = "otpauth://totp/A:b?secret=JBSWY3DPEHPK3PXP&issuer=A"
_SAMPLE_PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAG8AAABvAQAAAADKvqPNAAABWklEQVR42rVVsW3FIBA9xwUd"
    "WQCJNehYySxg+y9gr0THGkgsEHcUyJdnpUnS3BUJokF6fnr37t2Z+Pu56Q+fg8hNnYjmD6L1jX6c"
    "X08aGztLI/V28RDBi/EvrtaMlJ0C7Kyhjf2lAvvb+LM4DTM4d+OP6JJCM9xI5bmL7Ab8G1vhV2mP"
    "k6LmMF/Z74FSr6KM1PmItFLbw6xgRmn+7FXBzEfApcQAt1ssEMGI6DW9Zxm8Q60ZU0acRDB8o4Wq"
    "xVdRtg6wF8MTTUQZju0BmuG2okBEIvBZiIyseTW0mnYiclHRlId8viMtUWa26HKcr85cZOYpP5G7"
    "cn3vTo5ohxtj4naynI2zgBzDxVeWJ2UNGKt2mEEYRs2kZCDdJjflayP5O9akAD8bKdY10JYVTTF+"
    "j+1EqmXNz0YiWNGrjar1tT0LFcHzCs3YcmQN31G1kRCPI7SDWOHz//wmPgHPPKPpp446HgAAAABJ"
    "RU5ErkJggg=="
)


def decode_qr_image(image: Image.Image) -> str:
    """读出图片中的二维码文本。多个码时优先 otpauth 链接。"""
    prepared = image.convert("RGB")
    try:
        results = zxingcpp.read_barcodes(
            prepared,
            formats=zxingcpp.BarcodeFormat.QRCode,
            try_rotate=True,
            try_downscale=True,
            try_invert=True,
        )
    except Exception as exc:
        raise ValueError("无法识别这张图片里的二维码") from exc
    texts = [(getattr(item, "text", None) or "").strip() for item in results]
    texts = [text for text in texts if text]
    if not texts:
        raise ValueError("没有在图片里识别到二维码")
    for text in texts:
        if "otpauth://" in text.lower():
            return _reject_batch_export(text)
    return _reject_batch_export(texts[0])


def decode_qr_file(path: str | Path) -> str:
    try:
        with Image.open(path) as image:
            image.load()
            return decode_qr_image(image)
    except UnidentifiedImageError as exc:
        raise ValueError("打不开这张图片，请换 png、jpg 或 bmp") from exc
    except OSError as exc:
        raise ValueError(f"打不开这张图片：{exc}") from exc


def image_from_clipboard() -> Image.Image | None:
    """剪贴板里的位图，或复制的图片文件。没有图片时返回 None。"""
    try:
        data = ImageGrab.grabclipboard()
    except Exception:
        return None
    if isinstance(data, Image.Image):
        return data
    if isinstance(data, list):
        for item in data:
            candidate = Path(str(item))
            if candidate.suffix.lower() not in _IMAGE_SUFFIXES or not candidate.is_file():
                continue
            try:
                image = Image.open(candidate)
                image.load()
                return image
            except (OSError, UnidentifiedImageError):
                continue
    return None


def decoder_self_check() -> bool:
    with Image.open(io.BytesIO(_SAMPLE_PNG)) as image:
        return decode_qr_image(image) == _SAMPLE_TEXT


def _reject_batch_export(text: str) -> str:
    if "otpauth-migration://" in text.lower():
        raise ValueError("这是批量导出二维码，目前只能导入单个账号的 otpauth://totp 二维码")
    return text
