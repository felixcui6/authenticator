"""TOTP / HOTP，实现依据 RFC 4226 与 RFC 6238。"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
import struct
import time
import uuid
from dataclasses import dataclass
from urllib.parse import parse_qs, quote, unquote, urlencode, urlparse

DIGESTS = {
    "SHA1": hashlib.sha1,
    "SHA256": hashlib.sha256,
    "SHA512": hashlib.sha512,
}

_BASE32_ALPHABET = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")


def hotp(key: bytes, counter: int, digits: int, digest) -> str:
    """RFC 4226 动态截断，生成固定位数的一次性口令。"""
    if counter < 0:
        raise ValueError("系统时间无效")
    msg = struct.pack(">Q", counter)
    mac = hmac.new(key, msg, digest).digest()
    offset = mac[-1] & 0x0F
    binary = struct.unpack(">I", mac[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(binary % (10**digits)).zfill(digits)


def generate_secret() -> str:
    """生成 160 位随机密钥，Base32，可直接交给验证器使用。"""
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def normalize_secret(secret: str) -> str:
    """去掉空格和连字符，校验并补齐 Base32。"""
    cleaned = secret.replace("\u200b", "").replace("\ufeff", "")
    cleaned = re.sub(r"[\s\-]+", "", cleaned).upper().rstrip("=")
    if not cleaned:
        raise ValueError("请填写密钥")
    invalid = sorted({ch for ch in cleaned if ch not in _BASE32_ALPHABET})
    if invalid:
        shown = "".join(invalid[:8])
        raise ValueError(
            f"密钥含有无效字符「{shown}」。Base32 只使用字母 A–Z 和数字 2–7，不含 0、1、8、9"
        )
    if len(cleaned) < 8:
        raise ValueError("密钥太短，请确认已经完整复制")
    padded = cleaned + ("=" * ((8 - len(cleaned) % 8) % 8))
    try:
        raw = base64.b32decode(padded, casefold=True)
    except Exception as exc:
        raise ValueError("密钥无法解码，请检查是否复制完整") from exc
    if not raw:
        raise ValueError("密钥无法解码，请检查是否复制完整")
    return padded


def format_code(code: str) -> str:
    """6 位显示为 123 456，8 位显示为 1234 5678。复制时仍使用纯数字。"""
    if len(code) >= 4 and len(code) % 2 == 0:
        mid = len(code) // 2
        return f"{code[:mid]} {code[mid:]}"
    return code


@dataclass
class Account:
    id: str
    name: str
    issuer: str
    secret: str
    digits: int = 6
    period: int = 30
    algorithm: str = "SHA1"
    invalid_reason: str = ""

    @property
    def title(self) -> str:
        if self.issuer.strip():
            return self.issuer.strip()
        if self.name.strip():
            return self.name.strip()
        return "未命名账号"

    @property
    def subtitle(self) -> str:
        if self.issuer.strip() and self.name.strip():
            return self.name.strip()
        return ""

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "issuer": self.issuer,
            "secret": self.secret,
            "digits": self.digits,
            "period": self.period,
            "algorithm": self.algorithm,
        }

    @classmethod
    def create(
        cls,
        name: str,
        issuer: str,
        secret: str,
        digits: int = 6,
        period: int = 30,
        algorithm: str = "SHA1",
    ) -> Account:
        algorithm = algorithm.upper().replace("-", "")
        if algorithm not in DIGESTS:
            raise ValueError("算法只支持 SHA1、SHA256、SHA512")
        if digits not in (6, 7, 8):
            raise ValueError("位数只支持 6、7、8")
        if not 5 <= int(period) <= 300:
            raise ValueError("刷新周期需在 5 到 300 秒之间")
        return cls(
            id=str(uuid.uuid4()),
            name=name.strip(),
            issuer=issuer.strip(),
            secret=normalize_secret(secret),
            digits=int(digits),
            period=int(period),
            algorithm=algorithm,
        )

    @classmethod
    def from_dict(cls, data: dict) -> Account:
        reason = ""
        raw_secret = str(data.get("secret") or "")
        try:
            secret = normalize_secret(raw_secret)
        except ValueError as exc:
            secret = raw_secret
            reason = str(exc)

        algorithm = str(data.get("algorithm") or "SHA1").upper().replace("-", "")
        if algorithm not in DIGESTS:
            reason = reason or "不支持的算法"
            algorithm = "SHA1"

        try:
            digits = int(data.get("digits") or 6)
        except (TypeError, ValueError):
            digits = 6
        if digits not in (6, 7, 8):
            digits = 6

        try:
            period = int(data.get("period") or 30)
        except (TypeError, ValueError):
            period = 30
        if not 5 <= period <= 300:
            period = 30

        return cls(
            id=str(data.get("id") or uuid.uuid4()),
            name=str(data.get("name") or ""),
            issuer=str(data.get("issuer") or ""),
            secret=secret,
            digits=digits,
            period=period,
            algorithm=algorithm,
            invalid_reason=reason,
        )


def current_code(account: Account, timestamp: float | None = None) -> tuple[str, int]:
    """返回 (纯数字验证码, 本周期剩余秒数)。"""
    if account.invalid_reason:
        raise ValueError(account.invalid_reason)
    if account.algorithm not in DIGESTS:
        raise ValueError("不支持的算法")
    if timestamp is None:
        timestamp = time.time()
    counter = int(timestamp) // account.period
    try:
        key = base64.b32decode(account.secret, casefold=True)
        code = hotp(key, counter, account.digits, DIGESTS[account.algorithm])
    except Exception:
        raise ValueError("无法生成验证码，请检查密钥") from None
    remaining = account.period - (int(timestamp) % account.period)
    if remaining <= 0:
        remaining = account.period
    return code, remaining


def provisioning_uri(account: Account) -> str:
    """生成 otpauth 迁移链接。链接中包含密钥。"""
    label_name = (account.name.strip() or account.title).replace(":", " ")
    if account.issuer.strip():
        label = f"{account.issuer.strip()}:{label_name}"
    else:
        label = label_name
    query = {
        "secret": account.secret.rstrip("="),
        "algorithm": account.algorithm,
        "digits": str(account.digits),
        "period": str(account.period),
    }
    if account.issuer.strip():
        query["issuer"] = account.issuer.strip()
    return "otpauth://totp/" + quote(label, safe=":") + "?" + urlencode(query)


@dataclass
class ParsedOTP:
    name: str
    issuer: str
    secret: str
    digits: int
    period: int
    algorithm: str


def parse_otpauth(uri: str) -> ParsedOTP:
    compact = re.sub(r"\s+", "", uri.strip())
    lower = compact.lower()
    index = lower.find("otpauth://")
    if index < 0:
        raise ValueError("请粘贴 otpauth:// 链接或密钥")
    parsed = urlparse(compact[index:])
    kind = parsed.netloc.lower()
    if kind == "hotp":
        raise ValueError("暂不支持计数型（HOTP）验证码，请使用基于时间的 TOTP")
    if kind != "totp":
        raise ValueError("无法识别的链接，请粘贴 otpauth://totp/ 链接或密钥")

    label = unquote(parsed.path.lstrip("/"))
    issuer_from_label = ""
    name = label.strip()
    if ":" in label:
        issuer_from_label, name = label.split(":", 1)
        issuer_from_label = issuer_from_label.strip()
        name = name.strip()

    query = parse_qs(parsed.query, keep_blank_values=False)
    secret = (query.get("secret") or [""])[0]
    if not secret:
        raise ValueError("链接中没有密钥")
    issuer = ((query.get("issuer") or [""])[0] or issuer_from_label).strip()
    algorithm = ((query.get("algorithm") or ["SHA1"])[0] or "SHA1").upper().replace("-", "")
    if algorithm not in DIGESTS:
        raise ValueError("链接中的算法不受支持")
    try:
        digits = int((query.get("digits") or ["6"])[0])
        period = int((query.get("period") or ["30"])[0])
    except ValueError as exc:
        raise ValueError("链接中的位数或周期无效") from exc
    if digits not in (6, 7, 8):
        raise ValueError("位数只支持 6、7、8")
    if not 5 <= period <= 300:
        raise ValueError("刷新周期需在 5 到 300 秒之间")
    return ParsedOTP(
        name=name,
        issuer=issuer,
        secret=normalize_secret(secret),
        digits=digits,
        period=period,
        algorithm=algorithm,
    )


def account_from_input(
    name: str,
    issuer: str,
    secret_text: str,
    digits: int,
    period: int,
    algorithm: str,
) -> Account:
    text = secret_text.strip()
    if not text:
        raise ValueError("请填写密钥")
    compact = re.sub(r"\s+", "", text)
    if "otpauth://" in compact.lower():
        parsed = parse_otpauth(compact)
        return Account.create(
            name=name.strip() or parsed.name,
            issuer=issuer.strip() or parsed.issuer,
            secret=parsed.secret,
            digits=parsed.digits,
            period=parsed.period,
            algorithm=parsed.algorithm,
        )
    return Account.create(
        name=name,
        issuer=issuer,
        secret=text,
        digits=digits,
        period=period,
        algorithm=algorithm,
    )
