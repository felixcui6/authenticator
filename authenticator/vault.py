"""账号保险箱：本机 DPAPI 直接打开，同时用密码保护，便于换电脑。"""

from __future__ import annotations

import ctypes
import hashlib
import json
import logging
import os
import secrets
import struct
import sys
from ctypes import wintypes
from datetime import datetime
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from authenticator.core import Account

log = logging.getLogger(__name__)

BACKUP_MAGIC = b"GAUB"
BACKUP_VERSION = 1
BACKUP_AAD = b"PCAuthenticator backup v1"
VAULT_MAGIC = b"GAVL"
VAULT_VERSION = 2
KEY_AAD = b"PCAuthenticator vault key v2"
DATA_AAD = b"PCAuthenticator vault data v2"
PBKDF2_ROUNDS = 200_000
_MAX_ACCOUNTS = 500
_DATA_KEY_LEN = 32
MIN_VAULT_PASSWORD = 4
_WRAP_LEN = _DATA_KEY_LEN + 16
_VAULT_PREFIX = 4 + 1 + 16 + 12 + _WRAP_LEN

CRYPTPROTECT_UI_FORBIDDEN = 0x1


class VaultError(Exception):
    """本机账号文件无法读取。"""


class NeedsPassword(Exception):
    """换到另一台电脑后，需要用保险箱密码解锁一次。"""


class InvalidPassword(Exception):
    """保险箱密码不正确。"""


class InvalidBackup(Exception):
    """备份文件无法用给出的密码打开。"""


class DATA_BLOB(ctypes.Structure):
    _fields_ = [
        ("cbData", wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_byte)),
    ]


_crypt32 = ctypes.windll.crypt32
_kernel32 = ctypes.windll.kernel32

_crypt32.CryptProtectData.argtypes = [
    ctypes.POINTER(DATA_BLOB),
    wintypes.LPCWSTR,
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_void_p,
    wintypes.DWORD,
    ctypes.POINTER(DATA_BLOB),
]
_crypt32.CryptProtectData.restype = wintypes.BOOL
_crypt32.CryptUnprotectData.argtypes = [
    ctypes.POINTER(DATA_BLOB),
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_void_p,
    wintypes.DWORD,
    ctypes.POINTER(DATA_BLOB),
]
_crypt32.CryptUnprotectData.restype = wintypes.BOOL
_kernel32.LocalFree.argtypes = [ctypes.c_void_p]
_kernel32.LocalFree.restype = ctypes.c_void_p


def program_dir() -> Path:
    """打包后的 exe 所在目录；用源码运行时则是项目目录。"""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent


def default_vault_path() -> Path:
    path = program_dir() / "vault.bin"
    appdata = os.environ.get("APPDATA")
    legacy = Path(appdata) / "PCAuthenticator" / "vault.bin" if appdata else None
    if path.exists() or legacy is None or not legacy.exists():
        return path
    if path.resolve() == legacy.resolve():
        return path
    temporary = path.with_name("vault.migrate")
    try:
        temporary.write_bytes(legacy.read_bytes())
        os.replace(temporary, path)
        legacy.unlink()
    except OSError:
        log.warning("could not move the previous vault next to the program")
        temporary.unlink(missing_ok=True)
    return path


def _blob_from(data: bytes) -> tuple[DATA_BLOB, ctypes.Array]:
    # c_byte 会保留中间的 NUL。c_char 缓冲区会在 NUL 处截断，不能用来装密文。
    raw = (ctypes.c_byte * len(data)).from_buffer_copy(data)
    blob = DATA_BLOB(len(data), ctypes.cast(raw, ctypes.POINTER(ctypes.c_byte)))
    return blob, raw


def _copy_and_free(blob: DATA_BLOB) -> bytes:
    try:
        return ctypes.string_at(blob.pbData, blob.cbData)
    finally:
        _kernel32.LocalFree(ctypes.cast(blob.pbData, ctypes.c_void_p))


def protect(data: bytes) -> bytes:
    """用当前 Windows 用户的 DPAPI 加密。其他用户和其他电脑无法解密。"""
    source, _keep = _blob_from(data)
    output = DATA_BLOB()
    ok = _crypt32.CryptProtectData(
        ctypes.byref(source),
        "PCAuthenticator",
        None,
        None,
        None,
        CRYPTPROTECT_UI_FORBIDDEN,
        ctypes.byref(output),
    )
    if not ok:
        raise ctypes.WinError()
    return _copy_and_free(output)


def unprotect(data: bytes) -> bytes:
    source, _keep = _blob_from(data)
    output = DATA_BLOB()
    ok = _crypt32.CryptUnprotectData(
        ctypes.byref(source),
        None,
        None,
        None,
        None,
        CRYPTPROTECT_UI_FORBIDDEN,
        ctypes.byref(output),
    )
    if not ok:
        raise ctypes.WinError()
    return _copy_and_free(output)


def _dump_accounts(accounts: list[Account]) -> bytes:
    payload = {
        "version": 1,
        "accounts": [account.to_dict() for account in accounts],
    }
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def _load_accounts(payload: bytes) -> list[Account]:
    try:
        data = json.loads(payload.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("账号数据格式无效") from exc
    if not isinstance(data, dict) or data.get("version") != 1:
        raise ValueError("账号数据版本无法识别")
    raw_accounts = data.get("accounts")
    if not isinstance(raw_accounts, list):
        raise ValueError("账号数据格式无效")
    if len(raw_accounts) > _MAX_ACCOUNTS:
        raise ValueError("账号数量异常")
    accounts: list[Account] = []
    for item in raw_accounts:
        if not isinstance(item, dict):
            log.warning("skipped a non-object account entry")
            continue
        try:
            accounts.append(Account.from_dict(item))
        except Exception:
            log.warning("skipped an unreadable account entry")
    return accounts


def _derive_password_key(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PBKDF2_ROUNDS, dklen=_DATA_KEY_LEN
    )


def _wrap_data_key(password: str, data_key: bytes) -> tuple[bytes, bytes, bytes]:
    if len(password) < MIN_VAULT_PASSWORD:
        raise ValueError(f"保险箱密码至少 {MIN_VAULT_PASSWORD} 位")
    salt = os.urandom(16)
    nonce = os.urandom(12)
    wrapped = AESGCM(_derive_password_key(password, salt)).encrypt(nonce, data_key, KEY_AAD)
    return salt, nonce, wrapped


def _unwrap_data_key(password: str, salt: bytes, nonce: bytes, wrapped: bytes) -> bytes:
    if not password:
        raise InvalidPassword("请输入保险箱密码")
    try:
        return AESGCM(_derive_password_key(password, salt)).decrypt(nonce, wrapped, KEY_AAD)
    except Exception:
        raise InvalidPassword("密码不正确") from None


def _encrypt_accounts(data_key: bytes, accounts: list[Account]) -> tuple[bytes, bytes]:
    nonce = os.urandom(12)
    ciphertext = AESGCM(data_key).encrypt(nonce, _dump_accounts(accounts), DATA_AAD)
    return nonce, ciphertext


def _decrypt_accounts(data_key: bytes, nonce: bytes, ciphertext: bytes) -> list[Account]:
    try:
        payload = AESGCM(data_key).decrypt(nonce, ciphertext, DATA_AAD)
        return _load_accounts(payload)
    except Exception:
        raise VaultError("保险箱文件已损坏") from None


def _pack_vault(
    salt: bytes,
    password_nonce: bytes,
    password_wrap: bytes,
    local_wrap: bytes,
    data_nonce: bytes,
    ciphertext: bytes,
) -> bytes:
    return b"".join(
        (
            VAULT_MAGIC,
            bytes([VAULT_VERSION]),
            salt,
            password_nonce,
            password_wrap,
            struct.pack("<I", len(local_wrap)),
            local_wrap,
            data_nonce,
            ciphertext,
        )
    )


def _parse_vault(blob: bytes) -> tuple[bytes, bytes, bytes, bytes, bytes, bytes]:
    if len(blob) < _VAULT_PREFIX + 4 + 12 + 16 or not blob.startswith(VAULT_MAGIC):
        raise ValueError("not a password vault")
    if blob[4] != VAULT_VERSION:
        raise VaultError("无法识别的保险箱版本")
    offset = 5
    salt = blob[offset : offset + 16]
    offset += 16
    password_nonce = blob[offset : offset + 12]
    offset += 12
    password_wrap = blob[offset : offset + _WRAP_LEN]
    offset += _WRAP_LEN
    local_len = struct.unpack_from("<I", blob, offset)[0]
    offset += 4
    if local_len <= 0 or local_len > 1_000_000 or offset + local_len + 12 >= len(blob):
        raise VaultError("保险箱文件已损坏")
    local_wrap = blob[offset : offset + local_len]
    offset += local_len
    data_nonce = blob[offset : offset + 12]
    offset += 12
    return salt, password_nonce, password_wrap, local_wrap, data_nonce, blob[offset:]


def disable_local_wrap(blob: bytes) -> bytes:
    """破坏本机 DPAPI 包装，用来模拟把保险箱拷到另一台电脑。"""
    data = bytearray(blob)
    _parse_vault(bytes(data))
    data[_VAULT_PREFIX + 4] ^= 0xFF
    return bytes(data)


class Vault:
    def __init__(self, path: Path | None = None):
        if path is None:
            override = os.environ.get("AUTHENTICATOR_VAULT")
            path = Path(override) if override else default_vault_path()
        self.path = path
        self.has_password = False
        self._data_key: bytes | None = None
        self._salt: bytes | None = None
        self._password_nonce: bytes | None = None
        self._password_wrap: bytes | None = None
        self._sealed: tuple[bytes, bytes, bytes, bytes, bytes, bytes] | None = None

    @property
    def can_reset_password(self) -> bool:
        """本机已经解开数据密钥时，可以不输入旧密码而重设。"""
        return self._data_key is not None

    def _reset_crypto(self) -> None:
        self.has_password = False
        self._data_key = None
        self._salt = None
        self._password_nonce = None
        self._password_wrap = None
        self._sealed = None

    def _remember_password_wrap(self, salt: bytes, nonce: bytes, wrapped: bytes, data_key: bytes) -> None:
        self._data_key = data_key
        self._salt = salt
        self._password_nonce = nonce
        self._password_wrap = wrapped
        self.has_password = True
        self._sealed = None

    def load(self) -> list[Account]:
        self._reset_crypto()
        if not self.path.exists():
            return []
        blob = self.path.read_bytes()
        if blob.startswith(VAULT_MAGIC):
            return self._load_dual(blob)
        try:
            payload = unprotect(blob)
            return _load_accounts(payload)
        except Exception as exc:
            log.warning("vault decrypt failed: %s", type(exc).__name__)
            raise VaultError("无法解密已保存的账号") from None

    def _load_dual(self, blob: bytes) -> list[Account]:
        try:
            sealed = _parse_vault(blob)
        except ValueError:
            raise VaultError("保险箱文件已损坏") from None
        salt, password_nonce, password_wrap, local_wrap, data_nonce, ciphertext = sealed
        try:
            data_key = unprotect(local_wrap)
            if len(data_key) != _DATA_KEY_LEN:
                raise VaultError("local key length")
            accounts = _decrypt_accounts(data_key, data_nonce, ciphertext)
        except Exception:
            self._sealed = sealed
            self.has_password = True
            log.info("local protection did not open the vault")
            raise NeedsPassword("请输入保险箱密码") from None
        self._remember_password_wrap(salt, password_nonce, password_wrap, data_key)
        return accounts

    def unlock(self, password: str) -> list[Account]:
        if self._sealed is None:
            raise VaultError("当前不需要输入密码")
        salt, password_nonce, password_wrap, _local_wrap, data_nonce, ciphertext = self._sealed
        data_key = _unwrap_data_key(password, salt, password_nonce, password_wrap)
        accounts = _decrypt_accounts(data_key, data_nonce, ciphertext)
        self._remember_password_wrap(salt, password_nonce, password_wrap, data_key)
        self._write(accounts)
        return accounts

    def save(self, accounts: list[Account]) -> None:
        if len(accounts) > _MAX_ACCOUNTS:
            raise VaultError("账号数量过多")
        if not self.has_password or self._data_key is None:
            self._write_legacy(accounts)
            return
        self._write(accounts)

    def set_password(self, password: str, accounts: list[Account]) -> None:
        if self.has_password:
            raise VaultError("已经设置过密码，请使用修改密码")
        data_key = os.urandom(_DATA_KEY_LEN)
        salt, nonce, wrapped = _wrap_data_key(password, data_key)
        self._write_dual(data_key, salt, nonce, wrapped, accounts)
        self._remember_password_wrap(salt, nonce, wrapped, data_key)

    def change_password(self, current: str, new: str, accounts: list[Account]) -> None:
        if not self.verify_password(current):
            raise InvalidPassword("当前密码不正确")
        if current == new:
            raise ValueError("新密码与当前密码相同")
        if self._data_key is None:
            raise VaultError("请先解锁保险箱")
        salt, nonce, wrapped = _wrap_data_key(new, self._data_key)
        self._write_dual(self._data_key, salt, nonce, wrapped, accounts)
        self._remember_password_wrap(salt, nonce, wrapped, self._data_key)

    def reset_password(self, password: str, accounts: list[Account]) -> None:
        """本机已经能解密时，不核对旧密码，直接换成新密码。"""
        if self._data_key is None:
            raise VaultError("这台电脑还不能解密保险箱，无法重设密码")
        salt, nonce, wrapped = _wrap_data_key(password, self._data_key)
        self._write_dual(self._data_key, salt, nonce, wrapped, accounts)
        self._remember_password_wrap(salt, nonce, wrapped, self._data_key)

    def verify_password(self, password: str) -> bool:
        if not self.has_password or self._password_wrap is None or self._salt is None or self._password_nonce is None:
            raise VaultError("还没有设置密码")
        try:
            key = _unwrap_data_key(password, self._salt, self._password_nonce, self._password_wrap)
        except InvalidPassword:
            return False
        if self._data_key is None:
            return True
        return secrets.compare_digest(key, self._data_key)

    def _write_legacy(self, accounts: list[Account]) -> None:
        self._commit(protect(_dump_accounts(accounts)))

    def _write(self, accounts: list[Account]) -> None:
        if (
            self._data_key is None
            or self._salt is None
            or self._password_nonce is None
            or self._password_wrap is None
        ):
            raise VaultError("保险箱还没有设置密码")
        self._write_dual(self._data_key, self._salt, self._password_nonce, self._password_wrap, accounts)

    def _write_dual(
        self,
        data_key: bytes,
        salt: bytes,
        password_nonce: bytes,
        password_wrap: bytes,
        accounts: list[Account],
    ) -> None:
        if len(accounts) > _MAX_ACCOUNTS:
            raise VaultError("账号数量过多")
        data_nonce, ciphertext = _encrypt_accounts(data_key, accounts)
        blob = _pack_vault(salt, password_nonce, password_wrap, protect(data_key), data_nonce, ciphertext)
        self._commit(blob)

    def _commit(self, blob: bytes) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(".tmp")
        temporary.write_bytes(blob)
        os.replace(temporary, self.path)
        log.info("saved vault (%s bytes)", len(blob))

    def quarantine(self) -> Path:
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        destination = self.path.with_name(f"vault.bin.broken-{stamp}")
        self.path.replace(destination)
        return destination


def build_backup(accounts: list[Account], password: str) -> bytes:
    if len(password) < 6:
        raise ValueError("备份密码至少 6 位")
    if len(accounts) > _MAX_ACCOUNTS:
        raise ValueError("账号数量过多")
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PBKDF2_ROUNDS, dklen=32
    )
    token = AESGCM(key).encrypt(nonce, _dump_accounts(accounts), BACKUP_AAD)
    return BACKUP_MAGIC + bytes([BACKUP_VERSION]) + salt + nonce + token


def read_backup(blob: bytes, password: str) -> list[Account]:
    if not password:
        raise InvalidBackup("请输入备份密码")
    header = 4 + 1 + 16 + 12
    if len(blob) < header + 16 or not blob.startswith(BACKUP_MAGIC):
        raise InvalidBackup("这不是有效的备份文件")
    if blob[4] != BACKUP_VERSION:
        raise InvalidBackup("无法识别的备份版本")
    if len(blob) > 5_000_000:
        raise InvalidBackup("备份文件过大")
    salt = blob[5:21]
    nonce = blob[21:33]
    token = blob[33:]
    key = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PBKDF2_ROUNDS, dklen=32
    )
    try:
        payload = AESGCM(key).decrypt(nonce, token, BACKUP_AAD)
    except Exception:
        raise InvalidBackup("密码错误，或备份文件已损坏") from None
    try:
        return _load_accounts(payload)
    except ValueError as exc:
        raise InvalidBackup(str(exc)) from None
