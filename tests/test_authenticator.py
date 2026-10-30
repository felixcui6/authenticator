"""验证码算法、链接解析、本机保险箱和备份。"""

from __future__ import annotations

import base64
import hashlib
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from authenticator.core import (
    Account,
    account_from_input,
    current_code,
    format_code,
    generate_secret,
    hotp,
    normalize_secret,
    parse_otpauth,
    provisioning_uri,
)
from authenticator import vault as vault_module
from authenticator.vault import (
    InvalidBackup,
    InvalidPassword,
    NeedsPassword,
    Vault,
    VaultError,
    build_backup,
    default_vault_path,
    disable_local_wrap,
    program_dir,
    protect,
    read_backup,
    unprotect,
)


RFC_SEEDS = {
    "SHA1": b"12345678901234567890",
    "SHA256": b"12345678901234567890123456789012",
    "SHA512": b"1234567890123456789012345678901234567890123456789012345678901234",
}

# RFC 6238 附录 B，8 位数字。
RFC_CODES = {
    59: {"SHA1": "94287082", "SHA256": "46119246", "SHA512": "90693936"},
    1111111109: {"SHA1": "07081804", "SHA256": "68084774", "SHA512": "25091201"},
    1111111111: {"SHA1": "14050471", "SHA256": "67062674", "SHA512": "99943326"},
    1234567890: {"SHA1": "89005924", "SHA256": "91819424", "SHA512": "93441116"},
    2000000000: {"SHA1": "69279037", "SHA256": "90698825", "SHA512": "38618901"},
    20000000000: {"SHA1": "65353130", "SHA256": "77737706", "SHA512": "47863826"},
}


class HotpTests(unittest.TestCase):
    def test_rfc4226_vectors(self) -> None:
        key = b"12345678901234567890"
        expected = {
            0: "755224",
            1: "287082",
            2: "359152",
            3: "969429",
            4: "338314",
            5: "254676",
            6: "287922",
            7: "162583",
            8: "399871",
            9: "520489",
        }
        for counter, code in expected.items():
            self.assertEqual(hotp(key, counter, 6, hashlib.sha1), code)


class TotpTests(unittest.TestCase):
    def test_rfc6238_vectors(self) -> None:
        for algorithm, seed in RFC_SEEDS.items():
            secret = base64.b32encode(seed).decode("ascii")
            account = Account.create("rfc", algorithm, secret, digits=8, period=30, algorithm=algorithm)
            for timestamp, codes in RFC_CODES.items():
                code, _remaining = current_code(account, timestamp)
                self.assertEqual(code, codes[algorithm], f"{algorithm} @ {timestamp}")

    def test_period_boundary(self) -> None:
        secret = base64.b32encode(RFC_SEEDS["SHA1"]).decode("ascii")
        account = Account.create("rfc", "SHA1", secret, digits=8)
        code_59, remaining_59 = current_code(account, 59)
        code_60, remaining_60 = current_code(account, 60)
        code_89, remaining_89 = current_code(account, 89)
        self.assertEqual(code_59, "94287082")
        self.assertEqual(remaining_59, 1)
        self.assertEqual(remaining_60, 30)
        self.assertEqual(remaining_89, 1)
        self.assertEqual(code_60, code_89)
        self.assertNotEqual(code_59, code_60)

    def test_format_code(self) -> None:
        self.assertEqual(format_code("123456"), "123 456")
        self.assertEqual(format_code("12345678"), "1234 5678")


class SecretTests(unittest.TestCase):
    def test_generate_secret_can_produce_a_code(self) -> None:
        first = generate_secret()
        second = generate_secret()
        self.assertEqual(len(first), 32)
        self.assertNotEqual(first, second)
        account = Account.create("生成", "本地", first)
        code, remaining = current_code(account)
        self.assertEqual(len(code), 6)
        self.assertGreater(remaining, 0)

    def test_normalize_ignores_case_and_spaces(self) -> None:
        self.assertEqual(normalize_secret("jbsw y3dp ehpk 3pxp"), "JBSWY3DPEHPK3PXP")

    def test_rejects_invalid_characters_and_short_secrets(self) -> None:
        with self.assertRaises(ValueError):
            normalize_secret("ABCD1234")
        with self.assertRaises(ValueError):
            normalize_secret("ABCD")

    def test_parse_otpauth(self) -> None:
        uri = (
            "otpauth://totp/Example:alice@google.com"
            "?secret=JBSWY3DPEHPK3PXP&issuer=Example&algorithm=SHA1&digits=6&period=30"
        )
        parsed = parse_otpauth(uri)
        self.assertEqual(parsed.name, "alice@google.com")
        self.assertEqual(parsed.issuer, "Example")
        self.assertEqual(parsed.secret, "JBSWY3DPEHPK3PXP")

    def test_hotp_uri_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            parse_otpauth("otpauth://hotp/A?secret=JBSWY3DPEHPK3PXP")

    def test_manual_name_overrides_uri(self) -> None:
        uri = "otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example"
        account = account_from_input("我的名字", "", uri, 6, 30, "SHA1")
        self.assertEqual(account.name, "我的名字")
        self.assertEqual(account.issuer, "Example")

    def test_provisioning_uri_roundtrip(self) -> None:
        original = Account.create(
            "alice@google.com",
            "Example",
            base64.b32encode(RFC_SEEDS["SHA256"]).decode("ascii"),
            digits=8,
            period=60,
            algorithm="SHA256",
        )
        restored = account_from_input("", "", provisioning_uri(original), 6, 30, "SHA1")
        self.assertEqual(restored.secret, original.secret)
        self.assertEqual(restored.name, original.name)
        self.assertEqual(restored.issuer, original.issuer)
        self.assertEqual(restored.digits, 8)
        self.assertEqual(restored.period, 60)
        self.assertEqual(restored.algorithm, "SHA256")
        self.assertEqual(current_code(restored, 59)[0], current_code(original, 59)[0])


class VaultTests(unittest.TestCase):
    def test_dpapi_keeps_interior_nul(self) -> None:
        payload = b"abc\x00def" * 20
        self.assertEqual(unprotect(protect(payload)), payload)

    def test_save_load_preserves_order_and_codes(self) -> None:
        first = Account.create("甲", "谷歌", "JBSWY3DPEHPK3PXP")
        second_secret = base64.b32encode(RFC_SEEDS["SHA1"]).decode("ascii")
        second = Account.create("乙", "GitHub", second_secret, digits=8)
        with tempfile.TemporaryDirectory() as folder:
            vault = Vault(Path(folder) / "vault.bin")
            vault.save([second, first])
            loaded = vault.load()
        self.assertEqual([item.name for item in loaded], ["乙", "甲"])
        self.assertEqual(loaded[0].issuer, "GitHub")
        self.assertEqual(current_code(loaded[0], 59)[0], current_code(second, 59)[0])
        self.assertEqual(loaded[1].secret, first.secret)

    def test_corrupt_file_is_quarantined_without_being_overwritten(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "vault.bin"
            vault = Vault(path)
            vault.save([Account.create("甲", "谷歌", "JBSWY3DPEHPK3PXP")])
            path.write_bytes(b"this is not a vault")
            with self.assertRaises(VaultError):
                vault.load()
            self.assertTrue(path.exists())
            moved = vault.quarantine()
            self.assertTrue(moved.exists())
            self.assertFalse(path.exists())
            self.assertEqual(vault.load(), [])

    def test_source_run_stores_vault_beside_the_program(self) -> None:
        root = Path(vault_module.__file__).resolve().parent.parent
        self.assertEqual(program_dir(), root)
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("AUTHENTICATOR_VAULT", None)
            self.assertEqual(Vault().path, root / "vault.bin")

    def test_frozen_exe_stores_vault_beside_the_exe(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            exe = Path(folder) / "Authenticator.exe"
            exe.write_bytes(b"")
            with mock.patch.object(sys, "frozen", True, create=True), mock.patch.object(
                sys, "executable", str(exe)
            ), mock.patch.dict("os.environ", {"APPDATA": folder}, clear=False):
                folder_path = Path(folder).resolve()
                self.assertEqual(program_dir(), folder_path)
                self.assertEqual(default_vault_path(), folder_path / "vault.bin")

    def test_legacy_appdata_vault_is_moved_beside_the_program(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            exe_dir = base / "app"
            appdata = base / "Roaming"
            exe_dir.mkdir()
            legacy_dir = appdata / "PCAuthenticator"
            legacy_dir.mkdir(parents=True)
            legacy = legacy_dir / "vault.bin"
            legacy.write_bytes(b"encrypted-vault")
            exe = exe_dir / "Authenticator.exe"
            with mock.patch.object(sys, "frozen", True, create=True), mock.patch.object(
                sys, "executable", str(exe)
            ), mock.patch.dict("os.environ", {"APPDATA": str(appdata)}, clear=False):
                path = default_vault_path()
            self.assertEqual(path, (exe_dir / "vault.bin").resolve())
            self.assertEqual(path.read_bytes(), b"encrypted-vault")
            self.assertFalse(legacy.exists())

    def test_password_opens_on_this_pc_without_typing_it(self) -> None:
        account = Account.create("alice@google.com", "Google", "JBSWY3DPEHPK3PXP")
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "vault.bin"
            vault = Vault(path)
            vault.set_password("correct-horse", [account])
            raw = path.read_bytes()
            self.assertTrue(raw.startswith(b"GAVL"))
            self.assertNotIn(account.secret.encode("ascii"), raw)
            self.assertNotIn(b"alice@google.com", raw)

            opened = Vault(path)
            loaded = opened.load()
            self.assertTrue(opened.has_password)
            self.assertEqual(loaded[0].secret, account.secret)
            self.assertTrue(opened.verify_password("correct-horse"))
            self.assertFalse(opened.verify_password("wrong-password"))

            opened.change_password("correct-horse", "new-password-1", loaded)
            self.assertTrue(opened.verify_password("new-password-1"))
            self.assertFalse(opened.verify_password("correct-horse"))
            with self.assertRaises(InvalidPassword):
                opened.change_password("correct-horse", "another-password", loaded)

            moved = Vault(path)
            path.write_bytes(disable_local_wrap(path.read_bytes()))
            with self.assertRaises(NeedsPassword):
                moved.load()
            self.assertTrue(moved.has_password)
            with self.assertRaises(InvalidPassword):
                moved.unlock("correct-horse")
            unlocked = moved.unlock("new-password-1")
            self.assertEqual(unlocked[0].secret, account.secret)

            again = Vault(path)
            self.assertEqual(again.load()[0].name, "alice@google.com")
            self.assertTrue(again.verify_password("new-password-1"))

    def test_legacy_dpapi_file_can_gain_a_password(self) -> None:
        account = Account.create("甲", "谷歌", "JBSWY3DPEHPK3PXP")
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "vault.bin"
            vault = Vault(path)
            vault.save([account])
            self.assertFalse(path.read_bytes().startswith(b"GAVL"))
            loaded = Vault(path).load()
            self.assertFalse(Vault(path).has_password)
            upgrading = Vault(path)
            accounts = upgrading.load()
            self.assertEqual(accounts[0].secret, loaded[0].secret)
            upgrading.set_password("correct-horse", accounts)
            self.assertTrue(path.read_bytes().startswith(b"GAVL"))
            self.assertEqual(Vault(path).load()[0].issuer, "谷歌")

    def test_four_character_password_and_reset_without_the_old_one(self) -> None:
        account = Account.create("甲", "谷歌", "JBSWY3DPEHPK3PXP")
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "vault.bin"
            vault = Vault(path)
            with self.assertRaises(ValueError):
                vault.set_password("abc", [account])
            vault.set_password("ab12", [account])

            opened = Vault(path)
            loaded = opened.load()
            self.assertTrue(opened.can_reset_password)
            self.assertTrue(opened.verify_password("ab12"))
            opened.reset_password("wxyz", loaded)
            self.assertTrue(opened.verify_password("wxyz"))
            self.assertFalse(opened.verify_password("ab12"))

            fresh = Vault(path)
            self.assertEqual(fresh.load()[0].secret, account.secret)
            self.assertTrue(fresh.verify_password("wxyz"))

            path.write_bytes(disable_local_wrap(path.read_bytes()))
            locked = Vault(path)
            with self.assertRaises(NeedsPassword):
                locked.load()
            self.assertFalse(locked.can_reset_password)
            with self.assertRaises(VaultError):
                locked.reset_password("zzzz", loaded)


class BackupTests(unittest.TestCase):
    def _account(self) -> Account:
        return Account.create("alice@google.com", "Example", "JBSWY3DPEHPK3PXP", digits=8, period=45)

    def test_roundtrip_and_plaintext_secret_is_absent(self) -> None:
        account = self._account()
        blob = build_backup([account], "correct-horse")
        self.assertTrue(blob.startswith(b"GAUB"))
        self.assertNotIn(account.secret.encode("ascii"), blob)
        self.assertNotIn(b"alice@google.com", blob)
        loaded = read_backup(blob, "correct-horse")
        self.assertEqual(loaded[0].secret, account.secret)
        self.assertEqual(loaded[0].name, account.name)
        self.assertEqual(loaded[0].period, 45)
        self.assertEqual(current_code(loaded[0], 1_700_000_000)[0], current_code(account, 1_700_000_000)[0])

    def test_wrong_password_and_tamper(self) -> None:
        blob = build_backup([self._account()], "correct-horse")
        with self.assertRaises(InvalidBackup):
            read_backup(blob, "wrong-password")
        damaged = bytearray(blob)
        damaged[-1] ^= 0xFF
        with self.assertRaises(InvalidBackup):
            read_backup(bytes(damaged), "correct-horse")


if __name__ == "__main__":
    unittest.main()
