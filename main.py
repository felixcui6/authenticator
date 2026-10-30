"""身份验证器入口。直接运行，或由打包后的 exe 启动。"""

from __future__ import annotations

import sys
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _crash_path() -> Path:
    import os

    root = os.environ.get("APPDATA") or str(Path.home())
    folder = Path(root) / "PCAuthenticator"
    folder.mkdir(parents=True, exist_ok=True)
    return folder / "crash.txt"


def _report_crash() -> None:
    text = traceback.format_exc()
    try:
        path = _crash_path()
        path.write_text(text, encoding="utf-8")
    except OSError:
        path = None
    try:
        import tkinter as tk
        from tkinter import messagebox

        root = tk.Tk()
        root.withdraw()
        where = f"\n\n详情已写入：\n{path}" if path else ""
        messagebox.showerror("身份验证器", f"启动失败。{where}")
        root.destroy()
    except Exception:
        pass


def run_self_test() -> int:
    """供打包后的 exe 自检：验证码算法、本机加密和备份。"""
    import base64

    from authenticator.core import Account, current_code
    from authenticator.vault import build_backup, protect, read_backup, unprotect

    secret = base64.b32encode(b"12345678901234567890").decode("ascii")
    account = Account.create("self-test", "RFC", secret, digits=8, period=30, algorithm="SHA1")
    code, remaining = current_code(account, 59)
    if code != "94287082" or remaining != 1:
        return 1
    payload = b"ok\x00ping"
    if unprotect(protect(payload)) != payload:
        return 1
    blob = build_backup([account], "test-password")
    if secret.encode("ascii") in blob:
        return 1
    loaded = read_backup(blob, "test-password")
    if loaded[0].secret != account.secret:
        return 1
    if current_code(loaded[0], 59)[0] != "94287082":
        return 1
    return 0


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        try:
            sys.exit(run_self_test())
        except Exception:
            _report_crash()
            sys.exit(1)
    try:
        from authenticator.gui import main

        main()
    except Exception:
        _report_crash()
        sys.exit(1)
