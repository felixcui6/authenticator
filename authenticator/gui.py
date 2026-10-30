"""Windows 桌面界面。"""

from __future__ import annotations

import ctypes
import logging
import os
import sys
import time
import tkinter as tk
import tkinter.font as tkfont
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from authenticator import __version__
from authenticator.core import (
    Account,
    account_from_input,
    current_code,
    format_code,
    generate_secret,
    provisioning_uri,
)
from authenticator.vault import (
    InvalidBackup,
    InvalidPassword,
    NeedsPassword,
    Vault,
    VaultError,
    build_backup,
    read_backup,
)

log = logging.getLogger(__name__)

BG = "#141414"
CARD = "#1e1e1e"
TEXT = "#f1f3f4"
MUTED = "#9aa0a6"
ACCENT = "#8ab4f8"
ACCENT_BTN = "#1a73e8"
ACCENT_BTN_ACTIVE = "#185abc"
DANGER = "#f28b82"
DANGER_BG = "#5c2b29"
OK = "#81c995"
ENTRY = "#2a2a2a"
BORDER = "#333333"
RING_TRACK = "#3c4043"
GHOST = "#2a2a2a"
GHOST_ACTIVE = "#333333"


def bundle_path(relative: str) -> Path:
    base = getattr(sys, "_MEIPASS", None)
    if base:
        return Path(base) / relative
    return Path(__file__).resolve().parent.parent / relative


def enable_windows_dpi() -> None:
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        try:
            ctypes.windll.user32.SetProcessDPIAware()
        except Exception:
            pass


def set_windows_app_id() -> None:
    try:
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("PCAuthenticator.TOTP")
    except Exception:
        pass


def pick_font(names: tuple[str, ...]) -> str:
    have = {name.lower() for name in tkfont.families()}
    for name in names:
        if name.lower() in have:
            return name
    return "TkDefaultFont"


def place_dialog(dialog: tk.Toplevel, parent: tk.Misc) -> None:
    dialog.transient(parent)
    dialog.update_idletasks()
    width = max(dialog.winfo_reqwidth(), dialog.winfo_width())
    height = max(dialog.winfo_reqheight(), dialog.winfo_height())
    x = parent.winfo_rootx() + max(0, (parent.winfo_width() - width) // 2)
    y = parent.winfo_rooty() + max(0, (parent.winfo_height() - height) // 2)
    dialog.geometry(f"+{max(0, x)}+{max(0, y)}")
    dialog.lift()
    dialog.wait_visibility()
    dialog.grab_set()


def make_button(parent, text: str, command, font, kind: str = "primary") -> tk.Button:
    colors = {
        "primary": (ACCENT_BTN, "white", ACCENT_BTN_ACTIVE),
        "ghost": (GHOST, TEXT, GHOST_ACTIVE),
        "danger": (DANGER_BG, DANGER, "#6e3330"),
    }
    bg, fg, active = colors[kind]
    return tk.Button(
        parent,
        text=text,
        command=command,
        bg=bg,
        fg=fg,
        activebackground=active,
        activeforeground=fg,
        font=font,
        relief="flat",
        bd=0,
        padx=14,
        pady=6,
        cursor="hand2",
        highlightthickness=0,
    )


def style_input(widget, mono: bool = False) -> None:
    widget.configure(
        bg=ENTRY,
        fg=TEXT,
        insertbackground=TEXT,
        relief="flat",
        highlightthickness=1,
        highlightbackground=BORDER,
        highlightcolor=ACCENT,
        bd=0,
        font=widget.cget("font"),
    )


class ScrollList(tk.Frame):
    def __init__(self, parent, bg: str):
        super().__init__(parent, bg=bg)
        self.canvas = tk.Canvas(self, bg=bg, highlightthickness=0, bd=0)
        self.vsb = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.inner = tk.Frame(self.canvas, bg=bg)
        self.inner.bind("<Configure>", self._on_inner)
        self.window_id = self.canvas.create_window((0, 0), window=self.inner, anchor="nw")
        self.canvas.configure(yscrollcommand=self.vsb.set)
        self.canvas.pack(side="left", fill="both", expand=True)
        self.vsb.pack(side="right", fill="y")
        self.canvas.bind("<Configure>", self._on_canvas)
        self.canvas.bind_all("<MouseWheel>", self._on_wheel)
        self._syncing = False
        self.top_spacer = tk.Frame(self.inner, bg=bg, height=12)
        self.top_spacer.pack(fill="x")

    def _on_inner(self, _event) -> None:
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        self._sync_scrollbar()

    def _on_canvas(self, event) -> None:
        self.canvas.itemconfigure(self.window_id, width=event.width)
        self._sync_scrollbar()

    def _sync_scrollbar(self) -> None:
        if self._syncing:
            return
        self._syncing = True
        try:
            bbox = self.canvas.bbox("all")
            height = self.canvas.winfo_height()
            needed = bool(bbox) and height > 1 and (bbox[3] - bbox[1]) > height + 2
            mapped = bool(self.vsb.winfo_ismapped())
            if needed and not mapped:
                self.vsb.pack(side="right", fill="y")
            elif not needed and mapped:
                self.vsb.pack_forget()
        finally:
            self._syncing = False

    def _is_under(self, widget) -> bool:
        while widget is not None:
            if widget is self:
                return True
            widget = getattr(widget, "master", None)
        return False

    def _on_wheel(self, event) -> str | None:
        try:
            widget = self.winfo_containing(*self.winfo_pointerxy())
        except tk.TclError:
            return None
        if widget is None or not self._is_under(widget):
            return None
        delta = int(getattr(event, "delta", 0) or 0)
        if delta == 0:
            return None
        steps = int(-delta / 120) or (-1 if delta > 0 else 1)
        self.canvas.yview_scroll(steps, "units")
        return "break"


class AccountCard(tk.Frame):
    def __init__(self, parent, account: Account, app: App, index: int, count: int):
        super().__init__(parent, bg=CARD, highlightthickness=1, highlightbackground=BORDER)
        self.account = account
        self.app = app
        self.index = index
        self.count = count
        self._code: str | None = None
        self._alert: bool | None = None
        self._remaining: int | None = None
        self._shown_error = False

        self.bar = tk.Canvas(self, height=4, bg=CARD, highlightthickness=0, bd=0)
        self.bar.pack(side="bottom", fill="x")
        self.bar.bind("<Configure>", lambda _event: self._redraw_bar())

        body = tk.Frame(self, bg=CARD)
        body.pack(side="top", fill="both", expand=True)

        right = tk.Frame(body, bg=CARD)
        right.pack(side="right", padx=(8, 12), pady=10)
        self.menu_btn = tk.Button(
            right,
            text="···",
            command=self.open_menu,
            bg=CARD,
            fg=MUTED,
            activebackground=CARD,
            activeforeground=TEXT,
            font=app.font_ui,
            relief="flat",
            bd=0,
            cursor="hand2",
            highlightthickness=0,
            padx=4,
        )
        self.menu_btn.pack(anchor="e")
        self.ring = tk.Canvas(right, width=36, height=36, bg=CARD, highlightthickness=0, bd=0)
        self.ring.pack()
        self.seconds = tk.Label(
            right,
            text="",
            width=3,
            anchor="center",
            bg=CARD,
            fg=MUTED,
            font=app.font_small,
        )
        self.seconds.pack()

        left = tk.Frame(body, bg=CARD)
        left.pack(side="left", fill="both", expand=True, padx=(14, 0), pady=10)
        self.title_label = tk.Label(
            left,
            text=account.title,
            bg=CARD,
            fg=TEXT,
            font=app.font_h2,
            anchor="w",
            justify="left",
        )
        self.title_label.pack(anchor="w", fill="x")
        self.subtitle_label = tk.Label(
            left,
            text=account.subtitle,
            bg=CARD,
            fg=MUTED,
            font=app.font_small,
            anchor="w",
            justify="left",
        )
        if account.subtitle:
            self.subtitle_label.pack(anchor="w", fill="x", pady=(2, 0))

        code_row = tk.Frame(left, bg=CARD)
        code_row.pack(anchor="w", fill="x", pady=(8, 0))
        self.code_label = tk.Label(
            code_row,
            text="------",
            bg=CARD,
            fg=TEXT,
            font=app.font_code,
            anchor="w",
        )
        self.code_label.pack(side="left")
        if not account.invalid_reason:
            self.code_label.configure(cursor="hand2")
            self.code_label.bind("<Button-1>", lambda _event: app.copy_code(account))
            self.copy_btn = make_button(
                code_row,
                "复制",
                lambda: app.copy_code(account),
                app.font_small,
                "ghost",
            )
            self.copy_btn.pack(side="left", padx=(12, 0))

        self.bind("<Configure>", self._on_resize)

    def _on_resize(self, event) -> None:
        if event.widget is not self:
            return
        width = max(120, event.width - 110)
        self.title_label.configure(wraplength=width)
        self.subtitle_label.configure(wraplength=width)

    def open_menu(self) -> None:
        menu = tk.Menu(self, tearoff=0)
        if not self.account.invalid_reason:
            menu.add_command(
                label="复制验证码",
                command=lambda: self.app.copy_code(self.account),
            )
            menu.add_command(
                label="复制迁移链接",
                command=lambda: self.app.copy_migration(self.account),
            )
            menu.add_separator()
        menu.add_command(label="编辑", command=lambda: self.app.edit_account(self.account))
        if self.index > 0:
            menu.add_command(label="上移", command=lambda: self.app.move_account(self.account.id, -1))
        if self.index < self.count - 1:
            menu.add_command(label="下移", command=lambda: self.app.move_account(self.account.id, 1))
        menu.add_separator()
        menu.add_command(label="删除", command=lambda: self.app.delete_account(self.account))
        menu.tk_popup(self.winfo_pointerx(), self.winfo_pointery())

    def refresh(self, now: float) -> None:
        if self.account.invalid_reason:
            if not self._shown_error:
                self.code_label.configure(
                    text=self.account.invalid_reason,
                    fg=DANGER,
                    font=self.app.font_ui,
                )
                self.seconds.configure(text="")
                self.ring.delete("all")
                self.bar.delete("all")
                self._shown_error = True
            return
        try:
            code, remaining = current_code(self.account, now)
        except ValueError as exc:
            if not self._shown_error:
                self.code_label.configure(text=str(exc), fg=DANGER, font=self.app.font_ui)
                self.seconds.configure(text="")
                self.ring.delete("all")
                self.bar.delete("all")
                self._shown_error = True
            return
        alert = remaining <= 5
        if code != self._code:
            self._code = code
            self.code_label.configure(text=format_code(code), font=self.app.font_code)
        if alert != self._alert:
            self._alert = alert
            self.code_label.configure(fg=DANGER if alert else TEXT)
        if remaining != self._remaining:
            self._remaining = remaining
            self.seconds.configure(text=str(remaining), fg=DANGER if alert else MUTED)
            self._draw_ring(remaining, alert)
            self._redraw_bar()

    def _draw_ring(self, remaining: int, alert: bool) -> None:
        canvas = self.ring
        canvas.delete("all")
        pad = 3
        size = 36
        color = DANGER if alert else ACCENT
        canvas.create_oval(pad, pad, size - pad, size - pad, outline=RING_TRACK, width=3)
        fraction = remaining / self.account.period
        extent = -359.9 if fraction >= 0.999 else -360 * fraction
        if extent < -1:
            canvas.create_arc(
                pad,
                pad,
                size - pad,
                size - pad,
                start=90,
                extent=extent,
                style="arc",
                outline=color,
                width=3,
            )

    def _redraw_bar(self) -> None:
        if self._remaining is None or self.account.invalid_reason:
            return
        width = self.bar.winfo_width()
        if width <= 1:
            return
        alert = self._remaining <= 5
        fraction = self._remaining / self.account.period
        self.bar.delete("all")
        self.bar.create_rectangle(
            0,
            0,
            max(2, width * fraction),
            4,
            fill=DANGER if alert else ACCENT,
            width=0,
        )


class AccountDialog(tk.Toplevel):
    def __init__(self, app: App, account: Account | None = None, prefill: str = ""):
        super().__init__(app)
        self.app = app
        self.original = account
        self.result: Account | None = None
        self.deleted = False
        self.title("编辑账号" if account else "添加账号")
        self.configure(bg=BG)
        self.resizable(False, False)
        self.protocol("WM_DELETE_WINDOW", self.cancel)
        self.bind("<Escape>", lambda _event: self.cancel())

        pad = tk.Frame(self, bg=BG)
        pad.pack(fill="both", expand=True, padx=18, pady=16)

        self.name_var = tk.StringVar(value=account.name if account else "")
        self.issuer_var = tk.StringVar(value=account.issuer if account else "")
        self.digits_var = tk.StringVar(value=str(account.digits if account else 6))
        self.period_var = tk.StringVar(value=str(account.period if account else 30))
        self.algorithm_var = tk.StringVar(value=account.algorithm if account else "SHA1")

        self._field_label(pad, "账号名称").pack(anchor="w")
        self.name_entry = tk.Entry(pad, textvariable=self.name_var, font=app.font_ui)
        style_input(self.name_entry)
        self.name_entry.pack(fill="x", ipady=5, pady=(4, 10))

        self._field_label(pad, "发行方，例如 Google、GitHub，可留空").pack(anchor="w")
        self.issuer_entry = tk.Entry(pad, textvariable=self.issuer_var, font=app.font_ui)
        style_input(self.issuer_entry)
        self.issuer_entry.pack(fill="x", ipady=5, pady=(4, 10))

        header = tk.Frame(pad, bg=BG)
        header.pack(fill="x")
        self._field_label(header, "密钥").pack(side="left")
        make_button(header, "粘贴", self.paste_secret, app.font_small, "ghost").pack(side="right")
        make_button(header, "生成密钥", self.fill_generated_secret, app.font_small, "ghost").pack(
            side="right", padx=(0, 8)
        )

        self.secret = tk.Text(
            pad, height=4, width=46, wrap="char", undo=True, font=app.font_mono, padx=8, pady=6
        )
        style_input(self.secret)
        self.secret.pack(fill="x", pady=(4, 6))
        if account is not None and account.secret:
            self.secret.insert("1.0", account.secret.rstrip("="))
        elif prefill:
            self.secret.insert("1.0", prefill)
        self.secret.bind("<Return>", self._save_event)

        hint = (
            "上面是当前密钥。可以修改，粘贴新密钥，或点「生成密钥」换一把新的。清空后保存会保留原密钥。"
            if account
            else "粘贴网站给出的密钥，或点「生成密钥」。otpauth:// 链接也可以直接粘贴，链接里的位数和周期会自动采用。"
        )
        tk.Label(
            pad,
            text=hint,
            bg=BG,
            fg=MUTED,
            font=app.font_small,
            wraplength=420,
            justify="left",
        ).pack(anchor="w", pady=(0, 10))

        advanced = tk.Frame(pad, bg=BG)
        advanced.pack(fill="x", pady=(0, 8))
        digits_box = self._advanced_box(advanced, "位数")
        option_menu(digits_box, self.digits_var, ("6", "7", "8"), app.font_ui).pack(anchor="w", pady=(4, 0))
        period_box = self._advanced_box(advanced, "周期（秒）")
        self.period_entry = tk.Entry(period_box, textvariable=self.period_var, width=8, font=app.font_ui)
        style_input(self.period_entry)
        self.period_entry.pack(anchor="w", pady=(4, 0), ipady=4)
        algo_box = self._advanced_box(advanced, "算法")
        option_menu(algo_box, self.algorithm_var, ("SHA1", "SHA256", "SHA512"), app.font_ui).pack(
            anchor="w", pady=(4, 0)
        )

        self.preview_label = tk.Label(pad, text="", bg=BG, fg=OK, font=app.font_h2, anchor="w")
        self.preview_label.pack(anchor="w", fill="x", pady=(4, 0))
        self.err = tk.Label(
            pad,
            text="",
            bg=BG,
            fg=DANGER,
            font=app.font_small,
            wraplength=420,
            justify="left",
            anchor="w",
        )
        self.err.pack(anchor="w", fill="x", pady=(4, 8))

        buttons = tk.Frame(pad, bg=BG)
        buttons.pack(fill="x")
        if account is not None:
            make_button(buttons, "删除", self.delete, app.font_btn, "danger").pack(side="left")
        make_button(buttons, "保存", self.save, app.font_btn, "primary").pack(side="right")
        make_button(buttons, "预览", self.preview, app.font_btn, "ghost").pack(side="right", padx=(0, 8))
        make_button(buttons, "取消", self.cancel, app.font_btn, "ghost").pack(side="right", padx=(0, 8))

        self.name_entry.bind("<Return>", self._save_event)
        self.issuer_entry.bind("<Return>", self._save_event)
        self.period_entry.bind("<Return>", self._save_event)
        if prefill:
            self.secret.focus_set()
        else:
            self.name_entry.focus_set()
        place_dialog(self, app)

    def _field_label(self, parent, text: str) -> tk.Label:
        return tk.Label(parent, text=text, bg=BG, fg=MUTED, font=self.app.font_small)

    def _advanced_box(self, parent, title: str) -> tk.Frame:
        box = tk.Frame(parent, bg=BG)
        tk.Label(box, text=title, bg=BG, fg=MUTED, font=self.app.font_small).pack(anchor="w")
        box.pack(side="left", padx=(0, 16))
        return box

    def _save_event(self, _event=None):
        self.save()
        return "break"

    def paste_secret(self) -> None:
        try:
            text = self.clipboard_get().strip()
        except tk.TclError:
            self.err.configure(text="剪贴板里没有文本")
            return
        if not text:
            self.err.configure(text="剪贴板里没有文本")
            return
        self.secret.delete("1.0", "end")
        self.secret.insert("1.0", text)
        self.err.configure(text="")

    def fill_generated_secret(self) -> None:
        self.secret.delete("1.0", "end")
        self.secret.insert("1.0", generate_secret())
        self.err.configure(text="")
        self.preview()

    def _period(self) -> int:
        raw = self.period_var.get().strip()
        try:
            period = int(raw)
        except ValueError as exc:
            raise ValueError("刷新周期必须是整数") from exc
        return period

    def _compose(self) -> Account:
        secret_text = self.secret.get("1.0", "end").strip()
        period = self._period()
        digits = int(self.digits_var.get())
        algorithm = self.algorithm_var.get()
        if not secret_text:
            if self.original is None:
                raise ValueError("请填写密钥")
            return account_from_input(
                self.name_var.get(),
                self.issuer_var.get(),
                self.original.secret,
                digits,
                period,
                algorithm,
            )
        return account_from_input(
            self.name_var.get(),
            self.issuer_var.get(),
            secret_text,
            digits,
            period,
            algorithm,
        )

    def preview(self) -> None:
        try:
            account = self._compose()
            code, remaining = current_code(account)
        except ValueError as exc:
            self.preview_label.configure(text="")
            self.err.configure(text=str(exc))
            return
        self.err.configure(text="")
        self.preview_label.configure(text=f"当前验证码  {format_code(code)}     {remaining} 秒内有效")

    def save(self) -> None:
        try:
            created = self._compose()
            current_code(created)
        except ValueError as exc:
            self.err.configure(text=str(exc))
            return
        if self.original is None:
            self.result = created
        else:
            self.original.name = created.name
            self.original.issuer = created.issuer
            self.original.secret = created.secret
            self.original.digits = created.digits
            self.original.period = created.period
            self.original.algorithm = created.algorithm
            self.original.invalid_reason = ""
            self.result = self.original
        self.destroy()

    def delete(self) -> None:
        if self.original is None:
            return
        ok = messagebox.askyesno(
            "删除账号",
            f"确定删除「{self.original.title}」吗？此操作不能撤销。",
            parent=self,
        )
        if not ok:
            return
        self.deleted = True
        self.result = None
        self.destroy()

    def cancel(self) -> None:
        self.result = None
        self.destroy()


def option_menu(parent, variable: tk.StringVar, values: tuple[str, ...], font) -> ttk.Combobox:
    return ttk.Combobox(
        parent,
        textvariable=variable,
        values=values,
        state="readonly",
        width=max(6, max(len(item) for item in values) + 1),
        font=font,
        style="Dark.TCombobox",
    )


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.configure(bg=BG)
        self.title("身份验证器")
        self.minsize(420, 560)
        self._center(460, 700)
        self._tick_id: str | None = None
        self._toast_text = ""
        self._toast_until = 0.0
        self._toast_danger = False
        self._vault_ok = True
        self._needs_password = False
        self.cards: list[AccountCard] = []
        self.empty: tk.Widget | None = None
        self.pending: tk.Widget | None = None
        self._visible: list[Account] = []

        ui = pick_font(("Microsoft YaHei UI", "Microsoft YaHei", "Segoe UI"))
        mono = pick_font(("Consolas", "Courier New"))
        self.font_title = (ui, 18, "bold")
        self.font_h2 = (ui, 12, "bold")
        self.font_ui = (ui, 10)
        self.font_small = (ui, 9)
        self.font_code = (mono, 26)
        self.font_mono = (mono, 11)
        self.font_btn = (ui, 10)

        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure(
            "Vertical.TScrollbar",
            background="#2a2a2a",
            troughcolor=BG,
            bordercolor=BG,
            arrowcolor=MUTED,
            relief="flat",
        )
        style.configure(
            "Dark.TCombobox",
            fieldbackground=ENTRY,
            background=GHOST,
            foreground=TEXT,
            arrowcolor=TEXT,
            bordercolor=BORDER,
            lightcolor=ENTRY,
            darkcolor=ENTRY,
            padding=4,
        )
        style.map(
            "Dark.TCombobox",
            fieldbackground=[("readonly", ENTRY)],
            foreground=[("readonly", TEXT)],
            selectbackground=[("readonly", ENTRY)],
            selectforeground=[("readonly", TEXT)],
            bordercolor=[("focus", ACCENT)],
        )
        family, size = self.font_ui
        self.option_add("*TCombobox*Listbox.background", ENTRY)
        self.option_add("*TCombobox*Listbox.foreground", TEXT)
        self.option_add("*TCombobox*Listbox.selectBackground", ACCENT_BTN)
        self.option_add("*TCombobox*Listbox.selectForeground", "white")
        self.option_add("*TCombobox*Listbox.font", f"{{{family}}} {size}")

        self.vault = Vault()
        self.accounts: list[Account] = []
        try:
            self.accounts = self.vault.load()
        except NeedsPassword:
            log.info("vault needs the password on this computer")
            self.accounts = []
            self._vault_ok = False
            self._needs_password = True
        except VaultError:
            log.warning("stored accounts could not be opened")
            self.accounts = []
            self._vault_ok = False

        self._build()
        self._apply_icon()
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.bind_all("<Control-n>", self._on_new)
        self.bind_all("<Control-N>", self._on_new)
        self.bind_all("<Control-f>", self._focus_search)
        self.bind_all("<Control-F>", self._focus_search)
        self.bind("<Escape>", self._on_escape)

        if self._needs_password:
            self._show_pending("换到这台电脑后，需要输入一次保险箱密码。")
            self.after(80, self._prompt_unlock)
        elif self._vault_ok:
            self.refresh_cards()
            if not self.vault.has_password:
                self.after(200, self._offer_set_password)
        else:
            self._show_pending("正在确认本机保存的账号…")
            self.after(80, self._resolve_vault)
        self.tick()

    def _center(self, width: int, height: int) -> None:
        self.update_idletasks()
        x = max(0, (self.winfo_screenwidth() - width) // 2)
        y = max(0, (self.winfo_screenheight() - height) // 2)
        self.geometry(f"{width}x{height}+{x}+{y}")

    def _apply_icon(self) -> None:
        icon = bundle_path("assets/app.ico")
        if not icon.exists():
            return
        try:
            self.iconbitmap(default=str(icon))
        except tk.TclError:
            log.info("window icon was not applied")

    def _build(self) -> None:
        tk.Frame(self, bg=ACCENT_BTN, height=4).pack(side="top", fill="x")

        self.status = tk.Label(
            self,
            text="",
            bg=BG,
            fg=MUTED,
            font=self.font_small,
            anchor="w",
            padx=16,
            pady=8,
        )
        self.status.pack(side="bottom", fill="x")
        tk.Frame(self, bg="#2a2a2a", height=1).pack(side="bottom", fill="x")

        header = tk.Frame(self, bg=BG)
        header.pack(side="top", fill="x", padx=16, pady=(14, 8))
        titles = tk.Frame(header, bg=BG)
        titles.pack(side="left", fill="x", expand=True)
        tk.Label(
            titles,
            text="身份验证器",
            bg=BG,
            fg=TEXT,
            font=self.font_title,
            anchor="w",
        ).pack(anchor="w")
        tk.Label(
            titles,
            text="兼容 Google 身份验证器的动态口令",
            bg=BG,
            fg=MUTED,
            font=self.font_small,
            anchor="w",
            wraplength=240,
            justify="left",
        ).pack(anchor="w", pady=(2, 0))
        actions = tk.Frame(header, bg=BG)
        actions.pack(side="right")
        make_button(actions, "菜单", self.open_main_menu, self.font_btn, "ghost").pack(side="left", padx=(0, 8))
        make_button(actions, "添加", self.add_account, self.font_btn, "primary").pack(side="left")

        search_row = tk.Frame(self, bg=BG)
        search_row.pack(side="top", fill="x", padx=16, pady=(0, 8))
        tk.Label(search_row, text="搜索", bg=BG, fg=MUTED, font=self.font_ui).pack(side="left", padx=(0, 8))
        self.query = tk.StringVar()
        self.search_entry = tk.Entry(search_row, textvariable=self.query, font=self.font_ui)
        style_input(self.search_entry)
        self.search_entry.pack(side="left", fill="x", expand=True, ipady=4)
        self.query.trace_add("write", self._on_search)

        self.list = ScrollList(self, BG)
        self.list.pack(side="top", fill="both", expand=True)

    def _show_pending(self, text: str) -> None:
        self._clear_list()
        self.pending = tk.Label(self.list.inner, text=text, bg=BG, fg=MUTED, font=self.font_ui)
        self.pending.pack(pady=48)

    def _resolve_vault(self) -> None:
        if not self.winfo_exists():
            return
        ok = messagebox.askyesno(
            "无法读取账号",
            "已保存的账号无法解密。可能是文件已损坏，或这是另一台电脑上、还没有设置保险箱密码的旧文件。\n\n"
            "选择「是」会把原文件改名保留，并从空列表重新开始。\n"
            "选择「否」会直接退出，不改动原文件。",
            parent=self,
        )
        if not ok:
            self._on_close()
            return
        try:
            moved = self.vault.quarantine()
        except OSError as exc:
            messagebox.showerror("无法处理原文件", str(exc), parent=self)
            self._on_close()
            return
        self._vault_ok = True
        self.accounts = []
        self.refresh_cards()
        self.toast(f"原文件已改名为 {moved.name}")

    def _prompt_unlock(self) -> None:
        if not self.winfo_exists():
            return
        prompt = "这台电脑还不能直接打开这个保险箱。\n请输入保险箱密码。通过之后，这台电脑以后会直接打开。"
        while self.winfo_exists():
            password = ask_password(self, "输入保险箱密码", confirm=False, prompt=prompt)
            if not password:
                messagebox.showinfo("需要密码", "没有密码就无法打开从另一台电脑拷来的账号。", parent=self)
                self._on_close()
                return
            try:
                self.accounts = self.vault.unlock(password)
            except InvalidPassword:
                messagebox.showerror("密码不正确", "保险箱密码不正确，请再试一次。", parent=self)
                continue
            except (VaultError, OSError) as exc:
                messagebox.showerror("无法解锁", str(exc), parent=self)
                self._on_close()
                return
            self._vault_ok = True
            self._needs_password = False
            self.refresh_cards()
            self.toast("已在这台电脑上解锁，以后会直接打开")
            return

    def _offer_set_password(self) -> None:
        if not self.winfo_exists() or self.vault.has_password or self._dialog_open():
            return
        self.set_vault_password()

    def _dialog_open(self) -> bool:
        for child in self.winfo_children():
            if isinstance(child, tk.Toplevel) and child.winfo_exists():
                return True
        return False

    def _on_new(self, _event=None):
        if self._dialog_open() or not self._vault_ok:
            return None
        self.add_account()
        return "break"

    def _focus_search(self, _event=None):
        if self._dialog_open():
            return None
        self.search_entry.focus_set()
        self.search_entry.select_range(0, "end")
        return "break"

    def _on_escape(self, _event=None):
        if self._dialog_open():
            return None
        if self.query.get():
            self.query.set("")
            return "break"
        return None

    def _on_search(self, *_args) -> None:
        if self._vault_ok:
            self.refresh_cards()

    def _matches(self, account: Account, query: str) -> bool:
        if not query:
            return True
        blob = f"{account.issuer} {account.name}".lower()
        return query in blob

    def _clear_list(self) -> None:
        for card in self.cards:
            card.destroy()
        self.cards.clear()
        if self.empty is not None:
            self.empty.destroy()
            self.empty = None
        if self.pending is not None:
            self.pending.destroy()
            self.pending = None

    def refresh_cards(self) -> None:
        query = self.query.get().strip().lower()
        self._visible = [account for account in self.accounts if self._matches(account, query)]
        self._clear_list()
        if not self._visible:
            self._show_empty(query)
        else:
            now = time.time()
            total = len(self._visible)
            for index, account in enumerate(self._visible):
                card = AccountCard(self.list.inner, account, self, index, total)
                card.pack(fill="x", padx=16, pady=(0, 10))
                card.refresh(now)
                self.cards.append(card)
        self._render_status()

    def _show_empty(self, query: str) -> None:
        box = tk.Frame(self.list.inner, bg=BG)
        box.pack(fill="x", padx=28, pady=(36, 0))
        if not self.accounts:
            tk.Label(box, text="还没有账号", bg=BG, fg=TEXT, font=self.font_h2).pack(anchor="w")
            tk.Label(
                box,
                text=(
                    "在网站的两步验证里选择验证器应用，复制密钥后点右上角「添加」。\n"
                    "以 otpauth:// 开头的链接也可以直接粘贴。"
                ),
                bg=BG,
                fg=MUTED,
                font=self.font_ui,
                justify="left",
                wraplength=360,
            ).pack(anchor="w", pady=(8, 14))
            make_button(box, "添加账号", self.add_account, self.font_btn, "primary").pack(anchor="w")
        else:
            tk.Label(box, text="没有匹配的账号", bg=BG, fg=TEXT, font=self.font_h2).pack(anchor="w")
            tk.Label(
                box,
                text="换个关键词，或清空搜索框。",
                bg=BG,
                fg=MUTED,
                font=self.font_ui,
            ).pack(anchor="w", pady=(8, 0))
        self.empty = box

    def tick(self) -> None:
        self._tick_id = None
        if not self.winfo_exists():
            return
        now = time.time()
        for card in self.cards:
            card.refresh(now)
        self._render_status()
        self._tick_id = self.after(200, self.tick)

    def _render_status(self) -> None:
        if time.time() < self._toast_until:
            self.status.configure(text=self._toast_text, fg=DANGER if self._toast_danger else OK)
            return
        clock = datetime.now().strftime("%H:%M:%S")
        total = len(self.accounts)
        shown = len(self._visible)
        if shown == total:
            text = f"{total} 个账号   ·   本机时间 {clock}   ·   请保持系统时间准确"
        else:
            text = f"显示 {shown} / {total}   ·   本机时间 {clock}"
        self.status.configure(text=text, fg=MUTED)

    def toast(self, text: str, danger: bool = False) -> None:
        self._toast_text = text
        self._toast_danger = danger
        self._toast_until = time.time() + 2.4
        self._render_status()

    def _persist(self) -> bool:
        try:
            self.vault.save(self.accounts)
        except Exception as exc:
            log.exception("save failed")
            messagebox.showerror("保存失败", f"账号没有写入磁盘：{exc}", parent=self)
            return False
        return True

    def add_account(self, prefill: str = "") -> None:
        if not self._vault_ok:
            return
        dialog = AccountDialog(self, prefill=prefill)
        self.wait_window(dialog)
        if dialog.result is None:
            return
        self.accounts.append(dialog.result)
        if self._persist():
            self.query.set("")
            self.refresh_cards()
            self.toast("已添加账号")
        else:
            self.accounts.pop()

    def add_from_clipboard(self) -> None:
        try:
            text = self.clipboard_get().strip()
        except tk.TclError:
            messagebox.showinfo("剪贴板", "剪贴板里没有文本。", parent=self)
            return
        if not text:
            messagebox.showinfo("剪贴板", "剪贴板里没有文本。", parent=self)
            return
        self.add_account(prefill=text)

    def _restore(self, account: Account, data: dict) -> None:
        account.name = str(data.get("name") or "")
        account.issuer = str(data.get("issuer") or "")
        account.secret = str(data.get("secret") or "")
        account.digits = int(data.get("digits") or 6)
        account.period = int(data.get("period") or 30)
        account.algorithm = str(data.get("algorithm") or "SHA1")
        account.invalid_reason = str(data.get("invalid_reason") or "")

    def edit_account(self, account: Account) -> None:
        snapshot = account.to_dict()
        snapshot["invalid_reason"] = account.invalid_reason
        dialog = AccountDialog(self, account=account)
        self.wait_window(dialog)
        if dialog.deleted:
            previous = list(self.accounts)
            self.accounts = [item for item in self.accounts if item.id != account.id]
            if not self._persist():
                self.accounts = previous
                return
            self.refresh_cards()
            self.toast("已删除账号")
            return
        if dialog.result is None:
            return
        if not self._persist():
            self._restore(account, snapshot)
            return
        self.refresh_cards()
        self.toast("已保存修改")

    def delete_account(self, account: Account) -> None:
        ok = messagebox.askyesno(
            "删除账号",
            f"确定删除「{account.title}」吗？此操作不能撤销。",
            parent=self,
        )
        if not ok:
            return
        previous = list(self.accounts)
        self.accounts = [item for item in self.accounts if item.id != account.id]
        if not self._persist():
            self.accounts = previous
            return
        self.refresh_cards()
        self.toast("已删除账号")

    def move_account(self, account_id: str, delta: int) -> None:
        visible = self._visible
        index = next((i for i, account in enumerate(visible) if account.id == account_id), None)
        if index is None:
            return
        other = index + delta
        if other < 0 or other >= len(visible):
            return
        first = next(i for i, item in enumerate(self.accounts) if item is visible[index])
        second = next(i for i, item in enumerate(self.accounts) if item is visible[other])
        self.accounts[first], self.accounts[second] = self.accounts[second], self.accounts[first]
        if not self._persist():
            self.accounts[first], self.accounts[second] = self.accounts[second], self.accounts[first]
            return
        self.refresh_cards()

    def copy_code(self, account: Account) -> None:
        try:
            code, remaining = current_code(account)
        except ValueError as exc:
            messagebox.showerror("无法复制", str(exc), parent=self)
            return
        self.clipboard_clear()
        self.clipboard_append(code)
        self.update()
        shown = format_code(code)
        if remaining <= 5:
            self.toast(f"已复制 {shown}，{remaining} 秒后失效", danger=True)
        else:
            self.toast(f"已复制 {shown}")

    def copy_migration(self, account: Account) -> None:
        if account.invalid_reason:
            messagebox.showerror("无法复制", account.invalid_reason, parent=self)
            return
        ok = messagebox.askyesno(
            "复制迁移链接",
            "链接里包含这个账号的密钥。得到链接的人都能生成验证码。\n"
            "只把它粘贴到你自己的设备上。\n\n确定复制吗？",
            parent=self,
        )
        if not ok:
            return
        try:
            uri = provisioning_uri(account)
        except Exception:
            messagebox.showerror("无法复制", "无法生成迁移链接", parent=self)
            return
        self.clipboard_clear()
        self.clipboard_append(uri)
        self.update()
        self.toast("已复制迁移链接")

    def open_main_menu(self) -> None:
        menu = tk.Menu(self, tearoff=0)
        menu.add_command(label="从剪贴板添加", command=self.add_from_clipboard)
        menu.add_command(label="添加账号", command=self.add_account, accelerator="Ctrl+N")
        menu.add_separator()
        menu.add_command(label="导出备份…", command=self.export_backup)
        menu.add_command(label="导入备份…", command=self.import_backup)
        menu.add_separator()
        if self.vault.has_password:
            menu.add_command(label="验证密码", command=self.verify_vault_password)
            menu.add_command(label="修改密码", command=self.change_vault_password)
            if self.vault.can_reset_password:
                menu.add_command(label="忘记密码，重设", command=self.reset_vault_password)
        else:
            menu.add_command(label="设置密码", command=self.set_vault_password)
        menu.add_separator()
        menu.add_command(label="关于", command=self.show_about)
        menu.tk_popup(self.winfo_pointerx(), self.winfo_pointery())

    def set_vault_password(self) -> None:
        if not self._vault_ok or self.vault.has_password:
            return
        password = ask_password(
            self,
            "设置保险箱密码",
            confirm=True,
            prompt=_SET_PASSWORD_PROMPT,
            min_length=4,
        )
        if not password:
            return
        try:
            self.vault.set_password(password, self.accounts)
        except (ValueError, VaultError, OSError) as exc:
            messagebox.showerror("设置密码", str(exc), parent=self)
            return
        self.toast("已设置保险箱密码。本机以后会直接打开")

    def verify_vault_password(self) -> None:
        password = ask_password(
            self,
            "验证密码",
            confirm=False,
            prompt="输入保险箱密码，用来确认它是否正确。",
        )
        if not password:
            return
        try:
            ok = self.vault.verify_password(password)
        except VaultError as exc:
            messagebox.showerror("验证密码", str(exc), parent=self)
            return
        if ok:
            messagebox.showinfo("验证密码", "密码正确。", parent=self)
        else:
            messagebox.showerror("验证密码", "密码不正确。", parent=self)

    def change_vault_password(self) -> None:
        while self.winfo_exists():
            result = ask_password_change(self)
            if result is None:
                return
            current, new = result
            try:
                self.vault.change_password(current, new, self.accounts)
            except InvalidPassword:
                messagebox.showerror("修改密码", "当前密码不正确。", parent=self)
                continue
            except (ValueError, VaultError, OSError) as exc:
                messagebox.showerror("修改密码", str(exc), parent=self)
                return
            self.toast("密码已修改")
            return

    def reset_vault_password(self) -> None:
        if not self.vault.can_reset_password:
            messagebox.showinfo(
                "无法重设",
                "只有在这台电脑已经能直接打开保险箱时，才能不输入旧密码而重设。",
                parent=self,
            )
            return
        password = ask_password(
            self,
            "重设密码",
            confirm=True,
            prompt=(
                "这台电脑已经能打开保险箱，可以不输入旧密码，直接设置新密码。至少 4 位。\n\n"
                "换到另一台电脑后，要使用这个新密码。"
            ),
            min_length=4,
        )
        if not password:
            return
        try:
            self.vault.reset_password(password, self.accounts)
        except (ValueError, VaultError, OSError) as exc:
            messagebox.showerror("重设密码", str(exc), parent=self)
            return
        self.toast("密码已重设")

    def export_backup(self) -> None:
        if not self.accounts:
            messagebox.showinfo("导出备份", "还没有账号可以导出。", parent=self)
            return
        password = ask_password(self, "设置备份密码", confirm=True)
        if not password:
            return
        path = filedialog.asksaveasfilename(
            parent=self,
            title="导出备份",
            defaultextension=".authbak",
            filetypes=[("验证器备份", "*.authbak"), ("所有文件", "*.*")],
            initialfile="authenticator-backup.authbak",
        )
        if not path:
            return
        try:
            data = build_backup(self.accounts, password)
            Path(path).write_bytes(data)
        except ValueError as exc:
            messagebox.showerror("导出备份", str(exc), parent=self)
            return
        except OSError as exc:
            messagebox.showerror("导出备份", f"无法写入文件：{exc}", parent=self)
            return
        messagebox.showinfo(
            "导出备份",
            "备份已保存。请记住密码，换电脑时要用同一个密码才能导入。",
            parent=self,
        )

    def import_backup(self) -> None:
        if not self._vault_ok:
            return
        path = filedialog.askopenfilename(
            parent=self,
            title="导入备份",
            filetypes=[("验证器备份", "*.authbak"), ("所有文件", "*.*")],
        )
        if not path:
            return
        try:
            blob = Path(path).read_bytes()
        except OSError as exc:
            messagebox.showerror("导入备份", f"无法读取文件：{exc}", parent=self)
            return
        password = ask_password(self, "输入备份密码", confirm=False)
        if not password:
            return
        try:
            incoming = read_backup(blob, password)
        except InvalidBackup as exc:
            messagebox.showerror("导入备份", str(exc), parent=self)
            return
        existing = {account.id for account in self.accounts}
        added = [account for account in incoming if account.id not in existing]
        if not added:
            messagebox.showinfo("导入备份", "这些账号已经在列表里了。", parent=self)
            return
        self.accounts.extend(added)
        if not self._persist():
            del self.accounts[-len(added) :]
            return
        self.refresh_cards()
        skipped = len(incoming) - len(added)
        text = f"已导入 {len(added)} 个账号。"
        if skipped:
            text += f" 另有 {skipped} 个账号已存在，已跳过。"
        messagebox.showinfo("导入备份", text, parent=self)

    def show_about(self) -> None:
        dialog = tk.Toplevel(self)
        dialog.title("关于")
        dialog.configure(bg=BG)
        dialog.resizable(False, False)
        dialog.protocol("WM_DELETE_WINDOW", dialog.destroy)
        dialog.bind("<Escape>", lambda _event: dialog.destroy())
        body = (
            f"身份验证器  {__version__}\n\n"
            "生成与 Google 身份验证器相同的动态口令（TOTP）。\n"
            "登录 Google、GitHub、微软等开启了验证器的网站时，输入这里的数字即可。\n\n"
            "添加账号：在网站的两步验证里选择验证器应用，复制密钥，回到这里点「添加」。\n"
            "以 otpauth:// 开头的链接也可以直接粘贴。点击验证码即可复制。\n\n"
            "验证码默认每 30 秒变化一次，按这台电脑的时间计算。\n"
            "请在 Windows 设置中打开自动设置时间。\n"
            "数字变成红色时表示马上会刷新，等新码出现再输入更稳妥。\n\n"
            "密钥文件 vault.bin 保存在本程序同一目录。\n"
            "本机用 Windows 数据保护直接打开，不用输入密码。\n"
            "文件里同时有保险箱密码。拷到另一台电脑后，第一次要输入密码，之后那台电脑也会直接打开。\n"
            "可以在菜单里验证密码或修改密码。\n"
            "如果忘记密码，在还能直接打开的这台电脑上选择「忘记密码，重设」。\n\n"
            "数据文件："
        )
        tk.Label(
            dialog,
            text=body,
            bg=BG,
            fg=TEXT,
            font=self.font_ui,
            justify="left",
            wraplength=440,
            anchor="w",
        ).pack(padx=18, pady=(16, 8), anchor="w")
        path_var = tk.StringVar(value=str(self.vault.path))
        path_entry = tk.Entry(
            dialog,
            textvariable=path_var,
            font=self.font_small,
            readonlybackground=ENTRY,
            fg=TEXT,
            relief="flat",
            state="readonly",
            highlightthickness=1,
            highlightbackground=BORDER,
            bd=0,
        )
        path_entry.pack(fill="x", padx=18, ipady=4)
        row = tk.Frame(dialog, bg=BG)
        row.pack(fill="x", padx=18, pady=16)
        make_button(row, "打开所在目录", self._open_data_dir, self.font_btn, "ghost").pack(side="left")
        make_button(row, "关闭", dialog.destroy, self.font_btn, "primary").pack(side="right")
        place_dialog(dialog, self)

    def _open_data_dir(self) -> None:
        folder = self.vault.path.parent
        try:
            os.startfile(folder)  # type: ignore[attr-defined]
        except OSError as exc:
            messagebox.showerror("无法打开", str(exc), parent=self)

    def _on_close(self) -> None:
        if self._tick_id is not None:
            try:
                self.after_cancel(self._tick_id)
            except tk.TclError:
                pass
            self._tick_id = None
        try:
            self.unbind_all("<MouseWheel>")
        except tk.TclError:
            pass
        self.destroy()


_SET_PASSWORD_PROMPT = (
    "请设置保险箱密码，至少 4 位。\n\n"
    "这台电脑以后会直接打开，不用每次输入。\n"
    "把程序拷到另一台电脑时，第一次要输入这个密码。"
)


class PasswordDialog(tk.Toplevel):
    def __init__(
        self,
        parent,
        title: str,
        confirm: bool,
        prompt: str | None = None,
        min_length: int = 6,
    ):
        super().__init__(parent)
        self.result: str | None = None
        self.confirm = confirm
        self.min_length = min_length
        self.check_length = confirm or prompt is None
        self.title(title)
        self.configure(bg=BG)
        self.resizable(False, False)
        self.protocol("WM_DELETE_WINDOW", self.cancel)
        self.bind("<Escape>", lambda _event: self.cancel())

        frame = tk.Frame(self, bg=BG)
        frame.pack(fill="both", expand=True, padx=18, pady=16)
        if prompt is None:
            prompt = (
                "设置备份密码，至少 6 位。导入时需要填写同一个密码。"
                if confirm
                else "输入导出这份备份时设置的密码。"
            )
        tk.Label(
            frame,
            text=prompt,
            bg=BG,
            fg=MUTED,
            font=parent.font_small,
            wraplength=360,
            justify="left",
        ).pack(anchor="w", pady=(0, 10))

        self.first = tk.Entry(frame, show="*", font=parent.font_ui, width=36)
        style_input(self.first)
        self.first.pack(fill="x", ipady=5)
        self.second: tk.Entry | None = None
        if confirm:
            tk.Label(frame, text="再输入一次", bg=BG, fg=MUTED, font=parent.font_small).pack(
                anchor="w", pady=(10, 4)
            )
            self.second = tk.Entry(frame, show="*", font=parent.font_ui, width=36)
            style_input(self.second)
            self.second.pack(fill="x", ipady=5)
            self.second.bind("<Return>", lambda _event: self.ok())
        self.err = tk.Label(frame, text="", bg=BG, fg=DANGER, font=parent.font_small, anchor="w")
        self.err.pack(anchor="w", fill="x", pady=(8, 8))
        row = tk.Frame(frame, bg=BG)
        row.pack(fill="x")
        make_button(row, "确定", self.ok, parent.font_btn, "primary").pack(side="right")
        make_button(row, "取消", self.cancel, parent.font_btn, "ghost").pack(side="right", padx=(0, 8))
        self.first.bind("<Return>", lambda _event: self.ok())
        self.first.focus_set()
        place_dialog(self, parent)

    def ok(self) -> None:
        password = self.first.get()
        if self.check_length and len(password) < self.min_length:
            self.err.configure(text=f"密码至少 {self.min_length} 位")
            return
        if not password:
            self.err.configure(text="请输入密码")
            return
        if self.second is not None and password != self.second.get():
            self.err.configure(text="两次输入的密码不一致")
            return
        self.result = password
        self.destroy()

    def cancel(self) -> None:
        self.result = None
        self.destroy()


def ask_password(
    parent,
    title: str,
    confirm: bool,
    prompt: str | None = None,
    min_length: int = 6,
) -> str | None:
    dialog = PasswordDialog(parent, title, confirm, prompt, min_length)
    parent.wait_window(dialog)
    return dialog.result


class ChangePasswordDialog(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.result: tuple[str, str] | None = None
        self.title("修改密码")
        self.configure(bg=BG)
        self.resizable(False, False)
        self.protocol("WM_DELETE_WINDOW", self.cancel)
        self.bind("<Escape>", lambda _event: self.cancel())

        frame = tk.Frame(self, bg=BG)
        frame.pack(fill="both", expand=True, padx=18, pady=16)
        tk.Label(
            frame,
            text="先输入当前密码，再设置新密码。至少 4 位。",
            bg=BG,
            fg=MUTED,
            font=parent.font_small,
            wraplength=360,
            justify="left",
        ).pack(anchor="w", pady=(0, 10))
        self.current = self._entry(frame, "当前密码")
        self.new = self._entry(frame, "新密码")
        self.again = self._entry(frame, "再输入一次新密码")
        self.err = tk.Label(frame, text="", bg=BG, fg=DANGER, font=parent.font_small, anchor="w")
        self.err.pack(anchor="w", fill="x", pady=(8, 8))
        row = tk.Frame(frame, bg=BG)
        row.pack(fill="x")
        make_button(row, "确定", self.ok, parent.font_btn, "primary").pack(side="right")
        make_button(row, "取消", self.cancel, parent.font_btn, "ghost").pack(side="right", padx=(0, 8))
        self.again.bind("<Return>", lambda _event: self.ok())
        self.current.focus_set()
        place_dialog(self, parent)

    def _entry(self, parent, label: str) -> tk.Entry:
        tk.Label(parent, text=label, bg=BG, fg=MUTED, font=self.master.font_small).pack(anchor="w", pady=(8, 4))
        entry = tk.Entry(parent, show="*", font=self.master.font_ui, width=36)
        style_input(entry)
        entry.pack(fill="x", ipady=5)
        return entry

    def ok(self) -> None:
        current = self.current.get()
        new = self.new.get()
        if not current:
            self.err.configure(text="请输入当前密码")
            return
        if len(new) < 4:
            self.err.configure(text="新密码至少 4 位")
            return
        if new != self.again.get():
            self.err.configure(text="两次输入的新密码不一致")
            return
        if new == current:
            self.err.configure(text="新密码与当前密码相同")
            return
        self.result = (current, new)
        self.destroy()

    def cancel(self) -> None:
        self.result = None
        self.destroy()


def ask_password_change(parent) -> tuple[str, str] | None:
    dialog = ChangePasswordDialog(parent)
    parent.wait_window(dialog)
    return dialog.result


def main() -> None:
    enable_windows_dpi()
    set_windows_app_id()
    app = App()
    app.mainloop()
