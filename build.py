"""生成图标并打包成单个 exe。"""

from __future__ import annotations

import os
import sys
from pathlib import Path


def create_icon(path: Path) -> None:
    from PIL import Image, ImageDraw, ImageFont

    image = Image.new("RGBA", (256, 256), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)
    draw.rounded_rectangle((12, 12, 244, 244), radius=56, fill=(26, 115, 232, 255))
    try:
        font = ImageFont.truetype(r"C:\Windows\Fonts\segoeuib.ttf", 84)
    except OSError:
        font = ImageFont.load_default()
    draw.text((128, 138), "123", font=font, fill="white", anchor="mm")
    path.parent.mkdir(parents=True, exist_ok=True)
    image.save(
        path,
        format="ICO",
        sizes=[(256, 256), (64, 64), (48, 48), (32, 32), (16, 16)],
    )


def main() -> None:
    import PyInstaller.__main__

    root = Path(__file__).resolve().parent
    icon = root / "assets" / "app.ico"
    try:
        create_icon(icon)
    except Exception as exc:
        print(f"图标未生成，将使用默认图标：{exc}")
        icon = None

    args = [
        str(root / "main.py"),
        "--noconfirm",
        "--clean",
        "--windowed",
        "--onefile",
        "--name",
        "Authenticator",
        "--distpath",
        str(root / "dist"),
        "--workpath",
        str(root / "build"),
        "--specpath",
        str(root),
        "--collect-all",
        "cryptography",
    ]
    if icon is not None and icon.exists():
        args.extend(
            [
                "--icon",
                str(icon),
                "--add-data",
                f"{icon}{os.pathsep}assets",
            ]
        )
    PyInstaller.__main__.run(args)
    exe = root / "dist" / "Authenticator.exe"
    if not exe.exists():
        sys.exit("没有找到 dist/Authenticator.exe")
    print(f"已生成 {exe} （{exe.stat().st_size} 字节）")


if __name__ == "__main__":
    main()
