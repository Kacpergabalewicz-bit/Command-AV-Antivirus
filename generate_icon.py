from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw


def build_icon(output_path: Path) -> None:
    size = 256
    image = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)

    draw.rounded_rectangle((18, 18, 238, 238), radius=54, fill=(10, 18, 32, 255), outline=(0, 217, 255, 255), width=8)
    draw.rounded_rectangle((42, 42, 214, 214), radius=42, fill=(16, 28, 48, 255), outline=(84, 225, 255, 255), width=4)

    shield = [(128, 54), (196, 82), (186, 148), (128, 206), (70, 148), (60, 82)]
    draw.polygon(shield, fill=(25, 175, 255, 255), outline=(220, 248, 255, 255))
    draw.line((92, 110, 119, 138), fill=(255, 255, 255, 255), width=12)
    draw.line((119, 138, 166, 92), fill=(255, 255, 255, 255), width=12)

    draw.rounded_rectangle((54, 176, 202, 212), radius=14, fill=(6, 12, 22, 255), outline=(0, 255, 170, 255), width=3)
    draw.text((76, 181), ">_", fill=(0, 255, 170, 255))
    draw.text((120, 181), "AV", fill=(220, 248, 255, 255))

    output_path.parent.mkdir(parents=True, exist_ok=True)
    image.save(output_path, format="ICO", sizes=[(256, 256), (128, 128), (64, 64), (48, 48), (32, 32), (16, 16)])


if __name__ == "__main__":
    build_icon(Path("assets") / "command_av.ico")
