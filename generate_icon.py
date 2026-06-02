from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw


def build_icon(output_path: Path) -> None:
    size = 256
    image = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)

    draw.ellipse((12, 12, 244, 244), fill=(11, 21, 35, 255), outline=(56, 189, 248, 255), width=8)
    draw.ellipse((30, 30, 226, 226), fill=(15, 28, 46, 255), outline=(125, 211, 252, 255), width=3)

    shield = [(128, 58), (192, 84), (181, 147), (128, 198), (75, 147), (64, 84)]
    draw.polygon(shield, fill=(14, 165, 233, 255), outline=(224, 242, 254, 255))
    draw.line((93, 113, 120, 138), fill=(240, 249, 255, 255), width=11)
    draw.line((120, 138, 165, 95), fill=(240, 249, 255, 255), width=11)

    draw.rounded_rectangle((56, 176, 200, 214), radius=18, fill=(8, 15, 26, 255), outline=(45, 212, 191, 255), width=3)
    draw.text((83, 183), "AV", fill=(204, 251, 241, 255))

    output_path.parent.mkdir(parents=True, exist_ok=True)
    image.save(output_path, format="ICO", sizes=[(256, 256), (128, 128), (64, 64), (48, 48), (32, 32), (16, 16)])


if __name__ == "__main__":
    build_icon(Path("assets") / "command_av.ico")
