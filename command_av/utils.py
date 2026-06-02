from __future__ import annotations

import ctypes
import os
from pathlib import Path


def get_windows_drives() -> list[Path]:
    drives: list[Path] = []
    bitmask = ctypes.windll.kernel32.GetLogicalDrives()
    for index in range(26):
        if bitmask & (1 << index):
            letter = chr(65 + index)
            drive = Path(f"{letter}:\\")
            if drive.exists():
                drives.append(drive)
    return drives


def unique_existing_paths(paths: list[Path]) -> list[Path]:
    seen: set[str] = set()
    result: list[Path] = []
    for path in paths:
        normalized = str(path).lower()
        if normalized in seen:
            continue
        if path.exists():
            seen.add(normalized)
            result.append(path)
    return result


def default_quick_scan_paths() -> list[Path]:
    home = Path.home()
    appdata = Path(os.environ.get("APPDATA", home))
    local_appdata = Path(os.environ.get("LOCALAPPDATA", home))
    candidates = [
        home / "Desktop",
        home / "Downloads",
        home / "Documents",
        local_appdata / "Temp",
        appdata / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup",
    ]
    return unique_existing_paths(candidates)


def default_monitor_paths() -> list[Path]:
    home = Path.home()
    return unique_existing_paths([home / "Desktop", home / "Downloads"])


def format_bytes(size: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB"]
    value = float(size)
    for unit in units:
        if value < 1024 or unit == units[-1]:
            return f"{value:.1f} {unit}" if unit != "B" else f"{int(value)} B"
        value /= 1024
    return f"{size} B"
