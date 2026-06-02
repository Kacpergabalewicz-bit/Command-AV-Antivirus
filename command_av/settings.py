from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path

from command_av.utils import default_monitor_paths, default_quick_scan_paths


@dataclass
class AppSettings:
    excluded_paths: list[str] = field(default_factory=list)
    monitored_paths: list[str] = field(default_factory=list)
    quick_scan_paths: list[str] = field(default_factory=list)
    language: str = "pl"
    include_archives: bool = True
    scan_hidden_files: bool = True
    automatic_quarantine: bool = False
    realtime_enabled: bool = False
    scan_processes_with_full_scan: bool = True
    max_file_size_mb: int = 32


def default_settings() -> AppSettings:
    return AppSettings(
        excluded_paths=[],
        monitored_paths=[str(path) for path in default_monitor_paths()],
        quick_scan_paths=[str(path) for path in default_quick_scan_paths()],
    )


def load_settings(app_dir: Path) -> AppSettings:
    app_dir.mkdir(parents=True, exist_ok=True)
    settings_path = app_dir / "settings.json"
    if not settings_path.exists():
        settings = default_settings()
        settings_path.write_text(json.dumps(asdict(settings), indent=2, ensure_ascii=False), encoding="utf-8")
        return settings
    data = json.loads(settings_path.read_text(encoding="utf-8"))
    return AppSettings(**data)


def save_settings(app_dir: Path, settings: AppSettings) -> Path:
    app_dir.mkdir(parents=True, exist_ok=True)
    settings_path = app_dir / "settings.json"
    settings_path.write_text(json.dumps(asdict(settings), indent=2, ensure_ascii=False), encoding="utf-8")
    return settings_path
