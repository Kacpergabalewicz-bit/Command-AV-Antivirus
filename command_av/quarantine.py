from __future__ import annotations

import json
import shutil
from dataclasses import asdict, dataclass
from datetime import datetime, UTC
from pathlib import Path

from command_av.scanner import Finding


@dataclass
class QuarantineEntry:
    original_path: str
    quarantined_path: str
    threat_name: str
    severity: str
    quarantined_at: str
    original_size: int = 0


def _manifest_path(quarantine_dir: Path) -> Path:
    quarantine_dir.mkdir(parents=True, exist_ok=True)
    return quarantine_dir / "manifest.json"


def load_manifest(quarantine_dir: Path) -> list[QuarantineEntry]:
    manifest = _manifest_path(quarantine_dir)
    if not manifest.exists():
        return []
    data = json.loads(manifest.read_text(encoding="utf-8"))
    return [QuarantineEntry(**item) for item in data]


def save_manifest(quarantine_dir: Path, entries: list[QuarantineEntry]) -> None:
    manifest = _manifest_path(quarantine_dir)
    manifest.write_text(
        json.dumps([asdict(entry) for entry in entries], indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


def quarantine_file(file_path: Path, finding: Finding, quarantine_dir: Path) -> QuarantineEntry:
    quarantine_dir.mkdir(parents=True, exist_ok=True)
    target_name = f"{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}_{file_path.name}.quarantine"
    target_path = quarantine_dir / target_name
    shutil.move(str(file_path), str(target_path))

    entry = QuarantineEntry(
        original_path=str(file_path),
        quarantined_path=str(target_path),
        threat_name=finding.threat_name,
        severity=finding.severity,
        quarantined_at=datetime.now(UTC).isoformat(),
        original_size=file_path.stat().st_size if file_path.exists() else 0,
    )
    entries = load_manifest(quarantine_dir)
    entries.append(entry)
    save_manifest(quarantine_dir, entries)
    return entry


def restore_file(entry: QuarantineEntry, quarantine_dir: Path) -> Path:
    original_path = Path(entry.original_path)
    original_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(entry.quarantined_path, original_path)
    entries = [item for item in load_manifest(quarantine_dir) if item.quarantined_path != entry.quarantined_path]
    save_manifest(quarantine_dir, entries)
    return original_path


def delete_quarantined(entry: QuarantineEntry, quarantine_dir: Path) -> None:
    quarantined = Path(entry.quarantined_path)
    if quarantined.exists():
        quarantined.unlink()
    entries = [item for item in load_manifest(quarantine_dir) if item.quarantined_path != entry.quarantined_path]
    save_manifest(quarantine_dir, entries)
