from __future__ import annotations

import hashlib
import os
import re
import time
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable


@dataclass
class Signature:
    name: str
    description: str
    severity: str
    sha256: set[str]
    file_name_patterns: list[str]
    content_patterns: list[str]


@dataclass
class Finding:
    path: str
    threat_name: str
    method: str
    severity: str
    description: str
    source: str = "filesystem"
    score: int = 0
    sha256: str = ""
    size: int = 0
    details: str = ""


@dataclass
class ScanOptions:
    recursive: bool = True
    max_file_size_mb: int = 32
    include_archives: bool = True
    scan_hidden_files: bool = True
    excluded_paths: tuple[str, ...] = ()


@dataclass
class ScanStats:
    scanned_files: int = 0
    infected_files: int = 0
    errors: int = 0
    scanned_archives: int = 0
    scanned_targets: int = 0
    scanned_processes: int = 0
    suspicious_processes: int = 0
    duration_seconds: float = 0.0


ProgressCallback = Callable[[int, str], None]


def severity_to_score(severity: str) -> int:
    return {
        "low": 30,
        "medium": 60,
        "high": 85,
        "critical": 100,
    }.get(severity.lower(), 50)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file_handle:
        for chunk in iter(lambda: file_handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _normalize(path: Path | str) -> str:
    return str(Path(path)).lower()


def _is_excluded(path: Path, excluded_paths: tuple[str, ...]) -> bool:
    normalized = _normalize(path)
    return any(normalized.startswith(excluded) for excluded in excluded_paths)


def _is_probably_hidden(path: Path) -> bool:
    return any(part.startswith(".") for part in path.parts if part not in {path.drive, path.anchor})


def iter_files(target: Path, options: ScanOptions) -> Iterable[Path]:
    if target.is_file():
        if not _is_excluded(target, options.excluded_paths):
            yield target
        return

    if options.recursive:
        for root, _, file_names in os.walk(target):
            for file_name in file_names:
                child = Path(root) / file_name
                if _is_excluded(child, options.excluded_paths):
                    continue
                if not options.scan_hidden_files and _is_probably_hidden(child):
                    continue
                yield child
    else:
        for child in target.iterdir():
            if child.is_file() and not _is_excluded(child, options.excluded_paths):
                yield child


def _text_preview(path: Path, max_bytes: int) -> str:
    return path.read_bytes()[:max_bytes].decode("utf-8", errors="ignore")


def _build_finding(
    path: Path | str,
    threat_name: str,
    method: str,
    severity: str,
    description: str,
    *,
    source: str = "filesystem",
    sha256: str = "",
    size: int = 0,
    details: str = "",
) -> Finding:
    return Finding(
        path=str(path),
        threat_name=threat_name,
        method=method,
        severity=severity,
        description=description,
        source=source,
        score=severity_to_score(severity),
        sha256=sha256,
        size=size,
        details=details,
    )


def _match_signature(path: Path, signature: Signature) -> Finding | None:
    file_name = path.name
    try:
        size = path.stat().st_size
    except OSError:
        size = 0

    for pattern in signature.file_name_patterns:
        if re.search(pattern, file_name, re.IGNORECASE):
            return _build_finding(
                path,
                signature.name,
                f"filename:{pattern}",
                signature.severity,
                signature.description,
                size=size,
            )

    if signature.sha256:
        try:
            file_hash = sha256_file(path)
            if file_hash in signature.sha256:
                return _build_finding(
                    path,
                    signature.name,
                    "sha256",
                    signature.severity,
                    signature.description,
                    sha256=file_hash,
                    size=size,
                )
        except OSError:
            return None

    if signature.content_patterns:
        try:
            preview = _text_preview(path, 2_000_000)
            for pattern in signature.content_patterns:
                if re.search(pattern, preview, re.IGNORECASE | re.MULTILINE):
                    return _build_finding(
                        path,
                        signature.name,
                        f"content:{pattern}",
                        signature.severity,
                        signature.description,
                        size=size,
                    )
        except OSError:
            return None

    return None


def heuristic_check(path: Path) -> Finding | None:
    suspicious_extensions = {".bat", ".cmd", ".ps1", ".vbs", ".js"}

    try:
        text = path.read_text(encoding="utf-8", errors="ignore")[:200_000]
        size = path.stat().st_size
    except OSError:
        return None

    indicators = [
        r"Invoke-Expression",
        r"FromBase64String",
        r"powershell\s+-enc",
        r"certutil\s+-decode",
        r"reg\s+add\s+HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        r"Start-Process\s+.*-WindowStyle\s+Hidden",
        r"mshta\s+https?://",
        r"regsvr32\s+/s\s+/n\s+/u\s+/i:https?://",
        r"rundll32.*javascript:",
    ]

    matched = [indicator for indicator in indicators if re.search(indicator, text, re.IGNORECASE)]

    double_extension = re.search(r"\.(pdf|doc|docx|jpg|png|xls|xlsx)\.(exe|scr|bat|cmd|js|vbs|ps1)$", path.name, re.IGNORECASE)
    autorun_pattern = path.name.lower() == "autorun.inf" and re.search(r"open=|shellexecute=", text, re.IGNORECASE)

    if double_extension:
        return _build_finding(
            path,
            "Suspicious.Double.Extension",
            "heuristic:double-extension",
            "high",
            "Plik używa podwójnego rozszerzenia typowego dla malware.",
            size=size,
        )

    if autorun_pattern:
        return _build_finding(
            path,
            "Suspicious.Autorun.Configuration",
            "heuristic:autorun",
            "high",
            "Wykryto podejrzany wpis autorun uruchamiający plik wykonywalny lub skrypt.",
            size=size,
        )

    if path.suffix.lower() in suspicious_extensions and len(matched) >= 2:
        severity = "high" if len(matched) >= 3 else "medium"
        return _build_finding(
            path,
            "Suspicious.Script.Heuristic",
            "heuristic",
            severity,
            "Wykryto kombinację podejrzanych wzorców w skrypcie.",
            size=size,
            details=", ".join(matched[:4]),
        )

    return None


def _scan_zip_archive(path: Path, signatures: list[Signature]) -> list[Finding]:
    findings: list[Finding] = []
    try:
        with zipfile.ZipFile(path) as archive:
            for member in archive.infolist():
                member_name = member.filename
                if member.is_dir():
                    continue

                for signature in signatures:
                    matched_name = next(
                        (pattern for pattern in signature.file_name_patterns if re.search(pattern, member_name, re.IGNORECASE)),
                        None,
                    )
                    if matched_name:
                        findings.append(
                            _build_finding(
                                f"{path}::{member_name}",
                                signature.name,
                                f"archive-filename:{matched_name}",
                                signature.severity,
                                signature.description,
                                source="archive",
                                size=member.file_size,
                            )
                        )
                        break

                if member.file_size > 2_000_000:
                    continue

                try:
                    preview = archive.read(member)[:500_000].decode("utf-8", errors="ignore")
                except OSError:
                    continue

                for signature in signatures:
                    matched_content = next(
                        (
                            pattern
                            for pattern in signature.content_patterns
                            if re.search(pattern, preview, re.IGNORECASE | re.MULTILINE)
                        ),
                        None,
                    )
                    if matched_content:
                        findings.append(
                            _build_finding(
                                f"{path}::{member_name}",
                                signature.name,
                                f"archive-content:{matched_content}",
                                signature.severity,
                                signature.description,
                                source="archive",
                                size=member.file_size,
                            )
                        )
                        break
    except (OSError, zipfile.BadZipFile):
        return []
    return findings


def scan_single_file(path: Path, signatures: list[Signature], options: ScanOptions | None = None) -> list[Finding]:
    options = options or ScanOptions()
    findings: list[Finding] = []

    try:
        if not path.is_file():
            return findings
        if _is_excluded(path, options.excluded_paths):
            return findings
    except OSError:
        return findings

    matched = next((item for item in (_match_signature(path, signature) for signature in signatures) if item), None)
    if matched:
        findings.append(matched)

    heuristic = heuristic_check(path)
    if heuristic and not findings:
        findings.append(heuristic)

    if options.include_archives and path.suffix.lower() == ".zip":
        findings.extend(_scan_zip_archive(path, signatures))

    return findings


def scan_path(
    target: Path,
    signatures: list[Signature],
    options: ScanOptions | None = None,
    progress_callback: ProgressCallback | None = None,
) -> tuple[list[Finding], ScanStats]:
    options = options or ScanOptions()
    findings: list[Finding] = []
    stats = ScanStats(scanned_targets=1)
    started = time.perf_counter()

    for file_path in iter_files(target, options):
        stats.scanned_files += 1
        if progress_callback:
            progress_callback(stats.scanned_files, str(file_path))

        try:
            if not file_path.is_file():
                continue
        except OSError:
            stats.errors += 1
            continue

        try:
            file_findings = scan_single_file(file_path, signatures, options)
            findings.extend(file_findings)
            if options.include_archives and file_path.suffix.lower() == ".zip":
                stats.scanned_archives += 1
        except OSError:
            stats.errors += 1

    stats.infected_files = len(findings)
    stats.duration_seconds = round(time.perf_counter() - started, 2)
    return findings, stats


def scan_multiple_targets(
    targets: list[Path],
    signatures: list[Signature],
    options: ScanOptions | None = None,
    progress_callback: ProgressCallback | None = None,
) -> tuple[list[Finding], ScanStats]:
    options = options or ScanOptions()
    all_findings: list[Finding] = []
    combined = ScanStats(scanned_targets=len(targets))
    started = time.perf_counter()

    for target in targets:
        findings, stats = scan_path(target, signatures, options=options, progress_callback=progress_callback)
        all_findings.extend(findings)
        combined.scanned_files += stats.scanned_files
        combined.infected_files += stats.infected_files
        combined.errors += stats.errors
        combined.scanned_archives += stats.scanned_archives

    combined.duration_seconds = round(time.perf_counter() - started, 2)
    return all_findings, combined
