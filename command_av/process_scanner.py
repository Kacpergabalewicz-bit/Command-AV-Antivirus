from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import psutil

from command_av.scanner import ScanOptions, Signature, scan_single_file


@dataclass
class ProcessFinding:
    pid: int
    name: str
    executable: str
    threat_name: str
    severity: str
    method: str
    details: str


def scan_running_processes(signatures: list[Signature], options: ScanOptions | None = None) -> tuple[list[ProcessFinding], int, int]:
    options = options or ScanOptions()
    findings: list[ProcessFinding] = []
    scanned = 0
    errors = 0

    suspicious_cmd_patterns = {
        r"powershell(.+) -enc(odedcommand)? ": "Encoded PowerShell command",
        r"mshta\s+https?://": "MSHTA loading remote content",
        r"regsvr32(.+)/i:https?://": "Regsvr32 remote scriptlet execution",
        r"rundll32(.+)javascript:": "Rundll32 JavaScript execution",
        r"certutil(.+)-urlcache(.+)-split(.+)-f": "Certutil download pattern",
    }

    for proc in psutil.process_iter(["pid", "name", "exe", "cmdline"]):
        scanned += 1
        try:
            info = proc.info
            exe = info.get("exe") or ""
            name = info.get("name") or "unknown"
            cmdline = " ".join(info.get("cmdline") or [])
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            errors += 1
            continue

        if exe:
            path = Path(exe)
            file_findings = scan_single_file(path, signatures, options)
            for finding in file_findings:
                findings.append(
                    ProcessFinding(
                        pid=proc.pid,
                        name=name,
                        executable=exe,
                        threat_name=finding.threat_name,
                        severity=finding.severity,
                        method=f"process-file:{finding.method}",
                        details=finding.description,
                    )
                )

        for pattern, description in suspicious_cmd_patterns.items():
            if cmdline and re.search(pattern, cmdline, re.IGNORECASE):
                findings.append(
                    ProcessFinding(
                        pid=proc.pid,
                        name=name,
                        executable=exe,
                        threat_name="Suspicious.Process.CommandLine",
                        severity="high",
                        method="command-line-heuristic",
                        details=description,
                    )
                )
                break

    return findings, scanned, errors
