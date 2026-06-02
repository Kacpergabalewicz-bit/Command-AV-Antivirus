from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime, UTC
from pathlib import Path
from typing import Any

from command_av.scanner import Finding, ScanStats


def write_report(
    output_dir: Path,
    target: Path | str,
    findings: list[Finding],
    stats: ScanStats,
    *,
    process_findings: list[dict[str, Any]] | None = None,
    live_alerts: list[dict[str, Any]] | None = None,
    metadata: dict[str, Any] | None = None,
) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    report_path = output_dir / f"scan-report-{timestamp}.json"
    payload = {
        "target": str(target),
        "generated_at": datetime.now(UTC).isoformat(),
        "stats": asdict(stats),
        "findings": [asdict(finding) for finding in findings],
        "process_findings": process_findings or [],
        "live_alerts": live_alerts or [],
        "metadata": metadata or {},
    }
    report_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return report_path
