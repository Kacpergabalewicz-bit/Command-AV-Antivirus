from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from threading import Lock, Thread
import time

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

from command_av.scanner import Finding, ScanOptions, Signature, scan_single_file


@dataclass
class LiveAlert:
    timestamp: str
    path: str
    threat_name: str
    severity: str
    action: str
    method: str


class _MonitorHandler(FileSystemEventHandler):
    def __init__(self, monitor: "LiveMonitor") -> None:
        self.monitor = monitor

    def on_created(self, event: FileSystemEvent) -> None:
        self.monitor.handle_event(event)

    def on_modified(self, event: FileSystemEvent) -> None:
        self.monitor.handle_event(event)


class LiveMonitor:
    def __init__(self, signatures: list[Signature], options: ScanOptions, on_alert) -> None:
        self.signatures = signatures
        self.options = options
        self.on_alert = on_alert
        self.observer: Observer | None = None
        self._lock = Lock()
        self._recent: dict[str, float] = {}

    @property
    def is_running(self) -> bool:
        return self.observer is not None and self.observer.is_alive()

    def start(self, paths: list[Path]) -> None:
        if self.is_running:
            return
        self.observer = Observer()
        handler = _MonitorHandler(self)
        for path in paths:
            if path.exists():
                self.observer.schedule(handler, str(path), recursive=True)
        self.observer.start()

    def stop(self) -> None:
        if self.observer is None:
            return
        self.observer.stop()
        self.observer.join(timeout=3)
        self.observer = None

    def handle_event(self, event: FileSystemEvent) -> None:
        if event.is_directory:
            return
        path = Path(event.src_path)
        now = time.time()
        with self._lock:
            last = self._recent.get(str(path), 0)
            if now - last < 2:
                return
            self._recent[str(path)] = now
        Thread(target=self._scan_file, args=(path,), daemon=True).start()

    def _scan_file(self, path: Path) -> None:
        findings = scan_single_file(path, self.signatures, self.options)
        for finding in findings:
            alert = LiveAlert(
                timestamp=datetime.now(UTC).isoformat(),
                path=str(path),
                threat_name=finding.threat_name,
                severity=finding.severity,
                action="detected",
                method=finding.method,
            )
            self.on_alert(alert, finding)
