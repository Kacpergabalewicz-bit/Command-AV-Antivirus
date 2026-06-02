from __future__ import annotations

import logging
from pathlib import Path


LOGGER_NAME = "command_av"


def setup_logging(log_dir: Path) -> Path:
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / "command_av.log"
    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(logging.INFO)
    logger.propagate = False

    if not any(isinstance(handler, logging.FileHandler) and Path(handler.baseFilename) == log_file for handler in logger.handlers):
        handler = logging.FileHandler(log_file, encoding="utf-8")
        formatter = logging.Formatter("%(asctime)s | %(levelname)s | %(message)s")
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    return log_file


def get_logger() -> logging.Logger:
    return logging.getLogger(LOGGER_NAME)


def read_recent_logs(log_file: Path, max_lines: int = 250) -> str:
    if not log_file.exists():
        return "Brak logów."
    lines = log_file.read_text(encoding="utf-8", errors="ignore").splitlines()
    return "\n".join(lines[-max_lines:])
