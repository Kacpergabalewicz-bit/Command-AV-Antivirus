from __future__ import annotations

import json
from pathlib import Path

from command_av.scanner import Signature


DEFAULT_SIGNATURES = {
    "signatures": [
        {
            "name": "EICAR.Test.File",
            "description": "Standardowy plik testowy antywirusów EICAR.",
            "severity": "low",
            "sha256": [
                "275a021bbfb6489e54d471899f7db9d1b3b770dbd1d9c6427c4831e62c5e9b2b"
            ],
            "file_name_patterns": ["eicar"],
            "content_patterns": ["X5O!P%@AP\\[4\\PZX54\\(P\\^\\)7CC\\)7\\$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!"]
        },
        {
            "name": "Suspicious.Dropper.Script",
            "description": "Podejrzany skrypt z technikami pobierania i uruchamiania payloadu.",
            "severity": "high",
            "sha256": [],
            "file_name_patterns": ["dropper", "payload", "loader"],
            "content_patterns": [
                "DownloadString\\(",
                "Invoke-WebRequest",
                "Start-BitsTransfer",
                "CreateObject\\(\\\"Wscript\\.Shell\\\"\\)",
                "powershell\\s+-w\\s+hidden"
            ]
        },
        {
            "name": "Credential.Stealer.Pattern",
            "description": "Wzorzec skryptu próbującego odczytywać hasła lub ciasteczka.",
            "severity": "high",
            "sha256": [],
            "file_name_patterns": ["stealer", "password", "cookies"],
            "content_patterns": [
                "Login Data",
                "Local State",
                "CryptUnprotectData",
                "AppData\\\\Local\\\\Google\\\\Chrome"
            ]
        },
        {
            "name": "Ransomware.Like.Behavior.Pattern",
            "description": "Wzorzec skryptu modyfikującego wiele plików i usuwającego kopie zapasowe.",
            "severity": "critical",
            "sha256": [],
            "file_name_patterns": ["decrypt", "encrypt", "ransom", "locker"],
            "content_patterns": [
                "vssadmin\\s+delete\\s+shadows",
                "wbadmin\\s+delete\\s+catalog",
                "bcdedit\\s+/set\\s+\\{default\\}\\s+recoveryenabled\\s+No",
                "README_RECOVER|README_DECRYPT|HOW_TO_DECRYPT"
            ]
        },
        {
            "name": "LOLBins.Remote.Execution.Pattern",
            "description": "Zdalne uruchamianie z użyciem narzędzi systemowych Windows.",
            "severity": "high",
            "sha256": [],
            "file_name_patterns": ["invoice", "update", "security_patch"],
            "content_patterns": [
                "mshta\\s+https?://",
                "rundll32.*javascript:",
                "regsvr32\\s+/s\\s+/n\\s+/u\\s+/i:https?://",
                "bitsadmin\\s+/transfer"
            ]
        },
        {
            "name": "Macro.Downloader.Pattern",
            "description": "Wzorzec downloadera ukrytego w skryptach VBA lub dokumentach tekstowych.",
            "severity": "high",
            "sha256": [],
            "file_name_patterns": ["macro", "invoice", "payment", "statement"],
            "content_patterns": [
                "AutoOpen\\(",
                "Document_Open\\(",
                "Shell\\(",
                "URLDownloadToFileA",
                "CreateObject\\(\\\"MSXML2.XMLHTTP\\\"\\)"
            ]
        }
    ]
}


def ensure_default_signature_store(base_dir: Path) -> Path:
    base_dir.mkdir(parents=True, exist_ok=True)
    signature_path = base_dir / "signatures.json"
    if not signature_path.exists():
        signature_path.write_text(json.dumps(DEFAULT_SIGNATURES, indent=2), encoding="utf-8")
    return signature_path


def load_signatures(signature_file: Path) -> list[Signature]:
    raw = json.loads(signature_file.read_text(encoding="utf-8"))
    signatures: list[Signature] = []
    for item in raw.get("signatures", []):
        signatures.append(
            Signature(
                name=item["name"],
                description=item.get("description", ""),
                severity=item.get("severity", "medium"),
                sha256=set(item.get("sha256", [])),
                file_name_patterns=item.get("file_name_patterns", []),
                content_patterns=item.get("content_patterns", []),
            )
        )
    return signatures
