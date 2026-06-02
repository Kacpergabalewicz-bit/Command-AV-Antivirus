from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path
import tkinter as tk
from tkinter import messagebox, ttk


APP_NAME = "Command AV"
INSTALL_ROOT = Path.home() / "AppData" / "Local" / "Programs" / APP_NAME
DESKTOP_DIR = Path.home() / "Desktop"
START_MENU_DIR = Path.home() / "AppData" / "Roaming" / "Microsoft" / "Windows" / "Start Menu" / "Programs"


def bundled_path(filename: str) -> Path:
    if getattr(sys, "frozen", False):
        base = Path(getattr(sys, "_MEIPASS"))
    else:
        base = Path(__file__).parent
    return base / filename


def create_shortcut(shortcut_path: Path, target: Path, icon_path: Path) -> None:
    shortcut_path.parent.mkdir(parents=True, exist_ok=True)
    ps_script = (
        "$shell = New-Object -ComObject WScript.Shell; "
        f"$shortcut = $shell.CreateShortcut('{shortcut_path}'); "
        f"$shortcut.TargetPath = '{target}'; "
        f"$shortcut.WorkingDirectory = '{target.parent}'; "
        f"$shortcut.IconLocation = '{icon_path}'; "
        "$shortcut.Save()"
    )
    subprocess.run(
        [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            ps_script,
        ],
        check=True,
        capture_output=True,
        text=True,
    )


def resolve_source_file(filename: str) -> Path:
    candidates: list[Path] = [bundled_path(filename)]
    if getattr(sys, "frozen", False):
        exe_dir = Path(sys.executable).resolve().parent
        candidates.extend([
            exe_dir / filename,
            exe_dir / "dist" / filename,
        ])

    for candidate in candidates:
        if candidate.exists():
            return candidate

    searched = "\n".join(str(path) for path in candidates)
    raise FileNotFoundError(f"Missing required file: {filename}\nSearched in:\n{searched}")


def install_app() -> Path:
    source_exe = resolve_source_file("Command AV.exe")
    source_icon = resolve_source_file("command_av.ico")

    INSTALL_ROOT.mkdir(parents=True, exist_ok=True)
    installed_exe = INSTALL_ROOT / "Command AV.exe"
    installed_icon = INSTALL_ROOT / "command_av.ico"

    shutil.copy2(source_exe, installed_exe)
    shutil.copy2(source_icon, installed_icon)

    create_shortcut(DESKTOP_DIR / "Command AV.lnk", installed_exe, installed_icon)
    create_shortcut(START_MENU_DIR / "Command AV.lnk", installed_exe, installed_icon)

    uninstall_script = INSTALL_ROOT / "uninstall.bat"
    uninstall_script.write_text(
        "@echo off\n"
        "taskkill /IM \"Command AV.exe\" /F >nul 2>nul\n"
        f"del \"{DESKTOP_DIR / 'Command AV.lnk'}\" >nul 2>nul\n"
        f"del \"{START_MENU_DIR / 'Command AV.lnk'}\" >nul 2>nul\n"
        f"del \"{installed_exe}\" >nul 2>nul\n"
        f"del \"{installed_icon}\" >nul 2>nul\n"
        "del \"%~f0\"\n",
        encoding="utf-8",
    )

    return installed_exe


class InstallerApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Command AV Installer")
        self.geometry("620x320")
        self.resizable(False, False)
        self.configure(bg="#101826")
        self._build_ui()

    def _build_ui(self) -> None:
        style = ttk.Style(self)
        style.theme_use("clam")

        container = ttk.Frame(self, padding=20)
        container.pack(fill="both", expand=True)

        ttk.Label(container, text="Command AV Installer", font=("Segoe UI", 20, "bold")).pack(anchor="w", pady=(0, 12))
        ttk.Label(
            container,
            text="Instalator skopiuje aplikację do folderu użytkownika i utworzy skróty na pulpicie oraz w menu Start.",
            wraplength=560,
            font=("Segoe UI", 10),
        ).pack(anchor="w")

        ttk.Label(container, text=f"Lokalizacja: {INSTALL_ROOT}", wraplength=560, font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(16, 18))

        self.progress = ttk.Progressbar(container, mode="indeterminate")
        self.progress.pack(fill="x", pady=(0, 18))

        self.status_var = tk.StringVar(value="Gotowe do instalacji")
        ttk.Label(container, textvariable=self.status_var, font=("Segoe UI", 10)).pack(anchor="w", pady=(0, 18))

        actions = ttk.Frame(container)
        actions.pack(fill="x")
        ttk.Button(actions, text="Instaluj", command=self.run_install).pack(side="left")
        ttk.Button(actions, text="Zamknij", command=self.destroy).pack(side="right")

    def run_install(self) -> None:
        self.progress.start(12)
        self.status_var.set("Trwa instalacja...")
        self.update_idletasks()
        try:
            installed_exe = install_app()
        except Exception as exc:
            self.progress.stop()
            self.status_var.set("Błąd instalacji")
            messagebox.showerror("Command AV Installer", f"Nie udało się zainstalować aplikacji.\n\n{exc}")
            return

        self.progress.stop()
        self.status_var.set("Instalacja zakończona")
        if messagebox.askyesno("Command AV Installer", f"Zainstalowano poprawnie.\n\nUruchomić teraz?\n\n{installed_exe}"):
            subprocess.Popen([str(installed_exe)], shell=False)


if __name__ == "__main__":
    app = InstallerApp()
    app.mainloop()
