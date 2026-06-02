from __future__ import annotations

import queue
import sys
import threading
from dataclasses import asdict
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from tkinter.scrolledtext import ScrolledText

import ttkbootstrap as tb
from ttkbootstrap.constants import BOTH, END, LEFT, RIGHT, X

from command_av.i18n import LANGUAGE_NAMES, tr
from command_av.logging_utils import get_logger, read_recent_logs, setup_logging
from command_av.process_scanner import ProcessFinding, scan_running_processes
from command_av.quarantine import delete_quarantined, load_manifest, quarantine_file, restore_file
from command_av.realtime_monitor import LiveAlert, LiveMonitor
from command_av.reporting import write_report
from command_av.scanner import Finding, ScanOptions, ScanStats, scan_multiple_targets
from command_av.settings import load_settings, save_settings
from command_av.signatures import ensure_default_signature_store, load_signatures
from command_av.utils import default_quick_scan_paths, format_bytes, get_windows_drives
from command_av.vpn import VPNProfile, WindowsVPNManager


APP_DIR = Path.home() / ".command_av"
QUARANTINE_DIR = APP_DIR / "quarantine"
REPORT_DIR = APP_DIR / "reports"
LOG_DIR = APP_DIR / "logs"


class CommandAVApp(tb.Window):
    def __init__(self) -> None:
        super().__init__(themename="darkly")
        self.title("Command AV")
        self.geometry("1520x940")
        self.minsize(1240, 760)
        self._apply_visual_style()
        self._set_window_icon()

        signature_file = ensure_default_signature_store(APP_DIR)
        self.signatures = load_signatures(signature_file)
        self.settings = load_settings(APP_DIR)
        self.language = self.settings.language or "pl"
        self.log_file = setup_logging(LOG_DIR)
        self.logger = get_logger()
        self.vpn_manager = WindowsVPNManager(APP_DIR)

        self.findings: list[Finding] = []
        self.process_findings: list[ProcessFinding] = []
        self.live_alerts: list[LiveAlert] = []
        self.current_target_label = self.t("no_active_scan")
        self.last_stats = ScanStats()
        self.result_queue: queue.Queue = queue.Queue()
        self.scan_in_progress = False
        self.monitor: LiveMonitor | None = None
        self.finding_map: dict[str, Finding] = {}
        self.container: tb.Frame | None = None

        self._build_ui()
        self._load_settings_into_ui()
        self._refresh_quarantine()
        self._refresh_logs()
        self._refresh_vpn_profiles()
        self._refresh_counters()
        if self.settings.realtime_enabled:
            self.start_live_guard(silent=True)
        self.after(200, self._poll_queue)
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.logger.info("Command AV started")

    def t(self, key: str, **kwargs) -> str:
        return tr(self.language, key, **kwargs)

    def _title(self, level: str) -> str:
        return self.t(level)

    def _build_ui(self) -> None:
        if self.container is not None:
            self.container.destroy()

        self.container = tb.Frame(self, padding=16)
        self.container.pack(fill=BOTH, expand=True)

        self.status_var = tk.StringVar(value=self.t("ready"))
        self.summary_var = tk.StringVar(value=self.t("no_results"))
        self.engine_var = tk.StringVar(value=self.t("engine_info", count=len(self.signatures)))
        self.target_var = tk.StringVar(value=self.current_target_label)
        self.live_var = tk.StringVar(value=self.t("live_off"))
        self.stats_files_var = tk.StringVar(value=self.t("files_count", count=0))
        self.stats_threats_var = tk.StringVar(value=self.t("threats_count", count=0))
        self.stats_quarantine_var = tk.StringVar(value=self.t("quarantine_count", count=0))
        self.stats_process_var = tk.StringVar(value=self.t("process_count", count=0))
        self.vpn_status_var = tk.StringVar(value=self.t("vpn_ready"))

        header = tb.Frame(self.container)
        header.pack(fill=X)
        tb.Label(header, text="🛡  Command AV", font=("Segoe UI Variable", 28, "bold"), bootstyle="info").pack(anchor="w")
        tb.Label(header, text=self.t("subtitle"), font=("Segoe UI Variable", 11), bootstyle="secondary").pack(anchor="w", pady=(4, 12))

        action_bar = tb.Frame(self.container)
        action_bar.pack(fill=X, pady=(0, 12))
        tb.Button(action_bar, text=self.t("quick_scan"), bootstyle="info", command=self.start_quick_scan).pack(side=LEFT, padx=(0, 8))
        tb.Button(action_bar, text=self.t("full_scan"), bootstyle="secondary", command=self.start_full_scan).pack(side=LEFT, padx=8)
        tb.Button(action_bar, text=self.t("scan_folder"), bootstyle="secondary-outline", command=self.pick_folder_and_scan).pack(side=LEFT, padx=8)
        tb.Button(action_bar, text=self.t("scan_file"), bootstyle="secondary-outline", command=self.pick_file_and_scan).pack(side=LEFT, padx=8)
        tb.Button(action_bar, text=self.t("scan_processes"), bootstyle="info-outline", command=self.scan_processes_only).pack(side=LEFT, padx=8)
        tb.Button(action_bar, text=self.t("toggle_live_guard"), bootstyle="warning-outline", command=self.toggle_live_guard).pack(side=LEFT, padx=8)
        tb.Button(action_bar, text=self.t("save_report"), bootstyle="info-outline", command=self.save_report).pack(side=RIGHT)

        cards = tb.Frame(self.container)
        cards.pack(fill=X, pady=(0, 12))
        self._create_card(cards, self.t("status"), self.status_var).pack(side=LEFT, fill=X, expand=True, padx=(0, 10))
        self._create_card(cards, self.t("last_result"), self.summary_var).pack(side=LEFT, fill=X, expand=True, padx=10)
        self._create_card(cards, self.t("live_guard"), self.live_var).pack(side=LEFT, fill=X, expand=True, padx=10)
        self._create_card(cards, self.t("engine"), self.engine_var).pack(side=LEFT, fill=X, expand=True, padx=(10, 0))

        counters = tb.Frame(self.container)
        counters.pack(fill=X, pady=(0, 12))
        self._create_card(counters, self.t("scanned"), self.stats_files_var).pack(side=LEFT, fill=X, expand=True, padx=(0, 10))
        self._create_card(counters, self.t("detections"), self.stats_threats_var).pack(side=LEFT, fill=X, expand=True, padx=10)
        self._create_card(counters, self.t("quarantine"), self.stats_quarantine_var).pack(side=LEFT, fill=X, expand=True, padx=10)
        self._create_card(counters, self.t("processes"), self.stats_process_var).pack(side=LEFT, fill=X, expand=True, padx=(10, 0))

        self.progress = tb.Progressbar(self.container, mode="indeterminate", bootstyle="info")
        self.progress.pack(fill=X, pady=(0, 14))

        self.notebook = tb.Notebook(self.container, bootstyle="secondary")
        self.notebook.pack(fill=BOTH, expand=True)

        dashboard_tab = tb.Frame(self.notebook, padding=12)
        findings_tab = tb.Frame(self.notebook, padding=12)
        processes_tab = tb.Frame(self.notebook, padding=12)
        live_tab = tb.Frame(self.notebook, padding=12)
        quarantine_tab = tb.Frame(self.notebook, padding=12)
        settings_tab = tb.Frame(self.notebook, padding=12)
        vpn_tab = tb.Frame(self.notebook, padding=12)
        logs_tab = tb.Frame(self.notebook, padding=12)

        self.notebook.add(dashboard_tab, text=self.t("dashboard"))
        self.notebook.add(findings_tab, text=self.t("results"))
        self.notebook.add(processes_tab, text=self.t("processes"))
        self.notebook.add(live_tab, text=self.t("live_guard"))
        self.notebook.add(quarantine_tab, text=self.t("quarantine"))
        self.notebook.add(settings_tab, text=self.t("settings"))
        self.notebook.add(vpn_tab, text=self.t("vpn"))
        self.notebook.add(logs_tab, text=self.t("logs"))

        self._build_dashboard_tab(dashboard_tab)
        self._build_findings_tab(findings_tab)
        self._build_processes_tab(processes_tab)
        self._build_live_tab(live_tab)
        self._build_quarantine_tab(quarantine_tab)
        self._build_settings_tab(settings_tab)
        self._build_vpn_tab(vpn_tab)
        self._build_logs_tab(logs_tab)

    def _create_card(self, parent, title: str, variable: tk.StringVar):
        card = tb.Labelframe(parent, text=title, padding=14, bootstyle="secondary")
        tb.Label(card, textvariable=variable, font=("Segoe UI Variable", 11, "bold"), wraplength=280, justify="left").pack(anchor="w")
        return card

    def _asset_path(self, relative: str) -> Path:
        if getattr(sys, "frozen", False):
            base = Path(getattr(sys, "_MEIPASS", Path(sys.executable).resolve().parent))
        else:
            base = Path(__file__).resolve().parent.parent
        return base / relative

    def _set_window_icon(self) -> None:
        icon_path = self._asset_path("assets/command_av.ico")
        if icon_path.exists():
            try:
                self.iconbitmap(str(icon_path))
            except tk.TclError:
                pass

    def _apply_visual_style(self) -> None:
        self.option_add("*Font", ("Segoe UI Variable", 10))
        style = ttk.Style(self)
        style.configure("TButton", padding=(12, 8), font=("Segoe UI Variable", 10))
        style.configure("TLabel", font=("Segoe UI Variable", 10))
        style.configure("TLabelframe.Label", font=("Segoe UI Variable", 10, "bold"))
        style.configure("Treeview", rowheight=28, font=("Segoe UI Variable", 10))
        style.configure("Treeview.Heading", font=("Segoe UI Variable", 10, "bold"))
        style.configure("TNotebook.Tab", padding=(14, 8), font=("Segoe UI Variable", 10, "bold"))

    def _build_dashboard_tab(self, tab) -> None:
        left = tb.Frame(tab)
        left.pack(side=LEFT, fill=BOTH, expand=True)
        right = tb.Frame(tab)
        right.pack(side=RIGHT, fill=BOTH, expand=True, padx=(12, 0))

        quick_box = tb.Labelframe(left, text=self.t("quick_actions"), padding=12)
        quick_box.pack(fill=X)
        tb.Button(quick_box, text=self.t("quick_scan_important"), bootstyle="success", command=self.start_quick_scan).pack(fill=X, pady=4)
        tb.Button(quick_box, text=self.t("full_scan_all"), bootstyle="warning", command=self.start_full_scan).pack(fill=X, pady=4)
        tb.Button(quick_box, text=self.t("scan_processes_only"), bootstyle="secondary", command=self.scan_processes_only).pack(fill=X, pady=4)
        tb.Button(quick_box, text=self.t("pick_custom_folder"), bootstyle="info", command=self.pick_folder_and_scan).pack(fill=X, pady=4)

        target_box = tb.Labelframe(left, text=self.t("current_target"), padding=12)
        target_box.pack(fill=X, pady=(12, 0))
        tb.Label(target_box, textvariable=self.target_var, wraplength=560, justify="left").pack(anchor="w")

        info_box = tb.Labelframe(right, text=self.t("protection_scope"), padding=12)
        info_box.pack(fill=BOTH, expand=True)
        tb.Label(info_box, text=self.t("protection_scope_text"), justify="left", font=("Consolas", 11)).pack(anchor="w")

    def _build_findings_tab(self, tab) -> None:
        actions = tb.Frame(tab)
        actions.pack(fill=X, pady=(0, 8))
        tb.Button(actions, text=self.t("to_quarantine"), bootstyle="warning-outline", command=self.quarantine_selected).pack(side=LEFT)
        tb.Button(actions, text=self.t("delete_selected_suspicious"), bootstyle="danger", command=self.delete_selected_suspicious).pack(side=LEFT, padx=8)
        tb.Button(actions, text=self.t("delete_all_suspicious"), bootstyle="danger-outline", command=self.delete_all_suspicious).pack(side=LEFT, padx=8)
        tb.Button(actions, text=self.t("clear_results"), bootstyle="secondary-outline", command=self.clear_results).pack(side=LEFT, padx=8)

        columns = ("path", "threat", "severity", "source", "method", "score")
        self.results_tree = tb.Treeview(tab, columns=columns, show="headings", height=22)
        for key, text, width in [
            ("path", self.t("path"), 520),
            ("threat", self.t("threat"), 240),
            ("severity", self.t("severity"), 90),
            ("source", self.t("source"), 100),
            ("method", self.t("method"), 180),
            ("score", "Score", 70),
        ]:
            self.results_tree.heading(key, text=text)
            self.results_tree.column(key, width=width, anchor="w")
        self.results_tree.pack(fill=BOTH, expand=True)

    def _build_processes_tab(self, tab) -> None:
        actions = tb.Frame(tab)
        actions.pack(fill=X, pady=(0, 8))
        tb.Button(actions, text=self.t("scan_processes"), bootstyle="warning", command=self.scan_processes_only).pack(side=LEFT)

        columns = ("pid", "name", "exe", "threat", "severity", "method")
        self.process_tree = tb.Treeview(tab, columns=columns, show="headings", height=22)
        for key, text, width in [
            ("pid", "PID", 80),
            ("name", self.t("process"), 150),
            ("exe", "Executable", 420),
            ("threat", self.t("threat"), 220),
            ("severity", self.t("severity"), 100),
            ("method", self.t("method"), 220),
        ]:
            self.process_tree.heading(key, text=text)
            self.process_tree.column(key, width=width, anchor="w")
        self.process_tree.pack(fill=BOTH, expand=True)

    def _build_live_tab(self, tab) -> None:
        top = tb.Frame(tab)
        top.pack(fill=X, pady=(0, 8))
        tb.Button(top, text="Start Live Guard", bootstyle="success", command=self.start_live_guard).pack(side=LEFT)
        tb.Button(top, text="Stop Live Guard", bootstyle="danger", command=self.stop_live_guard).pack(side=LEFT, padx=8)

        columns = ("time", "path", "threat", "severity", "action", "method")
        self.live_tree = tb.Treeview(tab, columns=columns, show="headings", height=22)
        for key, text, width in [
            ("time", self.t("time"), 190),
            ("path", self.t("path"), 430),
            ("threat", self.t("threat"), 220),
            ("severity", self.t("severity"), 90),
            ("action", self.t("action"), 110),
            ("method", self.t("method"), 180),
        ]:
            self.live_tree.heading(key, text=text)
            self.live_tree.column(key, width=width, anchor="w")
        self.live_tree.pack(fill=BOTH, expand=True)

    def _build_quarantine_tab(self, tab) -> None:
        actions = tb.Frame(tab)
        actions.pack(fill=X, pady=(0, 8))
        tb.Button(actions, text=self.t("refresh"), bootstyle="info", command=self._refresh_quarantine).pack(side=LEFT)
        tb.Button(actions, text=self.t("restore"), bootstyle="success", command=self.restore_selected).pack(side=LEFT, padx=8)
        tb.Button(actions, text=self.t("delete_permanently"), bootstyle="danger", command=self.delete_selected_quarantine).pack(side=LEFT)

        columns = ("original", "threat", "severity", "time", "size")
        self.quarantine_tree = tb.Treeview(tab, columns=columns, show="headings", height=22)
        for key, text, width in [
            ("original", self.t("original_path"), 520),
            ("threat", self.t("threat"), 220),
            ("severity", self.t("severity"), 90),
            ("time", self.t("date"), 190),
            ("size", self.t("size"), 120),
        ]:
            self.quarantine_tree.heading(key, text=text)
            self.quarantine_tree.column(key, width=width, anchor="w")
        self.quarantine_tree.pack(fill=BOTH, expand=True)

    def _build_settings_tab(self, tab) -> None:
        left = tb.Frame(tab)
        left.pack(side=LEFT, fill=BOTH, expand=True)
        right = tb.Frame(tab)
        right.pack(side=RIGHT, fill=BOTH, expand=True, padx=(12, 0))

        self.include_archives_var = tk.BooleanVar()
        self.scan_hidden_var = tk.BooleanVar()
        self.auto_quarantine_var = tk.BooleanVar()
        self.realtime_enabled_var = tk.BooleanVar()
        self.scan_processes_var = tk.BooleanVar()
        self.max_size_var = tk.StringVar()
        self.language_var = tk.StringVar()

        engine_box = tb.Labelframe(left, text=self.t("engine_options"), padding=12)
        engine_box.pack(fill=X)
        tb.Checkbutton(engine_box, text=self.t("scan_archives"), variable=self.include_archives_var, bootstyle="round-toggle").pack(anchor="w", pady=4)
        tb.Checkbutton(engine_box, text=self.t("scan_hidden"), variable=self.scan_hidden_var, bootstyle="round-toggle").pack(anchor="w", pady=4)
        tb.Checkbutton(engine_box, text=self.t("automatic_quarantine"), variable=self.auto_quarantine_var, bootstyle="round-toggle").pack(anchor="w", pady=4)
        tb.Checkbutton(engine_box, text=self.t("start_live_on_boot"), variable=self.realtime_enabled_var, bootstyle="round-toggle").pack(anchor="w", pady=4)
        tb.Checkbutton(engine_box, text=self.t("scan_processes_full"), variable=self.scan_processes_var, bootstyle="round-toggle").pack(anchor="w", pady=4)

        size_row = tb.Frame(engine_box)
        size_row.pack(fill=X, pady=(8, 0))
        tb.Label(size_row, text=self.t("max_analysis_size")).pack(side=LEFT)
        tb.Entry(size_row, textvariable=self.max_size_var, width=8).pack(side=LEFT, padx=8)

        lang_row = tb.Frame(engine_box)
        lang_row.pack(fill=X, pady=(10, 0))
        tb.Label(lang_row, text=self.t("language")).pack(side=LEFT)
        self.language_combo = ttk.Combobox(lang_row, textvariable=self.language_var, state="readonly", width=22, values=list(LANGUAGE_NAMES.values()))
        self.language_combo.pack(side=LEFT, padx=8)

        exclusions_box = tb.Labelframe(left, text=self.t("exclusions"), padding=12)
        exclusions_box.pack(fill=BOTH, expand=True, pady=(12, 0))
        self.exclusions_list = tk.Listbox(exclusions_box, height=12)
        self.exclusions_list.pack(fill=BOTH, expand=True)
        exclusion_actions = tb.Frame(exclusions_box)
        exclusion_actions.pack(fill=X, pady=(8, 0))
        tb.Button(exclusion_actions, text=self.t("add_folder"), bootstyle="info", command=self.add_exclusion).pack(side=LEFT)
        tb.Button(exclusion_actions, text=self.t("remove"), bootstyle="danger", command=self.remove_exclusion).pack(side=LEFT, padx=8)

        monitor_box = tb.Labelframe(right, text=self.t("live_folders"), padding=12)
        monitor_box.pack(fill=BOTH, expand=True)
        self.monitor_list = tk.Listbox(monitor_box, height=12)
        self.monitor_list.pack(fill=BOTH, expand=True)
        monitor_actions = tb.Frame(monitor_box)
        monitor_actions.pack(fill=X, pady=(8, 0))
        tb.Button(monitor_actions, text=self.t("add_folder"), bootstyle="info", command=self.add_monitor_path).pack(side=LEFT)
        tb.Button(monitor_actions, text=self.t("remove"), bootstyle="danger", command=self.remove_monitor_path).pack(side=LEFT, padx=8)

        save_row = tb.Frame(right)
        save_row.pack(fill=X, pady=(12, 0))
        tb.Button(save_row, text=self.t("save_settings"), bootstyle="success", command=self.save_settings_from_ui).pack(side=LEFT)

    def _build_vpn_tab(self, tab) -> None:
        form_wrap = tb.Frame(tab)
        form_wrap.pack(fill=BOTH, expand=True)

        form = tb.Labelframe(form_wrap, text=self.t("vpn"), padding=12)
        form.pack(fill=BOTH, expand=True)

        tb.Label(
            form,
            text=self.t("vpn_auto_full_info"),
            wraplength=760,
            justify="left",
        ).pack(anchor="w", pady=(0, 10))

        action_row = tb.Frame(form)
        action_row.pack(fill=X, pady=(14, 8))
        tb.Button(action_row, text=self.t("connect"), bootstyle="primary", command=self.connect_selected_vpn).pack(side=LEFT)
        tb.Button(action_row, text=self.t("disconnect"), bootstyle="warning", command=self.disconnect_selected_vpn).pack(side=LEFT, padx=8)

        status_box = tb.Labelframe(form, text=self.t("vpn_status"), padding=12)
        status_box.pack(fill=X, pady=(10, 0))
        tb.Label(status_box, textvariable=self.vpn_status_var, wraplength=460, justify="left").pack(anchor="w")

    def _add_form_row(self, parent, label: str, variable: tk.StringVar, show: str | None = None) -> None:
        row = tb.Frame(parent)
        row.pack(fill=X, pady=6)
        tb.Label(row, text=label, width=20).pack(side=LEFT)
        tb.Entry(row, textvariable=variable, show=show or "").pack(side=LEFT, fill=X, expand=True)

    def _build_logs_tab(self, tab) -> None:
        actions = tb.Frame(tab)
        actions.pack(fill=X, pady=(0, 8))
        tb.Button(actions, text=self.t("refresh_logs"), bootstyle="info", command=self._refresh_logs).pack(side=LEFT)
        self.logs_text = ScrolledText(tab, wrap="word", font=("Consolas", 10))
        self.logs_text.pack(fill=BOTH, expand=True)

    def _load_settings_into_ui(self) -> None:
        self.include_archives_var.set(self.settings.include_archives)
        self.scan_hidden_var.set(self.settings.scan_hidden_files)
        self.auto_quarantine_var.set(self.settings.automatic_quarantine)
        self.realtime_enabled_var.set(self.settings.realtime_enabled)
        self.scan_processes_var.set(self.settings.scan_processes_with_full_scan)
        self.max_size_var.set(str(self.settings.max_file_size_mb))
        self.language_var.set(LANGUAGE_NAMES.get(self.settings.language, LANGUAGE_NAMES["en"]))
        self._reload_listbox(self.exclusions_list, self.settings.excluded_paths)
        self._reload_listbox(self.monitor_list, self.settings.monitored_paths)

    def _reload_listbox(self, listbox: tk.Listbox, values: list[str]) -> None:
        listbox.delete(0, END)
        for value in values:
            listbox.insert(END, value)

    def _current_scan_options(self) -> ScanOptions:
        return ScanOptions(
            recursive=True,
            max_file_size_mb=max(1, int(self.max_size_var.get() or self.settings.max_file_size_mb)),
            include_archives=self.include_archives_var.get(),
            scan_hidden_files=self.scan_hidden_var.get(),
            excluded_paths=tuple(path.lower() for path in self.settings.excluded_paths),
        )

    def _start_operation(self, label: str) -> bool:
        if self.scan_in_progress:
            messagebox.showinfo(self._title("info"), self.t("scan_in_progress"))
            return False
        self.scan_in_progress = True
        self.status_var.set(label)
        self.progress.start(10)
        return True

    def _finish_operation(self) -> None:
        self.scan_in_progress = False
        self.progress.stop()

    def start_quick_scan(self) -> None:
        targets = [Path(path) for path in self.settings.quick_scan_paths if Path(path).exists()]
        if not targets:
            targets = default_quick_scan_paths()
        self._start_scan_targets(targets, self.t("quick_scan"), include_processes=False, status_label=self.t("quick_scan_running"))

    def start_full_scan(self) -> None:
        targets = get_windows_drives()
        if not targets:
            targets = [Path.home()]
        self._start_scan_targets(targets, self.t("full_scan"), include_processes=self.scan_processes_var.get(), status_label=self.t("full_scan_running"))

    def pick_folder_and_scan(self) -> None:
        selected = filedialog.askdirectory(title=self.t("folder_dialog_scan"))
        if selected:
            self._start_scan_targets([Path(selected)], self.t("scan_folder"), include_processes=False, status_label=self.t("folder_scan_running"))

    def pick_file_and_scan(self) -> None:
        selected = filedialog.askopenfilename(title=self.t("file_dialog_scan"))
        if selected:
            self._start_scan_targets([Path(selected)], self.t("scan_file"), include_processes=False, status_label=self.t("file_scan_running"))

    def _start_scan_targets(self, targets: list[Path], label: str, *, include_processes: bool, status_label: str) -> None:
        if not targets:
            messagebox.showwarning(self._title("warning"), self.t("no_targets"))
            return
        if not self._start_operation(status_label):
            return
        self.current_target_label = ", ".join(str(path) for path in targets[:5])
        self.target_var.set(self.current_target_label)
        threading.Thread(target=self._scan_targets_worker, args=(targets, label, include_processes), daemon=True).start()

    def _scan_targets_worker(self, targets: list[Path], label: str, include_processes: bool) -> None:
        options = self._current_scan_options()
        findings, stats = scan_multiple_targets(
            targets,
            self.signatures,
            options=options,
            progress_callback=lambda processed, current: self.result_queue.put(("progress", processed, current)),
        )
        process_findings: list[ProcessFinding] = []
        if include_processes:
            process_findings, scanned_processes, process_errors = scan_running_processes(self.signatures, options)
            stats.scanned_processes = scanned_processes
            stats.suspicious_processes = len(process_findings)
            stats.errors += process_errors
        self.result_queue.put(("scan_complete", label, targets, findings, stats, process_findings))

    def scan_processes_only(self) -> None:
        if not self._start_operation(self.t("process_scan_running")):
            return
        threading.Thread(target=self._scan_processes_worker, daemon=True).start()

    def _scan_processes_worker(self) -> None:
        process_findings, scanned, errors = scan_running_processes(self.signatures, self._current_scan_options())
        self.result_queue.put(("process_complete", process_findings, scanned, errors))

    def _poll_queue(self) -> None:
        try:
            while True:
                message = self.result_queue.get_nowait()
                event = message[0]
                if event == "progress":
                    _, processed, current = message
                    self.status_var.set(self.t("scan_running", count=processed, current=current))
                elif event == "scan_complete":
                    _, label, targets, findings, stats, process_findings = message
                    self._finish_operation()
                    self.findings = findings
                    self.process_findings = process_findings
                    self.last_stats = stats
                    self._populate_results(findings)
                    self._populate_processes(process_findings)
                    self.summary_var.set(f"{label}: {stats.scanned_files} / {stats.infected_files} / {stats.suspicious_processes} / {stats.errors}")
                    self.status_var.set(self.t("scan_finished"))
                    self._refresh_counters()
                    if findings or process_findings:
                        messagebox.showwarning(self._title("warning"), self.t("scan_found", files=len(findings), processes=len(process_findings)))
                    else:
                        messagebox.showinfo(self._title("info"), self.t("scan_clean"))
                elif event == "process_complete":
                    _, process_findings, scanned, errors = message
                    self._finish_operation()
                    self.process_findings = process_findings
                    self.last_stats = ScanStats(scanned_processes=scanned, suspicious_processes=len(process_findings), errors=errors)
                    self._populate_processes(process_findings)
                    self.summary_var.set(f"{self.t('scan_processes')}: {scanned} / {len(process_findings)} / {errors}")
                    self.status_var.set(self.t("process_scan_finished"))
                    self._refresh_counters()
                elif event == "live_alert":
                    _, alert, finding = message
                    self.live_alerts.insert(0, alert)
                    self._add_live_alert(alert)
                    if finding and self.settings.automatic_quarantine:
                        path = Path(finding.path)
                        if path.exists() and finding.source == "filesystem":
                            quarantine_file(path, finding, QUARANTINE_DIR)
                            self._refresh_quarantine()
                    self._refresh_counters()
        except queue.Empty:
            pass

        self.after(200, self._poll_queue)

    def _populate_results(self, findings: list[Finding]) -> None:
        self.finding_map.clear()
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        for index, finding in enumerate(findings):
            item_id = str(index)
            self.finding_map[item_id] = finding
            self.results_tree.insert("", END, iid=item_id, values=(finding.path, finding.threat_name, finding.severity, finding.source, finding.method, finding.score))

    def _populate_processes(self, findings: list[ProcessFinding]) -> None:
        for item in self.process_tree.get_children():
            self.process_tree.delete(item)
        for index, finding in enumerate(findings):
            self.process_tree.insert("", END, iid=str(index), values=(finding.pid, finding.name, finding.executable, finding.threat_name, finding.severity, finding.method))

    def quarantine_selected(self) -> None:
        selected = self.results_tree.selection()
        if not selected:
            messagebox.showinfo(self._title("info"), self.t("select_quarantine"))
            return
        moved = 0
        for item_id in selected:
            finding = self.finding_map.get(item_id)
            if not finding or finding.source != "filesystem":
                continue
            path = Path(finding.path)
            if path.exists():
                quarantine_file(path, finding, QUARANTINE_DIR)
                moved += 1
        self._refresh_quarantine()
        messagebox.showinfo(self._title("info"), self.t("moved_to_quarantine", count=moved))

    def _delete_files_from_findings(self, item_ids: list[str]) -> tuple[int, int]:
        deleted = 0
        failed = 0
        for item_id in item_ids:
            finding = self.finding_map.get(item_id)
            if not finding or finding.source != "filesystem":
                continue
            file_path = Path(finding.path)
            try:
                if file_path.exists() and file_path.is_file():
                    file_path.unlink()
                    deleted += 1
            except OSError:
                failed += 1

        selected_set = set(item_ids)
        self.findings = [finding for index, finding in enumerate(self.findings) if str(index) not in selected_set]
        self.last_stats.infected_files = len(self.findings)
        self._populate_results(self.findings)
        self._refresh_counters()
        return deleted, failed

    def delete_selected_suspicious(self) -> None:
        selected = list(self.results_tree.selection())
        if not selected:
            messagebox.showinfo(self._title("info"), self.t("select_delete_results"))
            return
        if not messagebox.askyesno(self._title("warning"), self.t("confirm_delete_selected_results")):
            return
        deleted, failed = self._delete_files_from_findings(selected)
        messagebox.showinfo(self._title("info"), self.t("deleted_suspicious_files", count=deleted, failed=failed))

    def delete_all_suspicious(self) -> None:
        all_ids = list(self.finding_map.keys())
        if not all_ids:
            messagebox.showinfo(self._title("info"), self.t("select_delete_results"))
            return
        if not messagebox.askyesno(self._title("warning"), self.t("confirm_delete_all_results")):
            return
        deleted, failed = self._delete_files_from_findings(all_ids)
        messagebox.showinfo(self._title("info"), self.t("deleted_suspicious_files", count=deleted, failed=failed))

    def _refresh_quarantine(self) -> None:
        entries = load_manifest(QUARANTINE_DIR)
        if hasattr(self, "quarantine_tree"):
            for item in self.quarantine_tree.get_children():
                self.quarantine_tree.delete(item)
            for index, entry in enumerate(entries):
                self.quarantine_tree.insert("", END, iid=str(index), values=(entry.original_path, entry.threat_name, entry.severity, entry.quarantined_at, format_bytes(entry.original_size)))
        self.stats_quarantine_var.set(self.t("quarantine_count", count=len(entries)))

    def restore_selected(self) -> None:
        selected = self.quarantine_tree.selection()
        if not selected:
            messagebox.showinfo(self._title("info"), self.t("select_restore"))
            return
        entries = load_manifest(QUARANTINE_DIR)
        restored = 0
        for item_id in selected:
            entry = entries[int(item_id)]
            restore_file(entry, QUARANTINE_DIR)
            restored += 1
        self._refresh_quarantine()
        messagebox.showinfo(self._title("info"), self.t("restored_files", count=restored))

    def delete_selected_quarantine(self) -> None:
        selected = self.quarantine_tree.selection()
        if not selected:
            messagebox.showinfo(self._title("info"), self.t("select_delete_quarantine"))
            return
        if not messagebox.askyesno(self._title("warning"), self.t("confirm_delete_quarantine")):
            return
        entries = load_manifest(QUARANTINE_DIR)
        deleted = 0
        for item_id in selected:
            entry = entries[int(item_id)]
            delete_quarantined(entry, QUARANTINE_DIR)
            deleted += 1
        self._refresh_quarantine()
        messagebox.showinfo(self._title("info"), self.t("deleted_files", count=deleted))

    def toggle_live_guard(self) -> None:
        if self.monitor and self.monitor.is_running:
            self.stop_live_guard()
        else:
            self.start_live_guard()

    def start_live_guard(self, silent: bool = False) -> None:
        paths = [Path(path) for path in self.settings.monitored_paths if Path(path).exists()]
        if not paths:
            if not silent:
                messagebox.showwarning(self._title("warning"), self.t("add_monitor_folders"))
            return
        self.monitor = LiveMonitor(self.signatures, self._current_scan_options(), self._handle_live_alert)
        self.monitor.start(paths)
        self.live_var.set(self.t("live_on", count=len(paths)))
        if not silent:
            messagebox.showinfo(self._title("info"), self.t("live_guard_started"))

    def stop_live_guard(self) -> None:
        if self.monitor:
            self.monitor.stop()
        self.live_var.set(self.t("live_off"))

    def _handle_live_alert(self, alert: LiveAlert, finding: Finding | None) -> None:
        self.result_queue.put(("live_alert", alert, finding))

    def _add_live_alert(self, alert: LiveAlert) -> None:
        self.live_tree.insert("", 0, values=(alert.timestamp, alert.path, alert.threat_name, alert.severity, alert.action, alert.method))

    def add_exclusion(self) -> None:
        selected = filedialog.askdirectory(title=self.t("folder_dialog_exclusion"))
        if selected and selected not in self.settings.excluded_paths:
            self.settings.excluded_paths.append(selected)
            self._reload_listbox(self.exclusions_list, self.settings.excluded_paths)

    def remove_exclusion(self) -> None:
        selection = self.exclusions_list.curselection()
        if selection:
            self.settings.excluded_paths.pop(selection[0])
            self._reload_listbox(self.exclusions_list, self.settings.excluded_paths)

    def add_monitor_path(self) -> None:
        selected = filedialog.askdirectory(title=self.t("folder_dialog_live"))
        if selected and selected not in self.settings.monitored_paths:
            self.settings.monitored_paths.append(selected)
            self._reload_listbox(self.monitor_list, self.settings.monitored_paths)

    def remove_monitor_path(self) -> None:
        selection = self.monitor_list.curselection()
        if selection:
            self.settings.monitored_paths.pop(selection[0])
            self._reload_listbox(self.monitor_list, self.settings.monitored_paths)

    def save_settings_from_ui(self) -> None:
        reverse_language_map = {label: code for code, label in LANGUAGE_NAMES.items()}
        old_language = self.language
        self.settings.include_archives = self.include_archives_var.get()
        self.settings.scan_hidden_files = self.scan_hidden_var.get()
        self.settings.automatic_quarantine = self.auto_quarantine_var.get()
        self.settings.realtime_enabled = self.realtime_enabled_var.get()
        self.settings.scan_processes_with_full_scan = self.scan_processes_var.get()
        self.settings.max_file_size_mb = max(1, int(self.max_size_var.get() or "32"))
        self.settings.language = reverse_language_map.get(self.language_var.get(), self.settings.language)
        save_settings(APP_DIR, self.settings)
        self.language = self.settings.language
        self._rebuild_ui_after_language_change()
        message = self.t("language_applied") if old_language != self.language else self.t("settings_saved")
        messagebox.showinfo(self._title("info"), message)

    def _rebuild_ui_after_language_change(self) -> None:
        self._build_ui()
        self._load_settings_into_ui()
        self.target_var.set(self.current_target_label)
        self._populate_results(self.findings)
        self._populate_processes(self.process_findings)
        self._refresh_live_tree()
        self._refresh_quarantine()
        self._refresh_logs()
        self._refresh_vpn_profiles()
        self._refresh_counters()
        if self.monitor and self.monitor.is_running:
            self.live_var.set(self.t("live_on", count=len(self.settings.monitored_paths)))
        else:
            self.live_var.set(self.t("live_off"))

    def _refresh_live_tree(self) -> None:
        for item in self.live_tree.get_children():
            self.live_tree.delete(item)
        for alert in self.live_alerts[:200]:
            self._add_live_alert(alert)

    def save_report(self) -> None:
        report = write_report(
            REPORT_DIR,
            self.current_target_label,
            self.findings,
            self.last_stats,
            process_findings=[asdict(item) for item in self.process_findings],
            live_alerts=[asdict(item) for item in self.live_alerts[:100]],
            metadata={"live_guard": self.live_var.get(), "settings": asdict(self.settings)},
        )
        messagebox.showinfo(self._title("info"), self.t("report_saved", path=report))

    def clear_results(self) -> None:
        self.findings = []
        self.process_findings = []
        self.last_stats = ScanStats()
        self.current_target_label = self.t("no_active_scan")
        self.target_var.set(self.current_target_label)
        self.summary_var.set(self.t("no_results"))
        self.status_var.set(self.t("ready"))
        self._populate_results([])
        self._populate_processes([])
        self._refresh_counters()

    def _refresh_counters(self) -> None:
        self.stats_files_var.set(self.t("files_count", count=self.last_stats.scanned_files))
        self.stats_threats_var.set(self.t("threats_count", count=len(self.findings) + len(self.live_alerts)))
        self.stats_process_var.set(self.t("process_count", count=len(self.process_findings)))
        self._refresh_quarantine()

    def _refresh_logs(self) -> None:
        text = read_recent_logs(self.log_file)
        if hasattr(self, "logs_text"):
            self.logs_text.delete("1.0", END)
            self.logs_text.insert("1.0", text)

    def _refresh_vpn_profiles(self) -> None:
        if not hasattr(self, "vpn_list"):
            return
        profiles = self.vpn_manager.load_profiles()
        self.vpn_list.delete(0, END)
        for profile in profiles:
            self.vpn_list.insert(END, profile.name)

    def connect_selected_vpn(self) -> None:
        try:
            name = self.vpn_manager.connect_first_available(["Command AV VPN", "Default VPN", "VPN"])
            self.vpn_status_var.set(self.t("vpn_connected", name=name))
            messagebox.showinfo(self._title("info"), self.t("vpn_connect_success"))
        except Exception as exc:
            messagebox.showerror(self._title("error"), self.t("vpn_action_failed", error=str(exc)))

    def disconnect_selected_vpn(self) -> None:
        try:
            self.vpn_manager.disconnect_all()
            self.vpn_status_var.set(self.t("vpn_disconnected", name="VPN"))
            messagebox.showinfo(self._title("info"), self.t("vpn_disconnect_success"))
        except Exception as exc:
            messagebox.showerror(self._title("error"), self.t("vpn_action_failed", error=str(exc)))

    def _on_close(self) -> None:
        self.stop_live_guard()
        self.destroy()


def run() -> None:
    app = CommandAVApp()
    app.mainloop()
