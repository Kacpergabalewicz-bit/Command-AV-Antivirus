from __future__ import annotations

import json
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass
class VPNProfile:
    name: str
    server_address: str
    vpn_type: str
    username: str = ""
    l2tp_psk: str = ""


class WindowsVPNManager:
    def __init__(self, app_dir: Path) -> None:
        self.app_dir = app_dir
        self.app_dir.mkdir(parents=True, exist_ok=True)
        self.profile_path = self.app_dir / "vpn_profiles.json"

    def _ps(self, script: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script],
            capture_output=True,
            text=True,
            timeout=40,
        )

    def _escape(self, value: str) -> str:
        return value.replace("'", "''")

    def load_profiles(self) -> list[VPNProfile]:
        if not self.profile_path.exists():
            return []
        data = json.loads(self.profile_path.read_text(encoding="utf-8"))
        return [VPNProfile(**item) for item in data]

    def save_profiles(self, profiles: list[VPNProfile]) -> None:
        self.profile_path.write_text(json.dumps([asdict(item) for item in profiles], indent=2, ensure_ascii=False), encoding="utf-8")

    def upsert_profile(self, profile: VPNProfile) -> None:
        profiles = [item for item in self.load_profiles() if item.name.lower() != profile.name.lower()]
        profiles.append(profile)
        profiles.sort(key=lambda item: item.name.lower())
        self.save_profiles(profiles)

    def delete_profile(self, name: str) -> None:
        profiles = [item for item in self.load_profiles() if item.name.lower() != name.lower()]
        self.save_profiles(profiles)
        self.remove_windows_connection(name)

    def create_or_update_connection(self, profile: VPNProfile) -> None:
        name = self._escape(profile.name)
        server = self._escape(profile.server_address)
        tunnel = self._escape(profile.vpn_type)
        psk = self._escape(profile.l2tp_psk)
        tunnel_param = "" if profile.vpn_type.lower() in {"automatic", "auto"} else f"; $params['TunnelType'] = '{tunnel}'"
        script = (
            f"$existing = Get-VpnConnection -Name '{name}' -ErrorAction SilentlyContinue; "
            f"if ($existing) {{ Remove-VpnConnection -Name '{name}' -Force -PassThru | Out-Null }}; "
            f"$params = @{{ Name = '{name}'; ServerAddress = '{server}'; RememberCredential = $true; Force = $true }}"
            + tunnel_param
            + "; "
            + (f"$params['L2tpPsk'] = '{psk}'; " if profile.vpn_type == "L2tp" and profile.l2tp_psk else "")
            + "Add-VpnConnection @params | Out-Null"
        )
        result = self._ps(script)
        if result.returncode != 0:
            raise RuntimeError((result.stderr or result.stdout or "Failed to create VPN connection").strip())

    def remove_windows_connection(self, name: str) -> None:
        escaped = self._escape(name)
        script = f"$existing = Get-VpnConnection -Name '{escaped}' -ErrorAction SilentlyContinue; if ($existing) {{ Remove-VpnConnection -Name '{escaped}' -Force -PassThru | Out-Null }}"
        self._ps(script)

    def connect(self, name: str, username: str, password: str) -> None:
        cmd = ["rasdial", name]
        if username:
            cmd.append(username)
        if password:
            cmd.append(password)
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=40)
        if result.returncode != 0:
            raise RuntimeError((result.stderr or result.stdout or "Failed to connect VPN").strip())

    def list_windows_connections(self) -> list[str]:
        script = "Get-VpnConnection -AllUserConnection -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name"
        result = self._ps(script)
        if result.returncode != 0:
            return []
        return [line.strip() for line in (result.stdout or "").splitlines() if line.strip()]

    def connect_first_available(self, preferred_names: list[str] | None = None) -> str:
        preferred_names = preferred_names or []
        available = self.list_windows_connections()
        candidates: list[str] = []
        for name in preferred_names:
            if name and name in available and name not in candidates:
                candidates.append(name)
        for name in available:
            if name not in candidates:
                candidates.append(name)

        if not candidates:
            raise RuntimeError("No Windows VPN connections are configured.")

        last_error = ""
        for name in candidates:
            result = subprocess.run(["rasdial", name], capture_output=True, text=True, timeout=40)
            if result.returncode == 0:
                return name
            last_error = (result.stderr or result.stdout or "Failed to connect VPN").strip()

        raise RuntimeError(last_error or "Failed to connect any available Windows VPN connection.")

    def disconnect(self, name: str) -> None:
        result = subprocess.run(["rasdial", name, "/disconnect"], capture_output=True, text=True, timeout=40)
        if result.returncode != 0 and "No connections" not in (result.stdout or ""):
            raise RuntimeError((result.stderr or result.stdout or "Failed to disconnect VPN").strip())

    def is_connected(self, name: str) -> bool:
        result = subprocess.run(["rasdial"], capture_output=True, text=True, timeout=20)
        output = (result.stdout or "")
        return name.lower() in output.lower()

    def disconnect_all(self) -> None:
        result = subprocess.run(["rasdial", "/disconnect"], capture_output=True, text=True, timeout=20)
        if result.returncode != 0 and "No connections" not in (result.stdout or ""):
            raise RuntimeError((result.stderr or result.stdout or "Failed to disconnect VPN").strip())
