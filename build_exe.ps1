Set-Location $PSScriptRoot

& ".venv\Scripts\python.exe" "generate_icon.py"

& ".venv\Scripts\python.exe" -m PyInstaller `
  --noconfirm `
  --clean `
  --windowed `
  --onefile `
  --name "Command AV Antivirus security & VPN" `
  --icon "assets\command_av.ico" `
  --collect-all ttkbootstrap `
  --hidden-import watchdog.observers.winapi `
  --hidden-import watchdog.observers.polling `
  main.py

& ".venv\Scripts\python.exe" -m PyInstaller `
  --noconfirm `
  --clean `
  --windowed `
  --onefile `
  --name "Command AV Antivirus security & VPN Installer" `
  --icon "assets\command_av.ico" `
  --add-data "dist\Command AV Antivirus security & VPN.exe;." `
  --add-data "assets\command_av.ico;." `
  installer.py
