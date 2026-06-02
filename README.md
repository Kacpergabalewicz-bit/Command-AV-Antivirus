# Command AV - Antivirus Security Application

A comprehensive desktop security application for Windows with advanced scanning, real-time monitoring, threat quarantine, and multilingual VPN integration.

![License](https://img.shields.io/badge/License-MIT-blue.svg)
![Platform](https://img.shields.io/badge/Platform-Windows-brightgreen.svg)
![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)

## 🎯 Key Features

### Scanning & Detection
- **Quick Scan**: Fast scanning of important user directories
- **Full System Scan**: Complete disk scanning on all available drives
- **Custom Scan**: Scan individual files, folders, and archives
- **ZIP Archive Scanning**: Detect threats inside compressed files
- **Process Scanning**: Real-time scanning of running processes and command lines
- **Heuristic Detection**: Advanced pattern matching for scripts, LOLBins, and suspicious file extensions

### Threat Management
- **Live Guard**: Real-time file system monitoring and automatic threat detection
- **Quarantine System**: Automatic or manual quarantine of detected threats
- **Quarantine Recovery**: Restore quarantined files or permanently remove them
- **Detailed Reports**: JSON-based reports and activity logs
- **Exclusion Rules**: Create exceptions for trusted files and paths

### User Experience
- **Multilingual Support**: 6 languages - Polish, English, Ukrainian, German, French, Spanish
- **VPN Management**: Integrated native Windows VPN profile creation and connection
- **Settings Persistence**: Save preferences including language and VPN profiles
- **Modern UI**: ttkbootstrap-based dark theme interface
- **Command-line Interface**: Advanced users can access core scanning functions

## 🚀 Getting Started

### Requirements
- Windows 10 or later
- Python 3.9+
- Administrator privileges (for VPN and some antivirus features)

### Installation

1. **Clone the repository:**
```bash
git clone https://github.com/Kacpergabalewicz-bit/Command-AV-Antivirus.git
cd Command-AV-Antivirus
```

2. **Create and activate virtual environment:**
```bash
python -m venv .venv
.venv\Scripts\activate
```

3. **Install dependencies:**
```bash
pip install -r requirements.txt
```

### Running the Application

**Python Mode:**
```bash
python main.py
```

Or launch directly:
- Double-click `Command AV.pyw`

**Executable Mode:**
```bash
dist/Command AV.exe
```

## 🔨 Building Executable

Build a standalone Windows executable using PyInstaller:

```powershell
.\build_exe.ps1
```

The compiled files will appear in the `dist` folder:
- `Command AV.exe` - Main antivirus application
- `Command AV Installer.exe` - Windows installer with shortcuts

## 📋 Project Structure

```
Command-AV/
├── command_av/
│   ├── __init__.py              # Package initialization
│   ├── app.py                   # Main GUI application
│   ├── scanner.py               # File scanning engine
│   ├── process_scanner.py        # Process scanning module
│   ├── quarantine.py            # Quarantine management
│   ├── realtime_monitor.py      # Live Guard monitoring
│   ├── reporting.py             # Report generation
│   ├── signatures.py            # Threat signatures database
│   ├── settings.py              # Configuration management
│   ├── i18n.py                  # Internationalization (6 languages)
│   ├── vpn.py                   # Windows VPN management
│   ├── utils.py                 # Utility functions
│   └── logging_utils.py         # Logging configuration
├── assets/
│   └── command_av.ico           # Application icon
├── main.py                      # Entry point
├── generate_icon.py             # Icon generation script
├── installer.py                 # Windows installer template
├── build_exe.ps1                # PyInstaller build script
└── README.md                    # This file
```

## 🌍 Language Support

Command AV supports 6 languages with full UI localization:

| Language | Code |
|----------|------|
| Polish | `pl` |
| English | `en` |
| Ukrainian | `uk` |
| German | `de` |
| French | `fr` |
| Spanish | `es` |

Change language in **Settings** tab without restarting the application.

## 🔐 VPN Integration

Integrated Windows VPN management for secure connections:

- Create and manage VPN profiles
- Support for multiple VPN types: PPTP, SSTP, IKEv2, L2TP
- Store VPN profiles locally in JSON format
- Connect/disconnect with one click
- Native Windows RAS integration

## 📊 Configuration

Settings are stored in `~/.command_av/`:
```
~/.command_av/
├── settings.json         # User preferences and language selection
├── vpn_profiles.json     # Saved VPN profiles
├── quarantine/           # Quarantined files
├── reports/              # Scan reports
└── logs/                 # Application logs
```

## 🔬 Scanning Examples

### Quick Scan
Scans user Desktop, Documents, and Downloads directories.

### Full System Scan
Recursively scans all accessible drives and partitions.

### Process Scanning
Identifies potentially malicious:
- Encoded PowerShell commands
- MSHTA remote script loading
- Regsvr32 dynamic scriptlet execution
- Rundll32 JavaScript execution
- Certutil download patterns

## ⚠️ Important Notes

- **Desktop Application**: Not a kernel driver or enterprise EDR system
- **Administrator Rights**: Required for VPN creation and full system scanning
- **Windows Only**: Currently supports Windows 10 and later
- **Development Stage**: Continuously improved with new signatures and features
- **User Data**: Settings and quarantine stored locally, no cloud connectivity

## 📝 License

MIT License - See LICENSE file for details

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📧 Support

For issues, bugs, or feature requests, please open an issue on GitHub.

## 🔄 Version History

### v2.0 (Current)
- ✅ Multilingual UI (6 languages)
- ✅ VPN Profile Management
- ✅ Improved Process Scanning
- ✅ Live Guard Real-time Monitoring
- ✅ JSON-based Reports

### v1.0
- ✅ Core scanning engine
- ✅ File and process detection
- ✅ Quarantine system
- ✅ Basic reporting

---

**Made with ❤️ for Windows security**
