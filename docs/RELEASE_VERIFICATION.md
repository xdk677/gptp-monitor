# GPTPSyncMonitor v1.0.0 Verification

Verified on 2026-11-20 on Windows 10 x64 with Python 3.14 and Npcap
1.x installed.

## Automated tests

```text
126 passed in 1.22s
```

Offscreen GUI smoke:

```powershell
python -m gptp_monitor.gui --offscreen --smoke-ui
```

Result: exit code `0`.

## Built EXE

- Path: `GPTPSyncMonitor.exe`
- Size: `7,691,474` bytes
- File version: `1.0.0.0`
- Product version: `1.0.0`
- Offscreen smoke from the release directory: exit code `0`
- Visible launch: process responding, window title `GPTPSyncMonitor 1.0.0`

The EXE and release-document hashes are recorded in the generated
`SHA256SUMS.txt`.

## Release archives

The Windows and source ZIP SHA256 values are generated for each build and
recorded alongside the release files. Verify them with:

```powershell
Get-FileHash release\GPTPSyncMonitor-v1.0.0-windows-x64.zip -Algorithm SHA256
Get-FileHash release\GPTPSyncMonitor-v1.0.0-source.zip -Algorithm SHA256
```

Source ZIP entries: 37. No `build/`, `dist/`, `release/`, `__pycache__`,
`.pyc`, `.pytest_cache`, virtual environment or egg-info entries were present.
The extracted source ZIP was installed and its full test suite passed.

The GitHub Actions workflow installs Npcap with Chocolatey before running
Scapy-dependent smoke checks.

## External prerequisite

The release does not include the Npcap installer. Target PCs must install
Npcap separately and grant raw Ethernet access.
