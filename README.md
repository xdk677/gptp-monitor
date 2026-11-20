# GPTPSyncMonitor 1.0.0

GPTPSyncMonitor is a Windows desktop tool for operating a software gPTP
Master and analyzing an external gPTP Master as a Slave. It supports IEEE
802.1AS-style Ethernet framing over Npcap, two-step Sync/FollowUp, peer delay
measurement, live trend charts and detailed protocol statistics.

## Features

- Master mode: Announce, Sync/FollowUp, Pdelay requests and responses.
- Slave mode: automatic Grandmaster lock and real-time Offset analysis.
- Standard 34-byte and vendor-extended 54-byte Pdelay request support.
- Per-Slave RTT, Path delay, timeout and success counters.
- Responsive PyQt5 interface for 1366x768 and 1920x1080 screens.
- Detailed Tooltips and read-only Slave row details.
- Windows one-directory executable; Python is not required on the target PC.

## Npcap prerequisite

The target PC must have Npcap installed with raw Ethernet access enabled.
Download it from <https://npcap.com/#download>. Start GPTPSyncMonitor as
Administrator if Npcap reports access denied.

The release does not redistribute the Npcap installer.

## EXE quick start

1. Extract `GPTPSyncMonitor-v1.0.0-windows-x64.zip`.
2. Install Npcap if it is not already installed.
3. Run `GPTPSyncMonitor.exe`.
4. Select the Ethernet adapter connected to the gPTP network.
5. Select `Master` or `Slave`, then click `Start`.

See [USER_GUIDE.md](docs/USER_GUIDE.md) for complete operating instructions.

## Source development

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
python -m pytest tests -q
python -m gptp_monitor.gui
```

Master CLI:

```powershell
gptp-monitor-cli --iface "Ethernet" --time-offset-s 0
```

## Build Windows release

```powershell
pwsh -NoProfile -File scripts/build.ps1
```

The release script runs tests, builds the PyInstaller one-directory package,
creates the Windows ZIP and source ZIP, and writes SHA256 checksums.

## Documentation

- [User Guide](docs/USER_GUIDE.md)
- [Metrics Reference](docs/METRICS.md)
- [Troubleshooting](docs/TROUBLESHOOTING.md)
- [Release Verification](docs/RELEASE_VERIFICATION.md)
- [Changelog](CHANGELOG.md)

## Precision

The program uses Windows user-space packet timestamps. It is intended for
functional gPTP integration and analysis, not hardware-timestamp calibration.
Observed offset, frequency and Path delay values include Windows scheduling
and USB/NIC timestamp jitter.

## License

MIT License. Copyright (c) 2026 xdk677. See [LICENSE](LICENSE).

