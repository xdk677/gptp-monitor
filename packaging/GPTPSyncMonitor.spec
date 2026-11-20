from pathlib import Path

from PyInstaller.utils.hooks import collect_all

project_root = Path(SPECPATH).parent
scapy_datas, scapy_binaries, scapy_hiddenimports = collect_all("scapy")

analysis = Analysis(
    [str(Path(SPECPATH) / "launch_gui.py")],
    pathex=[str(project_root / "src")],
    binaries=scapy_binaries,
    datas=scapy_datas,
    hiddenimports=scapy_hiddenimports,
    excludes=["tkinter", "matplotlib", "pandas"],
)

pyz = PYZ(analysis.pure)

exe = EXE(
    pyz,
    analysis.scripts,
    [],
    exclude_binaries=True,
    name="GPTPSyncMonitor",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    version=str(Path(SPECPATH) / "version_info.txt"),
)

coll = COLLECT(
    exe,
    analysis.binaries,
    analysis.datas,
    strip=False,
    upx=True,
    name="GPTPSyncMonitor",
)
