# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec — headless ``dcp-cli`` bundle (one folder, console).

Build from the repository root:

    uv run --with pyinstaller==6.22.3 pyinstaller --noconfirm --clean \
        --distpath dist/pyinstaller --workpath build/pyinstaller \
        packaging/dcp-cli.spec

This bundle is deliberately Qt-free: ``dcpstudio.cli`` reaches the same
services, codec and safety model as the GUI but imports nothing from
``dcpstudio.gui``. That keeps the archive small and lets it run on a machine
with no display at all.
"""

from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files, collect_submodules, copy_metadata

ROOT = Path(SPECPATH).parent
NAME = "dcp-cli"

datas = collect_data_files("scapy")
# importlib.metadata reads this at run time to report the application version;
# without it a frozen build would fall back to "0.0.0+unknown".
datas += copy_metadata("dcp-studio")
hiddenimports = collect_submodules("scapy")

# The CLI never imports the GUI, so the whole Qt binding can be dropped.
EXCLUDES = ["tkinter", "PySide6"]

a = Analysis(
    [str(ROOT / "packaging" / "launchers" / "dcp_cli_main.py")],
    pathex=[str(ROOT / "src")],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=EXCLUDES,
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name=NAME,
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name=NAME,
)
