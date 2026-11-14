# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec — DCP Studio desktop bundle (one folder).

Build from the repository root:

    uv run --with pyinstaller==6.22.3 pyinstaller --noconfirm --clean \
        --distpath dist/pyinstaller --workpath build/pyinstaller \
        packaging/dcp-studio.spec

Result: ``dist/pyinstaller/dcp-studio/`` with the windowed ``dcp-studio``
launcher. The headless CLI is a separate spec (``dcp-cli.spec``) because a
windowed executable has no console on Windows.

Scapy is collected wholesale on purpose: its platform layer and its data files
are chosen by import-time probing (``scapy.arch.windows`` vs
``scapy.arch.linux``), not by static imports, so static analysis alone would
produce a bundle that fails the moment an interface is enumerated.

One folder, not one file: a one-file build unpacks hundreds of megabytes of Qt
into a temporary directory on every start.
"""

from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files, collect_submodules, copy_metadata

ROOT = Path(SPECPATH).parent
NAME = "dcp-studio"

datas = collect_data_files("scapy")
# importlib.metadata reads this at run time to report the application version;
# without it a frozen build would fall back to "0.0.0+unknown".
datas += copy_metadata("dcp-studio")
hiddenimports = collect_submodules("scapy")

# Qt modules this application never imports; only QtCore, QtGui and QtWidgets
# are used. The excludes cannot remove Qt's own shared libraries that arrive as
# binary dependencies (libQt6Quick, libQt6Qml, libQt6Pdf), but they do keep
# unused Python bindings out. Measured Linux one-folder size: 178 MB
# (2026-11-14); the Qt-free CLI bundle is 29 MB.
EXCLUDES = [
    "tkinter",
    "PySide6.QtWebEngineCore",
    "PySide6.QtWebEngineWidgets",
    "PySide6.QtWebEngineQuick",
    "PySide6.QtQuick",
    "PySide6.QtQuickWidgets",
    "PySide6.QtQml",
    "PySide6.Qt3DCore",
    "PySide6.Qt3DRender",
    "PySide6.QtMultimedia",
    "PySide6.QtCharts",
    "PySide6.QtDataVisualization",
    "PySide6.QtPdf",
    "PySide6.QtSql",
    "PySide6.QtTest",
]

a = Analysis(
    [str(ROOT / "packaging" / "launchers" / "dcp_studio_main.py")],
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
    console=False,
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
