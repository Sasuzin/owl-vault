# -*- mode: python ; coding: utf-8 -*-
# Spec do PyInstaller para OwlVault.exe (onefile, janela, sem console, asInvoker, sem UPX).
# Uso: packaging\build.ps1  (ou: python -m PyInstaller --noconfirm --clean packaging\owl_vault.spec)

from pathlib import Path

HERE = Path(SPECPATH)
ROOT = HERE.parent

EXCLUDES = [
    "tkinter",
    "unittest",
    "pydoc",
    "PySide6.QtWebEngineCore",
    "PySide6.QtWebEngineWidgets",
    "PySide6.QtWebEngineQuick",
    "PySide6.QtWebChannel",
    "PySide6.QtQml",
    "PySide6.QtQuick",
    "PySide6.QtQuick3D",
    "PySide6.QtQuickWidgets",
    "PySide6.Qt3DCore",
    "PySide6.Qt3DRender",
    "PySide6.QtMultimedia",
    "PySide6.QtMultimediaWidgets",
    "PySide6.QtNetwork",
    "PySide6.QtPdf",
    "PySide6.QtPdfWidgets",
    "PySide6.QtSql",
    "PySide6.QtCharts",
    "PySide6.QtDataVisualization",
    "PySide6.QtBluetooth",
    "PySide6.QtPositioning",
    "PySide6.QtSerialPort",
    "PySide6.QtSvg",
    "PySide6.QtOpenGL",
    "PySide6.QtOpenGLWidgets",
]

a = Analysis(
    [str(HERE / "owlvault_entry.py")],
    pathex=[str(ROOT / "src")],
    binaries=[],
    datas=[],
    hiddenimports=["argon2._utils", "_cffi_backend"],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=EXCLUDES,
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="OwlVault",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=str(HERE / "owl.ico"),
    version=str(HERE / "version_info.txt"),
    uac_admin=False,
)
