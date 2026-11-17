# -*- mode: python ; coding: utf-8 -*-
# Spec do PyInstaller para OwlVault.exe (onefile, janela, sem console, asInvoker, sem UPX).
# Uso: packaging\build.ps1 (recomendado: roda os testes e regenera packaging\owl.ico).
# Manual: python packaging\make_icon.py  e depois  python -m PyInstaller --noconfirm --clean packaging\owl_vault.spec
# (sem o make_icon, o ícone do .exe no Explorer pode ficar desatualizado)

from pathlib import Path

import PySide6

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
    # logo (escudo da coruja) usado no ícone da janela, cabeçalho e "Sobre";
    # tradução pt-BR dos botões/menus do próprio Qt ("Sim"/"Não", "Copiar"...)
    datas=[
        (str(ROOT / "src" / "owl_vault" / "ui" / "assets" / "owl-shield.png"), "owl_vault/ui/assets"),
        (str(Path(PySide6.__file__).parent / "translations" / "qtbase_pt_BR.qm"), "PySide6/translations"),
    ],
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
