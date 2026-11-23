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
        # tema "Cofre" (Claude Design): folha de estilo com os tokens
        (str(ROOT / "src" / "owl_vault" / "ui" / "tema" / "owlvault.qss"), "owl_vault/ui/tema"),
        (str(Path(PySide6.__file__).parent / "translations" / "qtbase_pt_BR.qm"), "PySide6/translations"),
    ],
    # QtNetwork: canal local da instância única (atalho "Abrir com Owl Vault")
    hiddenimports=["argon2._utils", "_cffi_backend", "PySide6.QtNetwork", "owl_vault._build"],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=EXCLUDES,
    noarchive=False,
    optimize=0,
)

# Sem TLS do Qt: o Owl Vault não usa rede (o QtNetwork serve só ao canal local da instância
# única). Sem este filtro, o gancho do PySide6 levava os plugins de TLS e as libssl/libcrypto
# "-x64" que achasse no PATH da máquina do build (na 0.4.0: as do Git for Windows, de versão
# desconhecida). A libcrypto-3.dll do próprio Python (hashlib/ssl) continua.
_TLS_DLLS = {"libssl-3-x64.dll", "libcrypto-3-x64.dll"}


def _sem_tls(toc):
    out = []
    for entry in toc:
        dest = entry[0].replace("/", "\\").lower()
        if dest.startswith("pyside6\\plugins\\tls\\") or dest.rsplit("\\", 1)[-1] in _TLS_DLLS:
            continue
        out.append(entry)
    return out


a.binaries = _sem_tls(a.binaries)
a.datas = _sem_tls(a.datas)

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
