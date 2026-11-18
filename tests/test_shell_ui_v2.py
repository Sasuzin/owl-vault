"""Integração com o Windows (shell, DPAPI, instalação) e interface v2 (pastas protegidas).

Regras destes testes: SOMENTE pastas temporárias (tmp_path) com dados sintéticos; o perfil
fica sempre em tmp_path com TESTING_POLICY/TESTING_PARAMS; nenhum diálogo modal é aberto
(``ask``/``inform``/``SecretDialog`` e o seletor de pastas são trocados por gravadores).
"""

from __future__ import annotations

import builtins
import ctypes
import datetime as dt
import gc
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import threading
import time
import types
from collections.abc import Callable, Iterator
from ctypes import wintypes
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import shiboken6
from PySide6.QtCore import SIGNAL, QCoreApplication, QEvent, QPoint, Qt
from PySide6.QtGui import QColor
from PySide6.QtTest import QTest
from PySide6.QtWidgets import (
    QApplication,
    QDialog,
    QGraphicsDropShadowEffect,
    QLabel,
    QLineEdit,
    QMenu,
    QPushButton,
    QScrollArea,
    QToolButton,
    QWidget,
)

from owl_vault import version_label
from owl_vault.application import install
from owl_vault.application import profile as profile_mod
from owl_vault.application.lockers import (
    ABERTA,
    ABERTURA_INCOMPLETA,
    ABRINDO,
    APAGANDO,
    COFRE_DIFERENTE,
    ICON_NAME,
    INFOTIP,
    MANTIDO,
    RESTAURANDO,
    TRANCADA,
    TRANCANDO,
    FolderView,
    LockOutcome,
    ProtectCheck,
    UnlockOutcome,
)
from owl_vault.application.profile import (
    DpapiUnavailableError,
    FolderRecord,
    PinError,
    PinUnavailableError,
    ProfileCorruptError,
    ProfileStore,
    VaultRef,
)
from owl_vault.application.progress import CancelToken, NullProgress
from owl_vault.application.protection import ProtectedPaths
from owl_vault.application.restore import RestoreReport
from owl_vault.crypto.kdf import TESTING_PARAMS, TESTING_POLICY
from owl_vault.domain.errors import (
    AuthenticationError,
    CancelledError,
    OwlVaultError,
    PreflightError,
    StateError,
)
from owl_vault.storage import dpapi, shell, winfs
from owl_vault.ui import app as ui_app
from owl_vault.ui import (
    common,
    componentes,
    folder_dialogs,
    owl_window,
    pages,
    protect_flow,
    single_instance,
)
from owl_vault.ui.owl_window import IDLE_LOCK_SECONDS, OwlWindow
from owl_vault.ui.theme import current_tokens
from owl_vault.ui.workers import JobRunner

LAUNCHER = ("C:\\Windows\\notepad.exe", "")
PIN = "947361"
PIN_ERRADO = "583920"
SENHA_MESTRA = "cavalo correto bateria grampo"
NOME = "Projeto Sigiloso Ômega"
ID_OK = "0123456789abcdef0123456789abcdef"

H = shell.FILE_ATTRIBUTE_HIDDEN
S = shell.FILE_ATTRIBUTE_SYSTEM
R = shell.FILE_ATTRIBUTE_READONLY
FILE_ATTRIBUTE_ARCHIVE = 0x20
FILE_ATTRIBUTE_NORMAL = 0x80

gui = pytest.mark.gui


# =========================================================================== utilidades Qt


@pytest.fixture(scope="module")
def qapp() -> Iterator[QApplication]:
    """Uma QApplication por módulo, sem janela real (plataforma offscreen)."""
    anterior = os.environ.get("QT_QPA_PLATFORM")
    os.environ["QT_QPA_PLATFORM"] = "offscreen"
    app = QApplication.instance() or QApplication(["owl-vault-testes"])
    assert isinstance(app, QApplication)
    yield app
    _descarta()
    if anterior is None:
        os.environ.pop("QT_QPA_PLATFORM", None)
    else:
        os.environ["QT_QPA_PLATFORM"] = anterior


def _descarta() -> None:
    """Processa eventos pendentes e as exclusões adiadas (deleteLater)."""
    QCoreApplication.processEvents()
    QCoreApplication.sendPostedEvents(None, int(QEvent.Type.DeferredDelete.value))
    QCoreApplication.processEvents()


def _espera(cond: Callable[[], object], timeout: float = 30.0) -> None:
    fim = time.monotonic() + timeout
    while not cond():
        if time.monotonic() > fim:
            raise AssertionError("tempo esgotado esperando a interface")
        QCoreApplication.processEvents()
        time.sleep(0.005)


def _textos(widget: QWidget, *, so_visiveis: bool = False) -> list[str]:
    """Textos dos QLabel dentro de ``widget`` (visíveis = seriam mostrados com a janela)."""
    out: list[str] = []
    for lbl in widget.findChildren(QLabel):
        if so_visiveis and not lbl.isVisibleTo(widget):
            continue
        out.append(lbl.text())
    return out


def _mesmo(a: str | Path, b: str | Path) -> bool:
    """Mesmo caminho (o Windows não diferencia maiúsculas)."""
    return os.path.normcase(os.path.normpath(str(a))) == os.path.normcase(os.path.normpath(str(b)))


# =========================================================================== shell: desktop.ini


def test_desktop_ini_utf16_com_bom_crlf_e_acentos(tmp_path: Path) -> None:
    dica = "Pasta protegida — não apague: ação, ÁÉÍÓÚ, ü, 日本"
    data = shell.desktop_ini_bytes(".owlvault.ico", dica)
    assert data[:2] == b"\xff\xfe"  # BOM UTF-16LE
    texto = data[2:].decode("utf-16-le")
    assert "\ufeff" not in texto  # só um BOM, no início
    # todas as quebras de linha são CRLF (nada de \n ou \r soltos)
    sem_crlf = texto.replace("\r\n", "")
    assert "\n" not in sem_crlf
    assert "\r" not in sem_crlf
    assert texto.split("\r\n") == [
        "[.ShellClassInfo]",
        "IconResource=.owlvault.ico,0",  # ícone RELATIVO à pasta
        f"InfoTip={dica}",
        "ConfirmFileOp=0",
        "",
    ]
    # gravado e relido como o Windows lê (UTF-16 com BOM): os acentos sobrevivem
    ini = tmp_path / "desktop.ini"
    ini.write_bytes(data)
    assert ini.read_bytes().decode("utf-16") == texto


def test_desktop_ini_com_textos_reais_da_pasta_trancada() -> None:
    data = shell.desktop_ini_bytes(ICON_NAME, INFOTIP)
    texto = data[2:].decode("utf-16-le")
    assert f"IconResource={ICON_NAME},0\r\n" in texto
    assert f"InfoTip={INFOTIP}\r\n" in texto
    assert "\\" not in texto and ":" not in texto.split("InfoTip=")[0]  # nenhum caminho absoluto


# =========================================================================== shell: atributos


def test_atributos_de_arquivo_ida_e_volta(tmp_path: Path) -> None:
    f = tmp_path / "arquivo sintético ção.txt"
    f.write_bytes(b"dados sinteticos")
    p = str(f)
    antes = shell.get_attributes(p)
    assert not antes & (H | S | R)
    try:
        shell.change_attributes(p, add=H | S | R)
        assert shell.get_attributes(p) & (H | S | R) == H | S | R
        # caminho estendido (\\?\) enxerga o mesmo arquivo
        assert shell.get_attributes(winfs.to_extended(p)) == shell.get_attributes(p)
        shell.change_attributes(p, remove=H | R)
        assert shell.get_attributes(p) & (H | S | R) == S
        shell.change_attributes(winfs.to_extended(p), remove=S)
        assert shell.get_attributes(p) == antes
        shell.change_attributes(p)  # nada a mudar: não falha
        assert shell.get_attributes(p) == antes
    finally:
        shell.change_attributes(p, remove=H | S | R)


def test_atributos_sem_nenhum_viram_normal(tmp_path: Path) -> None:
    f = tmp_path / "normal.bin"
    f.write_bytes(b"x")
    p = str(f)
    shell.change_attributes(p, add=FILE_ATTRIBUTE_ARCHIVE)
    atual = shell.get_attributes(p)
    shell.change_attributes(p, remove=atual)
    assert shell.get_attributes(p) == FILE_ATTRIBUTE_NORMAL


def test_atributos_de_caminho_inexistente_falham(tmp_path: Path) -> None:
    with pytest.raises(OSError):
        shell.get_attributes(str(tmp_path / "nao-existe.txt"))
    with pytest.raises(OSError):
        shell.change_attributes(str(tmp_path / "nao-existe.txt"), add=H)


# =========================================================================== shell: pasta de sistema


def test_make_e_unmake_system_folder(tmp_path: Path) -> None:
    pasta = tmp_path / "Pasta Trancada ção"
    pasta.mkdir()
    (pasta / "desktop.ini").write_bytes(shell.desktop_ini_bytes(ICON_NAME, INFOTIP))
    p = str(pasta)
    try:
        shell.make_system_folder(p)
        assert shell.get_attributes(p) & (R | S)  # o Explorer passa a ler o desktop.ini
        shell.notify_changed(p)  # só um aviso ao Explorer: não falha
        shell.unmake_system_folder(p)
        assert not shell.get_attributes(p) & (R | S)
        # o mesmo pelo caminho estendido
        shell.make_system_folder(winfs.to_extended(p))
        assert shell.get_attributes(p) & (R | S)
        shell.unmake_system_folder(winfs.to_extended(p))
        assert not shell.get_attributes(p) & (R | S)
    finally:
        shell.change_attributes(p, remove=R | S)


def test_make_system_folder_em_caminho_longo(tmp_path: Path) -> None:
    base = winfs.to_extended(str(tmp_path))
    partes = [f"subpasta-com-nome-bem-comprido-{i:02d}" for i in range(8)]
    longo = winfs.join(base, *partes)
    os.makedirs(longo)
    try:
        assert len(winfs.strip_extended(longo)) > 260
        shell.make_system_folder(longo)
        assert shell.get_attributes(longo) & (R | S)
        shell.unmake_system_folder(longo)
        assert not shell.get_attributes(longo) & (R | S)
    finally:
        try:
            shell.change_attributes(longo, remove=R | S)
        except OSError:
            pass
        shutil.rmtree(winfs.join(base, partes[0]), ignore_errors=True)


# =========================================================================== shell: atalho .lnk


def _ler_atalho(lnk: Path) -> dict[str, str]:
    """Lê um .lnk pela própria API do Windows (IShellLinkW + IPersistFile::Load)."""
    w = wintypes
    hr_init = shell._CoInitializeEx(None, shell._COINIT_APARTMENTTHREADED)
    link = ctypes.c_void_p()
    persist = ctypes.c_void_p()
    try:
        clsid = shell._GUID.parse(shell._CLSID_ShellLink)
        iid = shell._GUID.parse(shell._IID_IShellLinkW)
        hr = shell._CoCreateInstance(
            ctypes.byref(clsid), None, 1, ctypes.byref(iid), ctypes.byref(link)
        )
        assert hr >= 0
        iid_pf = shell._GUID.parse(shell._IID_IPersistFile)
        pguid = ctypes.POINTER(shell._GUID)
        pvoid = ctypes.POINTER(ctypes.c_void_p)
        hr = shell._vcall(
            link, 0, ctypes.byref(iid_pf), ctypes.byref(persist), argtypes=(pguid, pvoid)
        )
        assert hr >= 0
        assert shell._vcall(persist, 5, str(lnk), 0, argtypes=(w.LPCWSTR, w.DWORD)) >= 0
        out: dict[str, str] = {}
        buf = ctypes.create_unicode_buffer(4096)
        hr = shell._vcall(
            link,
            3,  # GetPath (SLGP_RAWPATH)
            buf,
            len(buf),
            None,
            0x4,
            argtypes=(w.LPWSTR, ctypes.c_int, ctypes.c_void_p, w.DWORD),
        )
        assert hr >= 0
        out["alvo"] = buf.value
        for chave, indice in (("argumentos", 10), ("pasta", 8), ("descricao", 6)):
            buf = ctypes.create_unicode_buffer(4096)
            assert shell._vcall(link, indice, buf, len(buf), argtypes=(w.LPWSTR, ctypes.c_int)) >= 0
            out[chave] = buf.value
        buf = ctypes.create_unicode_buffer(4096)
        n = ctypes.c_int()
        hr = shell._vcall(
            link,
            16,  # GetIconLocation
            buf,
            len(buf),
            ctypes.byref(n),
            argtypes=(w.LPWSTR, ctypes.c_int, ctypes.POINTER(ctypes.c_int)),
        )
        assert hr >= 0
        out["icone"] = buf.value
        return out
    finally:
        if persist:
            shell._vcall(persist, 2, argtypes=())
        if link:
            shell._vcall(link, 2, argtypes=())
        if hr_init in (0, 1):
            shell._CoUninitialize()


def test_create_shortcut_cria_lnk_com_argumentos_dificeis(tmp_path: Path) -> None:
    pasta = tmp_path / "Atalhos com espaço e ção"
    pasta.mkdir()
    lnk = pasta / "Abrir com Owl Vault.lnk"
    args = "--abrir \"C:\\pasta com espaço\\ação\" 'aspas simples' çãõ & | > %PATH%"
    descricao = "Descrição com acentos — teste sintético"
    alvo = "C:\\Windows\\notepad.exe"
    shell.create_shortcut(str(lnk), alvo, args, alvo, descricao, str(pasta))
    assert lnk.is_file()
    assert lnk.read_bytes()[:4] == b"\x4c\x00\x00\x00"  # cabeçalho de um Shell Link
    # relido pelo Windows: argumentos exatamente como passados (nada de linha de comando)
    lido = _ler_atalho(lnk)
    assert _mesmo(lido["alvo"], alvo)
    assert lido["argumentos"] == args
    assert lido["descricao"] == descricao
    assert _mesmo(lido["pasta"], pasta)
    assert _mesmo(lido["icone"], alvo)


def test_create_shortcut_aceita_caminho_estendido_e_regrava(tmp_path: Path) -> None:
    lnk = tmp_path / "atalho.lnk"
    alvo = "C:\\Windows\\notepad.exe"
    shell.create_shortcut(winfs.to_extended(str(lnk)), alvo, "--abrir 1", alvo, "um", str(tmp_path))
    assert lnk.is_file()
    assert _ler_atalho(lnk)["argumentos"] == "--abrir 1"
    shell.create_shortcut(str(lnk), alvo, "--abrir 2", alvo, "dois", str(tmp_path))
    lido = _ler_atalho(lnk)
    assert lido["argumentos"] == "--abrir 2"
    assert lido["descricao"] == "dois"


def test_create_shortcut_em_pasta_inexistente_falha(tmp_path: Path) -> None:
    lnk = tmp_path / "nao-existe" / "atalho.lnk"
    alvo = "C:\\Windows\\notepad.exe"
    with pytest.raises(OwlVaultError):
        shell.create_shortcut(str(lnk), alvo, "", alvo, "x", str(tmp_path))
    assert not lnk.exists()


# =========================================================================== shell: pastas conhecidas


def test_known_folders_devolve_caminhos_existentes() -> None:
    pastas = shell.known_folders()  # só leitura
    assert isinstance(pastas, dict)
    assert pastas
    assert set(pastas) <= set(shell.KNOWN_FOLDERS)
    assert "Perfil do usuário" in pastas
    for nome, caminho in pastas.items():
        assert isinstance(caminho, str)
        assert os.path.isabs(caminho), nome
        assert os.path.isdir(caminho), nome


def test_known_folder_guid_desconhecido_devolve_none() -> None:
    assert shell.known_folder("00000000-0000-0000-0000-000000000000") is None


# =========================================================================== DPAPI


def test_dpapi_ida_e_volta_com_bytes_nulos() -> None:
    dados = bytes(range(256)) * 3 + b"\x00\x00fim"
    entropia = b"perfil-sintetico-0123"
    blob = dpapi.protect(dados, entropia, "Owl Vault — teste sintético")
    assert dados not in blob
    assert dpapi.unprotect(blob, entropia) == dados
    # cada proteção é diferente (aleatória), mas ambas abrem
    blob2 = dpapi.protect(dados, entropia)
    assert blob2 != blob
    assert dpapi.unprotect(blob2, entropia) == dados


def test_dpapi_dados_vazios() -> None:
    blob = dpapi.protect(b"", b"entropia")
    assert dpapi.unprotect(blob, b"entropia") == b""


def test_dpapi_entropia_errada_e_autenticacao() -> None:
    blob = dpapi.protect(b"segredo sintetico", b"perfil-a")
    with pytest.raises(AuthenticationError):
        dpapi.unprotect(blob, b"perfil-b")
    with pytest.raises(AuthenticationError):
        dpapi.unprotect(blob, b"")
    with pytest.raises(AuthenticationError):
        dpapi.unprotect(blob, b"perfil-a\x00")


def test_dpapi_blob_adulterado_ou_lixo() -> None:
    blob = bytearray(dpapi.protect(b"segredo sintetico", b"perfil"))
    blob[-5] ^= 0x01
    with pytest.raises(AuthenticationError):
        dpapi.unprotect(bytes(blob), b"perfil")
    with pytest.raises(AuthenticationError):
        dpapi.unprotect(b"isto nao e um blob do dpapi", b"perfil")


# =========================================================================== instalação (T0)


def test_ensure_installed_em_desenvolvimento_usa_python(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delattr(sys, "frozen", raising=False)
    local = tmp_path / "LocalAppData"
    local.mkdir()
    monkeypatch.setenv("LOCALAPPDATA", str(local))
    monkeypatch.setenv("APPDATA", str(tmp_path / "Roaming"))
    resultado = install.ensure_installed()
    assert resultado == shell.current_executable()
    exe, args = resultado
    assert args == "-m owl_vault"
    assert os.path.normcase(os.path.dirname(exe)) == os.path.normcase(
        os.path.dirname(sys.executable)
    )
    assert list(local.iterdir()) == []  # nada foi copiado


@dataclass
class InstalacaoFalsa:
    baixado: Path
    local: Path
    menu_iniciar: Path
    alvo: Path
    atalho: Path
    escritas: list[str]
    pe: bytes = field(repr=False)


@pytest.fixture
def instalacao(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> InstalacaoFalsa:
    """``OwlVault.exe`` falso e LOCALAPPDATA/APPDATA dentro de tmp_path.

    O executável falso é o lançador do Python do venv com bytes aleatórios no fim: o Explorer
    só grava atalho para um PE válido (com bytes quaisquer, IPersistFile::Save dá E_FAIL).
    """
    pe = Path(sys.executable).read_bytes()
    baixado = tmp_path / "Downloads sintéticos" / "OwlVault.exe"
    baixado.parent.mkdir()
    baixado.write_bytes(pe + os.urandom(4096))
    local = tmp_path / "LocalAppData"
    local.mkdir()
    roaming = tmp_path / "AppData Roaming"
    menu = roaming / "Microsoft" / "Windows" / "Start Menu" / "Programs"
    menu.mkdir(parents=True)
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", str(baixado))
    monkeypatch.setenv("LOCALAPPDATA", str(local))
    monkeypatch.setenv("APPDATA", str(roaming))
    escritas: list[str] = []

    def abre(file: Any, mode: str = "r", *a: Any, **k: Any) -> Any:
        if "x" in mode or "w" in mode:
            escritas.append(str(file))
        return builtins.open(file, mode, *a, **k)

    monkeypatch.setattr(install, "open", abre, raising=False)
    return InstalacaoFalsa(
        baixado,
        local,
        menu,
        local / "Programs" / "Owl Vault" / "OwlVault.exe",
        menu / "Owl Vault.lnk",
        escritas,
        pe,
    )


def test_ensure_installed_congelado_copia_e_cria_atalho(instalacao: InstalacaoFalsa) -> None:
    assert shell.current_executable() == (str(instalacao.baixado), "")
    exe, args = install.ensure_installed()
    assert args == ""
    assert _mesmo(exe, instalacao.alvo)
    assert instalacao.alvo.read_bytes() == instalacao.baixado.read_bytes()
    # sem .tmp; ao lado ficam a versão instalada (impede trocar por uma versão mais antiga) e a
    # marca que liga essa versão ao conteúdo do exe (install.STAMP_FILE, revisão "perfil")
    assert sorted(p.name for p in instalacao.alvo.parent.iterdir()) == [
        "OwlVault.exe",
        "versao.sha256",
        "versao.txt",
    ]
    assert len(instalacao.escritas) == 1
    assert instalacao.atalho.is_file()
    lido = _ler_atalho(instalacao.atalho)
    assert _mesmo(lido["alvo"], instalacao.alvo)  # aponta para a cópia instalada (fixa)
    assert lido["argumentos"] == ""
    assert _mesmo(lido["pasta"], instalacao.alvo.parent)
    assert lido["descricao"] == "Owl Vault — pastas protegidas"


def test_ensure_installed_segunda_chamada_nao_recopia(instalacao: InstalacaoFalsa) -> None:
    install.ensure_installed()
    st_exe = instalacao.alvo.stat()
    st_lnk = instalacao.atalho.stat()
    instalacao.escritas.clear()
    exe, _args = install.ensure_installed()
    assert _mesmo(exe, instalacao.alvo)
    assert instalacao.escritas == []  # nenhuma cópia nova
    st2 = instalacao.alvo.stat()
    assert (st2.st_ino, st2.st_mtime_ns) == (st_exe.st_ino, st_exe.st_mtime_ns)
    assert instalacao.atalho.stat().st_mtime_ns == st_lnk.st_mtime_ns  # atalho não refeito


def test_ensure_installed_atualiza_so_com_versao_mais_nova(
    instalacao: InstalacaoFalsa, monkeypatch: pytest.MonkeyPatch
) -> None:
    install.ensure_installed()
    antigo = instalacao.alvo.read_bytes()
    novo = instalacao.pe + os.urandom(4096)  # mesmo tamanho, conteúdo diferente
    assert len(novo) == instalacao.baixado.stat().st_size
    instalacao.baixado.write_bytes(novo)
    instalacao.escritas.clear()
    major, minor, patch, build = install.current_version()
    # versão mais antiga: NUNCA substitui o instalado (revisão de segurança)
    monkeypatch.setattr(
        install, "current_version", lambda: (major, minor, patch - 1 if patch else 0, 0)
    )
    install.ensure_installed()
    assert instalacao.alvo.read_bytes() == antigo
    assert instalacao.escritas == []
    # versão mais nova: atualiza e grava a versão nova ao lado
    monkeypatch.setattr(install, "current_version", lambda: (major, minor, patch, build + 1))
    install.ensure_installed()
    assert instalacao.alvo.read_bytes() == novo
    assert len(instalacao.escritas) == 1
    assert install.installed_version(instalacao.alvo.parent) == (major, minor, patch, build + 1)
    # mesma versão com conteúdo diferente é um rebuild (ou um exe trocado por fora): substitui
    # (regra de install.py desde a revisão "perfil"; antes este teste exigia o contrário)
    rebuild = instalacao.pe + os.urandom(4096)
    instalacao.baixado.write_bytes(rebuild)
    install.ensure_installed()
    assert instalacao.alvo.read_bytes() == rebuild


def test_ensure_installed_rodando_da_copia_instalada(
    instalacao: InstalacaoFalsa, monkeypatch: pytest.MonkeyPatch
) -> None:
    install.ensure_installed()
    monkeypatch.setattr(sys, "executable", str(instalacao.alvo))
    instalacao.escritas.clear()
    exe, _args = install.ensure_installed()
    assert _mesmo(exe, instalacao.alvo)
    assert instalacao.escritas == []


def test_ensure_installed_copia_impossivel_roda_de_onde_esta(
    instalacao: InstalacaoFalsa,
) -> None:
    instalacao.alvo.parent.parent.mkdir(parents=True)
    instalacao.alvo.parent.write_bytes(b"")  # um ARQUIVO no lugar da pasta de instalação
    exe, _args = install.ensure_installed()  # falha silenciosa: o programa roda de onde está
    assert _mesmo(exe, instalacao.baixado)
    assert instalacao.alvo.parent.is_file()


def test_atalho_do_menu_iniciar_passa_para_a_copia_instalada(
    instalacao: InstalacaoFalsa,
) -> None:
    instalacao.alvo.parent.parent.mkdir(parents=True)
    instalacao.alvo.parent.write_bytes(b"")  # 1ª execução: a cópia não pôde ser feita
    install.ensure_installed()
    assert _mesmo(_ler_atalho(instalacao.atalho)["alvo"], instalacao.baixado)
    instalacao.alvo.parent.unlink()  # 2ª execução: agora a cópia funciona
    exe, _args = install.ensure_installed()
    assert _mesmo(exe, instalacao.alvo)
    assert _mesmo(_ler_atalho(instalacao.atalho)["alvo"], instalacao.alvo)


def test_ensure_installed_sem_menu_iniciar_nao_falha(instalacao: InstalacaoFalsa) -> None:
    shutil.rmtree(instalacao.menu_iniciar)
    exe, _args = install.ensure_installed()
    assert _mesmo(exe, instalacao.alvo)
    assert not instalacao.atalho.exists()


def test_ensure_installed_sem_localappdata_roda_de_onde_esta(
    instalacao: InstalacaoFalsa, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("LOCALAPPDATA")
    assert install.ensure_installed() == (str(instalacao.baixado), "")
    assert list(instalacao.local.iterdir()) == []


# =========================================================================== app._open_request


@pytest.mark.parametrize(
    ("argv", "esperado"),
    [
        (["--abrir", ID_OK], ID_OK),
        (["--abrir", f"  {ID_OK.upper()}  "], ID_OK),  # normalizado para minúsculas
        (["x", "--abrir", ID_OK, "--abrir", "zz"], ID_OK),
        (["--abrir", ID_OK[:-1]], None),  # 31
        (["--abrir", ID_OK + "0"], None),  # 33
        (["--abrir", "g" * 32], None),
        (["--abrir", ID_OK[:-1] + "\u0661"], None),  # dígito árabe-índico
        (["--abrir", "\uff10" * 32], None),  # zeros de largura total
        (["--abrir", "..\\..\\" + "a" * 26], None),
        (["--abrir", "0x" + ID_OK[:30]], None),
        (["--abrir", ID_OK[:16] + " " + ID_OK[16:]], None),
        (["--abrir", "--selftest"], None),
        (["--abrir"], None),
        ([f"--abrir={ID_OK}"], None),
        ([ID_OK], None),
        ([], None),
    ],
)
def test_open_request_aceita_so_32_hex(argv: list[str], esperado: str | None) -> None:
    assert ui_app._open_request(argv) == esperado


# =========================================================================== common


@pytest.mark.parametrize(
    ("estagio", "esperado"),
    [
        ("Pré-verificação: conferindo caminhos", "Conferindo a pasta"),
        ("Conferindo a pasta", "Conferindo a pasta"),
        ("Calibrando a derivação de chave", "Preparando a proteção"),
        ("Derivando chave (não cancelável)", "Preparando a proteção"),
        ("Criptografando", "1/4 Guardando os arquivos"),
        ("Verificando o cofre (derivando chave — não cancelável)", "2/4 Conferindo"),
        ("Verificando blocos criptografados", "2/4 Conferindo"),
        ("Teste de restauração", "3/4 Testando a recuperação"),
        ("Comparando a origem atual com o cofre", "3/4 Testando a recuperação"),
        ("Finalizando", "3/4 Testando a recuperação"),
        ("Apagando as cópias legíveis", "4/4 Apagando as cópias legíveis"),
        ("Etapa desconhecida", "Etapa desconhecida"),
    ],
)
def test_map_stage_trancar(estagio: str, esperado: str) -> None:
    assert common._map_stage("lock", estagio) == esperado


@pytest.mark.parametrize(
    ("estagio", "esperado"),
    [
        ("Abrindo o cofre (derivando chave — não cancelável)", "Preparando"),
        ("Conferindo o cofre antes de restaurar", "Conferindo os dados protegidos"),
        ("Restaurando", "Abrindo"),
        ("Etapa desconhecida", "Etapa desconhecida"),
    ],
)
def test_map_stage_abrir(estagio: str, esperado: str) -> None:
    assert common._map_stage("unlock", estagio) == esperado


@pytest.mark.parametrize(
    ("estagio", "esperado"),
    [
        ("Pré-verificação: listando a origem", "Conferindo a pasta"),
        ("Abrindo o cofre (derivando chave — não cancelável)", "Preparando"),
        ("Verificando blocos criptografados", "Conferindo os arquivos"),
        ("Restaurando", "Recuperando os arquivos"),
        ("Criptografando", "Guardando os arquivos"),
        ("Teste de restauração", "Testando a recuperação"),
        ("Outra coisa", "Outra coisa"),
    ],
)
def test_map_stage_generico(estagio: str, esperado: str) -> None:
    assert common._map_stage("generic", estagio) == esperado
    assert common._map_stage("modo-desconhecido", estagio) == esperado


def test_map_stage_trancar_nunca_mostra_texto_cru_do_motor() -> None:
    """Toda etapa emitida ao trancar tem texto da tela de progresso (UI_SPEC_V2 T6)."""
    do_motor = [
        "Pré-verificação: conferindo caminhos",
        "Pré-verificação: listando a origem",
        "Pré-verificação: abrindo arquivos",
        "Conferindo a pasta",
        "Criptografando",
        "Verificando o cofre (derivando chave — não cancelável)",
        "Teste de restauração",
        "Comparando a origem atual com o cofre",
        "Finalizando",
        "Apagando as cópias legíveis",
    ]
    for nome in do_motor:
        assert common._map_stage("lock", nome) != nome or nome == "Conferindo a pasta"
    for nome in (
        "Abrindo o cofre (derivando chave — não cancelável)",
        "Conferindo o cofre antes de restaurar",
        "Restaurando",
    ):
        assert common._map_stage("unlock", nome) != nome


@pytest.mark.parametrize(
    ("n", "esperado"),
    [
        (0, "0 bytes"),
        (1, "1 byte"),  # singular (common.fmt_size, revisão fmt-1)
        (1023, "1023 bytes"),
        (1024, "1,0 KB"),
        (1536, "1,5 KB"),
        (40 * 1024**2, "40,0 MB"),
        (int(2.5 * 1024**3), "2,5 GB"),
        (3 * 1024**4, "3,0 TB"),
        (2048 * 1024**4, "2048,0 TB"),
    ],
)
def test_fmt_size(n: int, esperado: str) -> None:
    assert common.fmt_size(n) == esperado


@pytest.mark.parametrize(("n", "esperado"), [(1024**2 - 1, "1,0 MB"), (1024**3 - 1, "1,0 GB")])
def test_fmt_size_fronteira_nao_mostra_1024(n: int, esperado: str) -> None:
    # Regressão: arredondava só na exibição e mostrava '1024,0 KB'.
    assert not common.fmt_size(n).startswith("1024,0")
    assert common.fmt_size(n) == esperado


@pytest.mark.parametrize(
    ("segundos", "esperado"),
    [
        (0, "menos de 2 minutos"),
        (89.9, "menos de 2 minutos"),
        (90, "cerca de 2 minutos"),
        (10 * 60, "cerca de 10 minutos"),
        (59 * 60, "cerca de 59 minutos"),
        (3599, "cerca de 1 hora"),
        (60 * 60, "cerca de 1 hora"),
        (89 * 60, "cerca de 1 hora"),
        (90 * 60, "cerca de 2 horas"),
        (3 * 3600, "cerca de 3 horas"),
        (26 * 3600, "cerca de 26 horas"),
    ],
)
def test_fmt_duration(segundos: float, esperado: str) -> None:
    assert common.fmt_duration(segundos) == esperado


def test_fmt_int_e_short_list() -> None:
    assert common.fmt_int(1234567) == "1.234.567"
    assert common.fmt_int(12) == "12"
    assert common.short_list(["a", "b"]) == "a, b"
    assert common.short_list([str(i) for i in range(8)], 3) == "0, 1, 2 e mais 5"
    assert common.short_list([]) == ""


@gui
def test_progresso_de_trancar_mostra_etapas_e_contagem(qapp: QApplication) -> None:
    pai = QWidget()
    runner = JobRunner()
    dlg = common.ProgressDialog(pai, "Trancando 'X'", runner, mode="lock", note="Não use.")
    b = runner.bridge
    b.stage.emit("Criptografando", 1000, 10)
    assert dlg.stage.text() == "1/4 Guardando os arquivos (0 de 10)"
    b.advance.emit(500, 5)
    assert dlg.stage.text() == "1/4 Guardando os arquivos (5 de 10)"
    assert dlg.bar.value() == 500
    b.stage.emit("Apagando as cópias legíveis", 0, 3)
    assert dlg.stage.text() == "4/4 Apagando as cópias legíveis"
    assert dlg.cancel_button.text() == "Parar depois do arquivo atual"
    dlg.finish()
    b.stage.emit("Restaurando", 0, 0)  # desconectado depois de finish
    assert dlg.stage.text() == "4/4 Apagando as cópias legíveis"
    dlg.deleteLater()
    pai.deleteLater()
    runner.deleteLater()
    _descarta()


# =========================================================================== instância única


def test_chave_instancia_unica_estavel_e_sem_dados_pessoais(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("USERDOMAIN", "DOMINIOSINTETICO")
    for var in ("LOGNAME", "USER", "LNAME", "USERNAME"):
        monkeypatch.setenv(var, "usuario.sintetico")
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "Local Sintético"))
    k1 = single_instance._key()
    assert k1 == single_instance._key()  # estável
    assert re.fullmatch(r"OwlVault-[0-9a-f]{24}", k1)  # é hash: só hex depois do prefixo
    for dado in ("DOMINIOSINTETICO", "usuario", "sintetico", "Local", str(tmp_path)):
        assert dado.lower() not in k1.lower()
    # outra conta / outro perfil local ⇒ outra instância
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "Outro"))
    k2 = single_instance._key()
    assert k2 != k1
    for var in ("LOGNAME", "USER", "LNAME", "USERNAME"):
        monkeypatch.setenv(var, "outra.pessoa")
    assert single_instance._key() not in (k1, k2)


def test_chave_instancia_unica_real_tem_formato_de_hash() -> None:
    assert re.fullmatch(r"OwlVault-[0-9a-f]{24}", single_instance._key())


_SEGUNDA_INSTANCIA = """
import sys
from PySide6.QtCore import QCoreApplication
from owl_vault.ui import single_instance as si
app = QCoreApplication([])
si._key = lambda: sys.argv[1]
s = si.SingleInstance()
sys.exit(0 if (not s.primary and s.send(sys.argv[2])) else 3)
"""


@gui
def test_instancia_unica_repassa_pedido(
    qapp: QApplication, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A 2ª execução (outro processo, como o atalho) só repassa o pedido à 1ª.

    Precisa ser outro processo: o canal do Qt no Windows só conclui a escrita quando a 1ª
    instância lê, e no mesmo processo ela estaria parada esperando.
    """
    nome = "OwlVault-teste-" + secrets.token_hex(12)  # nunca o nome real do usuário
    monkeypatch.setattr(single_instance, "_key", lambda: nome)
    primeira = single_instance.SingleInstance()
    recebidas: list[str] = []
    primeira.message.connect(recebidas.append)
    pedido = f"abrir {ID_OK}"
    try:
        assert primeira.primary
        proc = subprocess.Popen([sys.executable, "-c", _SEGUNDA_INSTANCIA, nome, pedido])  # noqa: S603
        try:
            _espera(lambda: recebidas and proc.poll() is not None, timeout=60)
        finally:
            if proc.poll() is None:
                proc.kill()
            proc.wait()
        assert proc.returncode == 0  # a 2ª não virou principal e o envio foi aceito
        assert recebidas == [pedido]
    finally:
        primeira.deleteLater()
        _descarta()


# =========================================================================== pages: menu ⋯ (T4)

MENU_TRANCADA = [
    ("Esconder do Explorer", "hide"),
    ("Verificar arquivos", "verify"),
    ("Remover proteção…", "remove"),
]
MENU_ESCONDIDA = [
    ("Mostrar no Explorer", "show"),
    ("Verificar arquivos", "verify"),
    ("Remover proteção…", "remove"),
]
MENU_ABERTA = [
    ("Abrir a pasta no Explorer", "explore"),
    ("Trancar e esconder", "lock_hide"),
    ("Remover proteção…", "remove"),
]
PROCURAR = ("Procurar a pasta…", "relocate")
TIRAR = ("Tirar da lista", "forget")
EXPLORER = ("Abrir a pasta no Explorer", "explore")
MENU_NAO_ENCONTRADA = [PROCURAR, TIRAR]
#: estado intermediário (com conteúdo na pasta): ver no Explorer, procurar e tirar da lista
MENU_INTERMEDIARIO = [EXPLORER, PROCURAR, TIRAR]

#: (id, estado, escondida, ação, issue, ação base, menu esperado). Contratos C2/C4: TODA linha
#: tem saída no ⋯ — "Tirar da lista" em qualquer estado; "Procurar a pasta…" quando a pasta
#: sumiu, a unidade não responde, o estado é intermediário ou o problema é desconhecido.
CASOS_MENU: list[tuple[str, str, bool, str, str, str, list[tuple[str, str]]]] = [
    ("trancada", TRANCADA, False, "abrir", "", "abrir", [*MENU_TRANCADA, TIRAR]),
    ("escondida", TRANCADA, True, "abrir", "", "abrir", [*MENU_ESCONDIDA, TIRAR]),
    ("aberta", ABERTA, False, "trancar", "", "trancar", [*MENU_ABERTA, TIRAR]),
    ("itens_extras", TRANCADA, False, "resolver", "itens_extras", "abrir", [("Abrir", "abrir"), *MENU_TRANCADA, TIRAR]),
    ("sem_dados", TRANCADA, False, "resolver", "sem_dados", "abrir", [("Abrir", "abrir"), *MENU_TRANCADA, TIRAR]),
    ("senha_antiga", TRANCADA, True, "resolver", "senha_antiga", "abrir", [("Abrir", "abrir"), *MENU_ESCONDIDA, TIRAR]),
    ("versao_anterior_aberta", ABERTA, False, "resolver", "versao_anterior", "trancar", [("Trancar", "trancar"), *MENU_ABERTA, TIRAR]),
    ("versao_anterior_trancada", TRANCADA, False, "resolver", "versao_anterior", "abrir", [("Abrir", "abrir"), *MENU_TRANCADA, TIRAR]),
    ("nao_encontrada_trancada", TRANCADA, False, "resolver", "nao_encontrada", "", MENU_NAO_ENCONTRADA),
    ("nao_encontrada_aberta", ABERTA, False, "resolver", "nao_encontrada", "", MENU_NAO_ENCONTRADA),
    # unidade que voltou com outra letra: "Procurar a pasta…" acha a mesma pasta (estados-6)
    ("indisponivel", TRANCADA, True, "", "indisponivel", "", [PROCURAR, TIRAR]),
    ("apagando", APAGANDO, False, "resolver", APAGANDO, "", MENU_INTERMEDIARIO),
    ("trancando", TRANCANDO, False, "resolver", TRANCANDO, "", MENU_INTERMEDIARIO),
    ("abrindo", ABRINDO, False, "resolver", ABRINDO, "", [PROCURAR, TIRAR]),
    ("restaurando", RESTAURANDO, False, "resolver", ABRINDO, "", MENU_INTERMEDIARIO),
    ("abertura_incompleta", ABERTURA_INCOMPLETA, False, "resolver", ABERTURA_INCOMPLETA, "", MENU_INTERMEDIARIO),
    # problema que a janela não conhece (C4): nunca fica sem saída
    ("issue_desconhecida", TRANCADA, False, "resolver", "cofre_diferente", "abrir", [("Abrir", "abrir"), *MENU_TRANCADA, PROCURAR, TIRAR]),
    ("estado_desconhecido", "estado_novo", False, "resolver", "estado_novo", "", [PROCURAR, TIRAR]),
]  # fmt: skip

#: chaves que OwlWindow._on_row_action sabe tratar
TRATADORES = {
    "abrir": "_open_folder",
    "trancar": "_lock_folder",
    "resolver": "_resolve",
    "hide": "_hide",
    "show": "_show_folder",
    "verify": "_verify",
    "remove": "_remove",
    "explore": "_explore",
    "lock_hide": "_lock_folder",
    "forget": "_forget",
    "relocate": "_relocate",
}

ROTULOS_ACAO = {"abrir": "Abrir", "trancar": "Trancar", "resolver": "Resolver…"}
#: cor da linha (QLabel#linhaEstado[estado]) por ação/issue
ESTADO_LINHA = {"abrir": "trancada", "trancar": "aberta", "resolver": "atencao", "": "indisponivel"}


def _registro(state: str, *, hidden: bool = False, name: str = NOME) -> FolderRecord:
    """Registro sintético (o caminho é só texto: nada no disco é tocado)."""
    return FolderRecord(
        id=secrets.token_hex(16),
        name=name,
        path="\\\\?\\C:\\Sintetico\\Pastas\\" + name,
        volume="volume{00000000-0000-0000-0000-000000000000}",
        file_id="00" * 16,
        state=state,
        hidden=hidden,
    )


def _view(caso: tuple[str, str, bool, str, str, str, list[tuple[str, str]]]) -> FolderView:
    _id, state, hidden, action, issue, base, _menu = caso
    rec = _registro(state, hidden=hidden)
    label = {"abrir": "Escondida" if hidden else "Trancada", "trancar": "Aberta — visível"}.get(
        action, "Precisa de atenção"
    )
    if issue == "indisponivel":
        label = "Indisponível — conecte a unidade C:"
    attention = "Atenção sintética" if action == "resolver" else ""
    return FolderView(
        rec,
        label,
        action,
        attention,
        available=issue != "indisponivel",
        issue=issue,
        base_action=base,
    )


def _por_nome(widget: QWidget, nome: str) -> list[QLabel]:
    return [lbl for lbl in widget.findChildren(QLabel) if lbl.objectName() == nome]


@pytest.mark.parametrize("caso", CASOS_MENU, ids=[c[0] for c in CASOS_MENU])
def test_row_menu_por_estado(
    caso: tuple[str, str, bool, str, str, str, list[tuple[str, str]]],
) -> None:
    menu = pages.row_menu(_view(caso))
    assert menu == caso[6]
    for _label, key in menu:
        assert key in TRATADORES, key


@gui
@pytest.mark.parametrize("caso", CASOS_MENU, ids=[c[0] for c in CASOS_MENU])
def test_folder_row_botao_e_menu(
    qapp: QApplication, caso: tuple[str, str, bool, str, str, str, list[tuple[str, str]]]
) -> None:
    view = _view(caso)
    chamadas: list[tuple[str, str]] = []
    row = pages.FolderRow(view, lambda fid, act: chamadas.append((fid, act)), pages.row_menu(view))
    assert row.objectName() == "linhaPasta"
    assert [lbl.text() for lbl in _por_nome(row, "linhaNome")] == [NOME]
    assert row.where.objectName() == "linhaLocal"
    assert row.where.toolTip() == "C:\\Sintetico\\Pastas"  # local (pai), sem o prefixo \\?\
    estado = _por_nome(row, "linhaEstado")
    assert [e.text() for e in estado] == [view.label]
    assert estado[0].property("estado") == ESTADO_LINHA[view.action]
    if view.action == "resolver":
        assert [d.text() for d in _por_nome(row, "linhaDetalhe")] == ["Atenção sintética"]
    botoes = row.findChildren(QPushButton)
    if view.action:
        assert [b.text() for b in botoes] == [ROTULOS_ACAO[view.action]]
        # UM botão: primário para Abrir/Trancar, comum para Resolver…
        assert (botoes[0].objectName() == "primario") == (view.action != "resolver")
        assert botoes[0].accessibleName() == f"{ROTULOS_ACAO[view.action]} {NOME}"
        botoes[0].click()
        assert chamadas == [(view.record.id, view.action)]
    else:
        assert botoes == []  # Indisponível: sem botão
    chamadas.clear()
    mais = row.findChildren(QToolButton)
    esperado = caso[6]
    if not esperado:
        assert mais == []
    else:
        assert len(mais) == 1
        assert mais[0].objectName() == "mais"
        assert mais[0].text() == "⋯"
        menu = mais[0].menu()
        assert menu is not None
        acoes = [a for a in menu.actions() if not a.isSeparator()]
        assert [a.text() for a in acoes] == [label for label, _k in esperado]
        for a in acoes:
            a.trigger()
        assert chamadas == [(view.record.id, k) for _l, k in esperado]
    row.deleteLater()
    _descarta()


# =========================================================================== pages: lista (T4)


def _caso(nome: str) -> tuple[str, str, bool, str, str, str, list[tuple[str, str]]]:
    return next(c for c in CASOS_MENU if c[0] == nome)


@gui
def test_home_page_lista_vazia_faixa_e_limpeza(qapp: QApplication) -> None:
    home = pages.HomePage()
    assert any("Nenhuma pasta protegida ainda" in t for t in _textos(home))
    assert home.banner.isHidden()
    assert home.banner.objectName() == "aviso"
    assert home.rodape.primario.text() == "+ Proteger uma pasta…"
    assert home.rodape.primario.isDefault()
    abertas = [_view(_caso("aberta")), _view(_caso("aberta"))]
    trancada = _view(_caso("trancada"))
    home.set_rows([abertas[0], trancada], lambda _f, _a: None)
    assert not home.banner.isHidden()
    assert home.banner_text == "1 pasta está aberta e visível neste computador."
    assert len(home.findChildren(pages.FolderRow)) == 2
    home.set_rows([*abertas, trancada], lambda _f, _a: None)
    _descarta()
    assert home.banner_text == "2 pastas estão abertas e visíveis neste computador."
    assert len(home.findChildren(pages.FolderRow)) == 3
    assert not home.lock_all.isHidden()
    sinal: list[bool] = []
    home.lock_all_clicked.connect(lambda: sinal.append(True))
    trancar_agora = [
        b for b in home.banner.findChildren(QPushButton) if b.text() == "Trancar agora"
    ]
    assert trancar_agora == [home.lock_all]
    trancar_agora[0].click()
    assert sinal == [True]
    protegido: list[bool] = []
    home.protect_clicked.connect(lambda: protegido.append(True))
    home.rodape.primario.click()
    assert protegido == [True]
    home.set_notice(f"'{NOME}' está trancada.")
    assert not home.notice.isHidden()
    home.clear()
    _descarta()
    assert home.banner.isHidden()
    assert home.notice.isHidden()
    assert home.notice.text() == ""  # nem escondido o nome fica num rótulo
    assert home.findChildren(pages.FolderRow) == []
    assert not [t for t in _textos(home) if NOME in t]
    home.deleteLater()
    _descarta()


@gui
def test_home_page_faixa_conta_pastas_com_copias_legiveis(qapp: QApplication) -> None:
    """Abrindo/restaurando/apagando/trancando/abertura incompleta também podem deixar arquivos
    legíveis (T11). Antes, 'restaurando' (abertura cancelada no meio) e 'trancando' ficavam
    fora da faixa (estados-1, fluxos-1): este teste exigia a faixa oculta em 'trancando'."""
    home = pages.HomePage()
    nomes = ("apagando", "abrindo", "restaurando", "trancando", "abertura_incompleta")
    home.set_rows([_view(_caso(n)) for n in nomes], lambda _f, _a: None)
    assert home.banner_text.startswith("5 pastas estão abertas e visíveis")
    assert "Resolver" in home.banner_text
    assert home.lock_all.isHidden()  # nenhuma ABERTA: "Trancar agora" não faria nada
    for nome in ("restaurando", "trancando"):
        home.set_rows([_view(_caso(nome))], lambda _f, _a: None)
        assert home.banner_text.startswith("1 pasta está aberta e visível"), nome
        assert not home.banner.isHidden()
    # aberta, mas a pasta sumiu: conta como visível, sem "Trancar agora" (não trancaria)
    home.set_rows([_view(_caso("nao_encontrada_aberta"))], lambda _f, _a: None)
    assert "Resolver" in home.banner_text
    assert home.lock_all.isHidden()
    home.set_rows([_view(_caso("trancada")), _view(_caso("escondida"))], lambda _f, _a: None)
    assert home.banner.isHidden()
    home.deleteLater()
    _descarta()


def test_visiveis_inclui_todo_estado_com_copias_legiveis() -> None:
    """estados-1/fluxos-1 (contrato C5): só 'trancada' fica fora."""
    assert {
        ABERTA,
        ABERTURA_INCOMPLETA,
        ABRINDO,
        RESTAURANDO,
        APAGANDO,
        TRANCANDO,
    } == pages.VISIVEIS
    assert TRANCADA not in pages.VISIVEIS


@gui
def test_home_page_resumo_e_dica(qapp: QApplication) -> None:
    home = pages.HomePage()
    assert home.counts == {"trancadas": 0, "abertas": 0, "escondidas": 0, "atencao": 0}
    assert "Proteger uma pasta" in home.dica._texto.text()
    views = [
        _view(_caso("trancada")),
        _view(_caso("trancada")),
        _view(_caso("escondida")),
        _view(_caso("aberta")),
        _view(_caso("itens_extras")),
    ]
    home.set_rows(views, lambda _f, _a: None)
    assert home.counts == {"trancadas": 2, "abertas": 1, "escondidas": 1, "atencao": 1}
    textos = _textos(home.resumo)
    for chave in ("Trancadas", "Abertas", "Escondidas", "Precisam de atenção"):
        assert chave in textos
    assert home.resumo.objectName() == "cartaoLateral"
    assert home.dica._titulo.text() == "Precisa de atenção"
    assert not [t for t in _textos(home.resumo) if NOME in t]  # o resumo só tem contagens
    home.deleteLater()
    _descarta()


# =========================================================================== pages: assistente (T1/T2)


@gui
def test_assistente_valida_senha_mestra_e_pin(qapp: QApplication) -> None:
    page = pages.SetupPage()
    recebidos: list[tuple[str, str, bool]] = []
    page.finished.connect(lambda sm, pin, rec: recebidos.append((sm, pin, rec)))
    assert page.trilha.atual == 0
    assert page.rodape.primario.text() == "Continuar para o PIN"
    assert page.rodape.voltar.isHidden()
    assert pages._AVISO_SM in page.aviso.texto()  # o aviso da senha mestra nunca some
    assert "ninguém consegue recuperar os arquivos" in pages._AVISO_SM
    page.sm1.setText("curta")
    page.sm2.setText("curta")
    page._next()
    assert page.stack.currentIndex() == 0
    assert "pelo menos" in page.err1.text()
    page.sm1.setText(SENHA_MESTRA)
    assert page.forca.accessibleDescription().startswith("Força da senha: ")
    page.sm2.setText(SENHA_MESTRA + "x")
    page._next()
    assert page.err1.text() == "As duas senhas não são iguais."
    page.sm2.setText(SENHA_MESTRA)
    page._next()
    assert "Anotei" in page.err1.text()  # caixa obrigatória
    page.noted.setChecked(True)
    page._next()
    assert page.stack.currentIndex() == 1
    assert page.trilha.atual == 1
    assert page.rodape.primario.text() == "Concluir"
    assert not page.rodape.voltar.isHidden()
    assert page.err1.isHidden()
    for ruim, trecho in (
        ("12345", "6 a 12"),
        ("123456", "fácil de adivinhar"),
        ("777777", "fácil de adivinhar"),
        ("311299", "datas"),  # ddmmaa
        ("19991231", "datas"),  # aaaammdd
    ):
        page.pin1.setText(ruim)
        page.pin2.setText(ruim)
        page._finish()
        assert trecho in page.err2.text(), ruim
    page.pin1.setText(PIN)
    page.pin2.setText(PIN_ERRADO)
    page._finish()
    assert page.err2.text() == "Os dois PINs não são iguais."
    assert recebidos == []
    page.rodape.voltar.click()  # Voltar não perde o que foi digitado
    assert page.stack.currentIndex() == 0
    assert page.sm1.text() == SENHA_MESTRA
    page.rodape.primario.click()
    assert page.stack.currentIndex() == 1
    page.pin2.setText(PIN)
    page.rodape.primario.click()
    assert recebidos == [(SENHA_MESTRA, PIN, False)]
    for campo in (page.sm1, page.sm2, page.pin1, page.pin2):
        assert campo.text() == ""  # apagados depois de emitir
    page.deleteLater()
    _descarta()


@gui
def test_assistente_enter_aciona_o_botao_primario(qapp: QApplication) -> None:
    page = pages.SetupPage()
    assert page.rodape.primario.isDefault()
    page.sm1.setText(SENHA_MESTRA)
    page.sm2.setText(SENHA_MESTRA)
    page.noted.setChecked(True)
    QTest.keyClick(page.sm2, Qt.Key.Key_Return)
    assert page.stack.currentIndex() == 1
    page.set_busy(True, "Preparando…")
    assert not page.rodape.primario.isEnabled()
    QTest.keyClick(page.pin2, Qt.Key.Key_Return)  # ocupado: Enter não faz nada
    assert page.err2.isHidden()
    page.set_busy(False)
    page.deleteLater()
    _descarta()


@gui
def test_assistente_recuperar_marca_pedido(qapp: QApplication) -> None:
    page = pages.SetupPage()
    assert not page.recover_link.isHidden()
    page.recover_link.click()
    assert page.wants_recover
    assert "MESMA senha mestra" in page.recover_note.text()
    assert not page.recover_note.isHidden()
    assert page.recover_link.isHidden()
    page.start()  # recomeçar zera o pedido
    assert not page.wants_recover
    assert page.recover_note.isHidden()
    page.start(recuperar=True)  # vindo de "perfil danificado"
    assert page.wants_recover
    assert not page.recover_note.isHidden()
    page.deleteLater()
    _descarta()


# =========================================================================== pages: desbloqueio (T3)


@gui
def test_unlock_page_pin_envio_e_troca(qapp: QApplication) -> None:
    page = pages.UnlockPage()
    enviados: list[tuple[str, bool]] = []
    page.submitted.connect(lambda s, m: enviados.append((s, m)))
    page.configure(master=False)
    assert page.go is page.rodape.primario
    assert page.go.text() == "Entrar"
    assert page.edit.placeholderText() == "PIN"
    assert page.edit.maxLength() == 12
    assert page.edit.echoMode() == QLineEdit.EchoMode.Password
    page._submit()
    assert page.err.text() == "Digite o PIN."
    assert enviados == []
    page.edit.setText(PIN)
    QTest.keyClick(page.edit, Qt.Key.Key_Return)  # Enter no campo = Entrar
    assert enviados == [(PIN, False)]
    assert page.edit.text() == ""
    assert not page.go.isEnabled()
    assert page.go.text() == "Entrando…"
    page.fail("PIN incorreto.")
    assert page.go.isEnabled()
    assert page.err.text() == "PIN incorreto."
    page._toggle()
    assert page.master
    assert page.edit.placeholderText() == "Senha mestra"
    assert page.switch.text() == "Usar o PIN"
    assert page.forgot.isHidden()
    page._toggle()
    page._forgot()
    assert page.master
    assert "Alterar PIN" in page.text.text()
    page.configure(master=False, title="Abrir pasta protegida", button="Abrir")
    assert page.go.text() == "Abrir"
    page.set_busy(True)
    assert page.go.text() == "Abrindo…"
    page.deleteLater()
    _descarta()


@gui
def test_unlock_page_ocupada_desativa_os_links(qapp: QApplication) -> None:
    """Com o desbloqueio rodando, nada na tela pode disparar outro pedido (achado: 2º Enter)."""
    page = pages.UnlockPage()
    page.configure(master=False)
    page.set_busy(True)
    for w in (page.go, page.edit, page.switch, page.forgot, page.new_master, page.once):
        assert not w.isEnabled()
    assert page.rodape.ponto.property("estado") == "trabalhando"
    page.set_busy(False)
    for w in (page.go, page.edit, page.switch, page.forgot, page.new_master, page.once):
        assert w.isEnabled()
    page.deleteLater()
    _descarta()


@gui
def test_unlock_page_pratica_tres_erros_oferece_nova_senha(qapp: QApplication) -> None:
    page = pages.UnlockPage()
    page.configure(master=True, practice=True, title="Digite sua senha mestra")
    assert page.switch.isHidden()
    for _ in range(2):
        page.fail("Senha mestra incorreta.")
        assert page.extra.isHidden()
    page.fail("Senha mestra incorreta.")
    assert not page.extra.isHidden()
    assert "Esqueceu?" in page.err.text()
    page.configure(master=False)  # reconfigurar zera a contagem
    assert page.extra.isHidden()
    assert page.master_failures == 0
    page.deleteLater()
    _descarta()


# =========================================================================== proteger (T5, assistente)


def _check(nome: str = NOME, files: int = 1234, total: int = 40 * 1024**3) -> ProtectCheck:
    return ProtectCheck(
        "\\\\?\\C:\\Sintetico\\Pastas\\" + nome,
        nome,
        files,
        total,
        None,  # type: ignore[arg-type]  # o plano não é usado pela tela
    )


@pytest.fixture
def proteger(qapp: QApplication) -> Iterator[protect_flow.ProtectPage]:
    runner = JobRunner()
    page = protect_flow.ProtectPage(runner)
    yield page
    page.deleteLater()
    runner.deleteLater()
    _descarta()


def _estados(page: protect_flow.ProtectPage) -> dict[str, str]:
    return {k: str(linha.icone.property("estado")) for k, linha in page.linhas.items()}


@gui
def test_proteger_passo_pasta_exige_escolha(proteger: protect_flow.ProtectPage) -> None:
    page = proteger
    page.start(first_time=True)
    assert page.step == 0
    assert page.trilha.atual == 0
    assert [t for t in _textos(page.trilha)] == ["1", "Pasta", "2", "Conferência", "3", "Trancar"]
    assert not page.rodape.primario.isEnabled()
    assert page.rodape.primario.text() == "Continuar para a conferência"
    voltou: list[bool] = []
    page.back_to_list.connect(lambda: voltou.append(True))
    page.rodape.voltar.click()
    assert voltou == [True]
    pedidos: list[str] = []
    page.check_requested.connect(pedidos.append)
    page.set_path("C:\\Sintetico\\Pastas\\" + NOME)
    assert page.campo.texto() == "C:\\Sintetico\\Pastas\\" + NOME
    assert page.rodape.primario.isEnabled()
    page.rodape.primario.click()
    assert pedidos == ["C:\\Sintetico\\Pastas\\" + NOME]


@gui
def test_proteger_conferencia_sem_falhas_e_entendi(proteger: protect_flow.ProtectPage) -> None:
    page = proteger
    page.start(first_time=True)
    page.set_path("C:\\Sintetico\\Pastas\\" + NOME)
    page.checking()
    assert page.step == 1
    assert page.trilha.atual == 1
    assert set(_estados(page).values()) == {""}  # ainda não rodaram
    assert not page.rodape.primario.isEnabled()
    assert page.rodape.voltar.text() == "Cancelar"
    page.show_check(_check())
    assert set(_estados(page).values()) == {"ok"}
    assert page.linhas["arquivos"].detalhe.text().startswith("1.234 arquivo(s) · 40,0 GB")
    assert "pode levar" in page.linhas["arquivos"].detalhe.text()
    assert [linha.titulo.text() for linha in page.linhas.values()] == [
        "Pasta permitida",
        "Arquivos",
        "Espaço em disco",
        "Arquivos em uso",
        "Permissão para apagar",
    ]
    # todos os pontos da confirmação T5d continuam na tela
    aviso = page.aviso2.texto()
    for trecho in (
        "não vão para a Lixeira",
        "atalho dentro da pasta",
        "BitLocker",
        "data de criação, atributos e permissões não voltam",
        "dobro do espaço",
    ):
        assert trecho in aviso
    assert page.t2.text() == f"Proteger '{NOME}'?"
    # 1ª proteção: "Entendi" é obrigatória
    assert not page.entendi.isHidden()
    assert not page.rodape.primario.isEnabled()
    assert "Entendi" in page.rodape.texto.text()
    pedidos: list[bool] = []
    page.lock_requested.connect(lambda: pedidos.append(True))
    page._primario()
    assert pedidos == []
    page.entendi.setChecked(True)
    assert page.rodape.primario.isEnabled()
    assert page.rodape.primario.text() == "Trancar agora"
    page.rodape.primario.click()
    assert pedidos == [True]
    # nas próximas proteções a caixa não aparece
    page.start(first_time=False)
    page.set_path("C:\\x")
    page.show_check(_check())
    assert page.entendi.isHidden()
    assert page.rodape.primario.isEnabled()


#: com bloqueio, só "passou" o que certamente rodou inteiro (nunca um ✓ sem conferência)
CASOS_BLOQUEIO = [
    (
        "em_uso",
        ["Relatório.docx: arquivo em uso por outro programa. Feche-o e tente novamente."],
        {"permitida": "ok", "arquivos": "", "espaco": "ok", "em_uso": "falhou", "permissao": ""},
    ),
    (
        "espaco",
        ["Espaço insuficiente para o cofre: necessário ~900 MiB, livre 10 MiB."],
        {"permitida": "ok", "arquivos": "", "espaco": "falhou", "em_uso": "", "permissao": ""},
    ),
    (
        "permissao",
        [
            "O Windows não deixou o Owl Vault apagar arquivos aqui ('a.txt'). Em Segurança do "
            "Windows > Proteção contra ransomware > Permitir um aplicativo, adicione o Owl Vault."
        ],
        {"permitida": "ok", "arquivos": "", "espaco": "ok", "em_uso": "", "permissao": "falhou"},
    ),
    (
        "pasta",
        ["Não dá para proteger a pasta Documentos inteira. Crie uma pasta dentro dela."],
        {"permitida": "falhou", "arquivos": "", "espaco": "", "em_uso": "", "permissao": ""},
    ),
    (
        "varios",
        [
            "Esta unidade usa exFAT. O Owl Vault só tranca pastas em unidades NTFS.",
            "a.txt: arquivo em uso por outro programa.",
            "b.txt: arquivo em uso por outro programa.",
        ],
        {"permitida": "falhou", "arquivos": "", "espaco": "", "em_uso": "falhou", "permissao": ""},
    ),
]


@gui
@pytest.mark.parametrize(
    ("_id", "bloqueios", "esperado"), CASOS_BLOQUEIO, ids=[c[0] for c in CASOS_BLOQUEIO]
)
def test_proteger_conferencia_classifica_cada_bloqueio(
    proteger: protect_flow.ProtectPage, _id: str, bloqueios: list[str], esperado: dict[str, str]
) -> None:
    page = proteger
    page.start(first_time=False)
    page.set_path("C:\\Sintetico\\Pastas\\" + NOME)
    page.checking()
    page.show_blockers(bloqueios)
    assert _estados(page) == esperado
    for key, motivos in page.failures.items():
        detalhe = page.linhas[key].detalhe.text()
        assert detalhe.startswith(motivos[0])  # o motivo, não um texto genérico
        if len(motivos) > 1:
            assert detalhe.endswith(f"(e mais {len(motivos) - 1})")
    assert not page.rodape.primario.isEnabled()  # com falha, não tranca
    assert not page.again.isHidden()  # "Conferir de novo"
    assert page.rodape.ponto.property("estado") == "erro"
    assert page.show_details.isHidden() == (len(bloqueios) == 1)
    pedidos: list[str] = []
    page.check_requested.connect(pedidos.append)
    page.again.click()
    assert pedidos == ["C:\\Sintetico\\Pastas\\" + NOME]


def test_proteger_classificar_bloqueios() -> None:
    c = protect_flow.classificar
    assert c("x.txt: arquivo em uso por outro programa.") == "em_uso"
    assert c("Falta espaço no disco D:. Libere cerca de 12 GB.") == "espaco"
    assert c("Cofre: não foi possível consultar o espaço livre (x).") == "espaco"
    assert c("O Windows não deixou o Owl Vault apagar arquivos aqui.") == "permissao"
    assert c("Em Segurança do Windows > Proteção contra ransomware") == "permissao"
    assert c("Esta pasta está no OneDrive.") == "permitida"
    assert c("Origem: a pasta não existe.") == "permitida"


@gui
def test_proteger_trancando_mostra_etapas_sem_nomes_de_arquivos(
    proteger: protect_flow.ProtectPage, monkeypatch: pytest.MonkeyPatch
) -> None:
    page = proteger
    cancelados: list[bool] = []
    monkeypatch.setattr(page._runner, "cancel", lambda: cancelados.append(True))
    page.start(first_time=False)
    page.set_path("C:\\Sintetico\\Pastas\\" + NOME)
    page.show_check(_check())
    page.locking()
    assert page.step == 2
    assert page.trilha.atual == 2
    assert page.t3.text() == f"Trancando '{NOME}'"
    assert page.aviso3.texto() == "Não use esta pasta até terminar."
    assert page.log.objectName() == "log"
    assert page.rodape.primario.isHidden()
    assert page.rodape.voltar.text() == "Cancelar"
    b = page._runner.bridge
    b.stage.emit("Criptografando", 1000, 10)
    assert page.etapa.text() == "1/4 Guardando os arquivos (0 de 10)"
    b.advance.emit(500, 5)
    assert page.etapa.text() == "1/4 Guardando os arquivos (5 de 10)"
    assert page.bar3.value() == 500
    b.info.emit("Segredo do Projeto.docx")  # nomes de arquivos nunca vão para o registro
    b.warning.emit("Segredo do Projeto.docx: aviso")
    b.stage.emit("Verificando o cofre (derivando chave — não cancelável)", 0, 0)
    b.stage.emit("Teste de restauração", 0, 10)
    b.stage.emit("Apagando as cópias legíveis", 0, 10)
    assert page.etapa.text() == "4/4 Apagando as cópias legíveis"
    assert page.rodape.voltar.text() == "Parar depois do arquivo atual"
    registro = page.log.toPlainText()
    for etapa in ("1/4", "2/4", "3/4", "4/4"):
        assert etapa in registro
    assert "Segredo" not in registro
    page.rodape.voltar.click()
    assert cancelados == [True]
    assert not page.rodape.voltar.isEnabled()
    b.stage.emit("Apagando as cópias legíveis", 0, 10)  # nova etapa não reativa o botão
    assert not page.rodape.voltar.isEnabled()
    rec = _registro(TRANCADA)
    page.finish(LockOutcome(rec, True, removable=True))
    assert page.t3.text() == f"'{NOME}' está trancada."
    assert "Remover hardware com segurança" in page.s3.text()
    assert page.rodape.primario.text() == "Voltar para a lista"
    assert not page.another.isHidden()
    assert page.rodape.voltar.isHidden()
    texto = page.etapa.text()
    b.stage.emit("Restaurando", 0, 0)  # desconectado depois do fim
    assert page.etapa.text() == texto
    voltou: list[bool] = []
    page.back_to_list.connect(lambda: voltou.append(True))
    page.rodape.primario.click()
    assert voltou == [True]
    page.another.click()  # "Proteger outra pasta": volta ao passo 1, limpo
    assert page.step == 0
    assert page.campo.texto() == ""


@gui
def test_proteger_falha_e_limpeza(proteger: protect_flow.ProtectPage) -> None:
    page = proteger
    page.start(first_time=False)
    page.set_path("C:\\Sintetico\\Pastas\\" + NOME)
    page.show_check(_check())
    page.locking()
    page.fail(CancelledError("cancelado"))
    assert page.t3.text() == "O trancamento foi cancelado"
    assert "Nada foi apagado" in page.s3.text()
    page.locking()  # cancelado na etapa 4: os arquivos já estão guardados, não "nada mudou"
    page._runner.bridge.stage.emit("Apagando as cópias legíveis", 0, 3)
    page.fail(CancelledError("cancelado"))
    assert "Nada foi apagado" not in page.s3.text()
    assert "Resolver" in page.s3.text()
    page.locking()
    page.fail(PreflightError("Não é possível proteger esta pasta.", ["a.txt: em uso"]))
    assert page.t3.text() == f"Não foi possível trancar '{NOME}'"
    assert page.s3.text().startswith("a.txt: em uso")
    assert page.rodape.ponto.property("estado") == "erro"
    page.clear()  # ao bloquear: nenhum nome nem caminho fica nos rótulos
    _descarta()
    assert not [t for t in _textos(page) if NOME in t]
    assert NOME not in page.rodape.texto.text()
    assert page.campo.texto() == ""
    assert page.log.toPlainText() == ""


# =========================================================================== OwlWindow


@dataclass
class Tela:
    win: OwlWindow
    dialogos: list[tuple[str, str]]
    perfil: Path
    respostas: dict[str, Any]
    perguntas: list[dict[str, Any]]

    @property
    def store(self) -> ProfileStore:
        return self.win.store

    def pergunta(self, titulo: str) -> dict[str, Any]:
        achadas = [p for p in self.perguntas if p["title"] == titulo]
        assert achadas, (titulo, [p["title"] for p in self.perguntas])
        return achadas[-1]


@pytest.fixture
def abrir_tela(
    qapp: QApplication, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Iterator[Callable[..., Tela]]:
    """Fábrica de janelas com perfil em tmp_path e diálogos substituídos por gravadores.

    ``respostas`` (prefixo do título → resposta ou função) escolhe o botão de ``ask``; sem
    resposta, é "cancel".
    """
    dialogos: list[tuple[str, str]] = []
    perguntas: list[dict[str, Any]] = []
    respostas: dict[str, Any] = {}

    def ask(_p: object, title: str, text: str = "", buttons: Any = (), **kw: object) -> str:
        dialogos.append(("ask", title))
        perguntas.append({"title": title, "text": text, "buttons": [k for _l, k in buttons], **kw})
        for prefixo, resposta in respostas.items():
            if title.startswith(prefixo):
                return str(resposta() if callable(resposta) else resposta)
        return "cancel"

    def inform(_p: object, title: str, text: str = "", *_a: object, **_k: object) -> None:
        dialogos.append(("inform", title))
        perguntas.append({"title": title, "text": text, "buttons": ["ok"]})

    def choose_folder(_p: object, title: str, *_a: object, **_k: object) -> None:
        dialogos.append(("choose_folder", title))

    def limits(_p: object) -> None:
        dialogos.append(("limits", ""))

    monkeypatch.setattr(owl_window, "ask", ask)
    monkeypatch.setattr(owl_window, "inform", inform)
    monkeypatch.setattr(owl_window, "choose_folder", choose_folder)
    monkeypatch.setattr(owl_window, "limits_dialog", limits)
    monkeypatch.setattr(owl_window, "saved_theme", lambda: "dark")  # não lê o registro real
    monkeypatch.setattr(owl_window, "open_in_explorer", lambda p: dialogos.append(("explorer", p)))
    real_manager = owl_window.LockerManager

    def gerente(session: Any, **kw: Any) -> Any:
        kw["protected"] = ProtectedPaths.none()
        kw["known_folders"] = {}
        return real_manager(session, **kw)

    monkeypatch.setattr(owl_window, "LockerManager", gerente)
    perfil = tmp_path / "perfil"
    janelas: list[OwlWindow] = []

    def abrir(open_request: str | None = None) -> Tela:
        win = OwlWindow(
            LAUNCHER, open_request=open_request, policy=TESTING_POLICY, profile_dir=perfil
        )
        for nome in ("showNormal", "raise_", "activateWindow"):  # nada de janela real
            monkeypatch.setattr(win, nome, lambda: None)
        janelas.append(win)
        return Tela(win, dialogos, perfil, respostas, perguntas)

    yield abrir
    for win in janelas:
        _espera(lambda w=win: not w.runner.busy)
        _descarta()
        win._quitting = True
        win.close()
        win.deleteLater()
    _descarta()
    assert [d for d in dialogos if d[0] == "choose_folder"] == []  # nunca abre QFileDialog


def _criar_perfil(tela: Tela) -> profile_mod.ProfileSession:
    return tela.store.create(SENHA_MESTRA, PIN, params=TESTING_PARAMS)


def _pasta_aberta(base: Path, nome: str = NOME, state: str = ABERTA) -> FolderRecord:
    """Pasta real (sintética) em tmp_path registrada como 'aberta' (ou ``state``)."""
    pasta = base / "pastas" / nome
    pasta.mkdir(parents=True)
    (pasta / "nota.txt").write_bytes(b"dados sinteticos")
    res = winfs.resolve(str(pasta))
    assert res.identity is not None
    return FolderRecord(
        id=secrets.token_hex(16),
        name=nome,
        path=winfs.to_extended(str(pasta)),
        volume=res.volume,
        file_id=res.identity.file_id.hex(),
        state=state,
    )


def _envia(tela: Tela, segredo: str) -> None:
    page = tela.win.unlock_page
    page.edit.setText(segredo)
    page._submit()
    assert page.edit.text() == ""  # o campo é apagado na hora
    _espera(lambda: not tela.win.runner.busy)


def _vencer_pratica(store: ProfileStore) -> None:
    obj, _ = store.read_raw()
    obj["practice_due"] = (dt.date.today() - dt.timedelta(days=1)).isoformat()
    store.write_both(obj)


def _menu_principal(win: OwlWindow) -> QMenu:
    menus = [
        m for m in win.findChildren(QMenu) if any(a.text() == "Bloquear agora" for a in m.actions())
    ]
    assert len(menus) == 1
    return menus[0]


@gui
def test_janela_sem_perfil_abre_no_assistente(abrir_tela: Callable[..., Tela]) -> None:
    tela = abrir_tela()
    win = tela.win
    assert win.store.dir == tela.perfil
    assert win.pages.currentWidget() is win.setup_page
    assert win.rodapes.currentWidget() is win.setup_page.rodape
    assert win.setup_page.stack.currentIndex() == 0
    assert not tela.perfil.exists()  # abrir a janela não grava nada
    assert win.session is None
    assert win.mgr is None


@gui
def test_estrutura_da_janela_no_visual_cofre(abrir_tela: Callable[..., Tela]) -> None:
    win = abrir_tela().win
    central = win.centralWidget()
    lay = central.layout()
    assert lay is not None
    m = lay.contentsMargins()
    assert (m.left(), m.top(), m.right(), m.bottom()) == (0, 0, 0, 0)
    conteudo = lay.itemAt(0).widget()
    cl = conteudo.layout()
    m = cl.contentsMargins()
    assert (m.left(), m.top(), m.right(), m.bottom()) == (32, 20, 32, 24)
    assert lay.itemAt(1).widget() is win.rodapes  # rodapé na largura toda, embaixo
    assert win.menu_button.objectName() == "mais"
    assert win.menu_button.text() == "☰"
    assert win.menu_button.menu() is _menu_principal(win)
    assert [w for w in win.findChildren(QLabel) if w.objectName() == "marcaRoxo"]
    for page in win._all_pages:
        assert page.rodape.objectName() == "rodape"
        assert page.rodape.primario.objectName() == "primario"
        assert page.rodape.primario.isDefault()
    assert version_label() in win.windowTitle()


def _cadeia_de_foco(win: QWidget) -> list[QWidget]:
    out: list[QWidget] = []
    w = win.nextInFocusChain()
    while w is not win and len(out) < 10_000:
        out.append(w)
        w = w.nextInFocusChain()
    return out


@gui
def test_tab_segue_a_ordem_de_leitura(abrir_tela: Callable[..., Tela]) -> None:
    """Tab: ☰ → campos do cartão (na ordem em que aparecem) → rodapé (Voltar, primário)."""
    tela = abrir_tela()
    win = tela.win
    cadeia = _cadeia_de_foco(win)
    s = win.setup_page
    ordem = [win.menu_button, s.sm1, s.sm1.mostrar, s.sm2, s.noted, s.rodape.voltar]
    ordem += [s.rodape.primario, s.recover_link]
    assert [cadeia.index(w) for w in ordem] == sorted(cadeia.index(w) for w in ordem)
    u = win.unlock_page
    ordem = [u.edit, u.switch, u.forgot, u.go]
    assert [cadeia.index(w) for w in ordem] == sorted(cadeia.index(w) for w in ordem)
    p = win.protect_page
    ordem = [p.campo.campo, p.campo.botao, p.rodape.voltar, p.rodape.primario]
    assert [cadeia.index(w) for w in ordem] == sorted(cadeia.index(w) for w in ordem)
    # as áreas de rolagem não roubam um Tab
    assert not [
        w
        for w in cadeia
        if isinstance(w, QScrollArea) and w.focusPolicy() != Qt.FocusPolicy.NoFocus
    ]


@gui
def test_apos_criar_perfil_desbloqueio_pede_pin(abrir_tela: Callable[..., Tela]) -> None:
    tela = abrir_tela()
    win = tela.win
    _criar_perfil(tela).close()
    assert (tela.perfil / "perfil.owlp").is_file()
    win._show_unlock()
    page = win.unlock_page
    assert win.pages.currentWidget() is page
    assert win.rodapes.currentWidget() is page.rodape
    assert not page.master
    assert page.title.text() == "Digite seu PIN"
    assert page.edit.placeholderText() == "PIN"
    assert page.edit.maxLength() == 12
    assert page.edit.echoMode() == QLineEdit.EchoMode.Password
    assert not page.switch.isHidden()
    assert page.switch.text() == "Usar a senha mestra"
    assert not page.forgot.isHidden()
    assert page.extra.isHidden()
    assert page.err.isHidden()
    # uma janela nova, com o perfil já criado, começa direto no PIN
    outra = abrir_tela().win
    assert outra.pages.currentWidget() is outra.unlock_page
    assert not outra.unlock_page.master


@gui
def test_desbloqueado_mostra_lista_vazia(abrir_tela: Callable[..., Tela]) -> None:
    tela = abrir_tela()
    win = tela.win
    sessao = _criar_perfil(tela)
    win._unlocked(sessao)
    assert win.pages.currentWidget() is win.home
    assert win.rodapes.currentWidget() is win.home.rodape
    assert win.session is sessao
    assert win.mgr is not None
    assert win.mgr.folders == []
    assert win.home.findChildren(pages.FolderRow) == []
    assert any("Nenhuma pasta protegida ainda" in t for t in _textos(win.home))
    assert win.home.banner.isHidden()
    assert win.home.notice.isHidden()
    assert version_label() in win.home.rodape.texto.text()  # estado padrão com a versão
    _descarta()  # roda _after_unlock (nada pendente)
    assert tela.dialogos == []


@gui
def test_lista_mostra_pasta_aberta_e_trancada(
    abrir_tela: Callable[..., Tela], tmp_path: Path
) -> None:
    tela = abrir_tela()
    win = tela.win
    sessao = _criar_perfil(tela)
    win._unlocked(sessao)
    aberta = _pasta_aberta(tmp_path)
    trancada = _pasta_aberta(tmp_path, "Fotos Trancadas")
    (Path(winfs.strip_extended(trancada.path)) / "nota.txt").unlink()
    (Path(winfs.strip_extended(trancada.path)) / ".owlvault").mkdir()
    trancada.state = TRANCADA
    sessao.index.folders += [aberta, trancada]
    win._refresh()
    linhas = win.home.findChildren(pages.FolderRow)
    assert len(linhas) == 2
    textos = _textos(win.home)
    assert NOME in textos
    assert "Fotos Trancadas" in textos
    assert "Aberta — visível neste computador" in textos
    assert "Trancada" in textos
    assert win.home.banner_text == "1 pasta está aberta e visível neste computador."
    assert win.home.counts == {"trancadas": 1, "abertas": 1, "escondidas": 0, "atencao": 0}
    botoes = sorted(
        b.text() for b in win.home.findChildren(QPushButton) if b.text() in ("Abrir", "Trancar")
    )
    assert botoes == ["Abrir", "Trancar"]


@gui
def test_bloquear_agora_limpa_lista_e_volta_ao_pin(
    abrir_tela: Callable[..., Tela], tmp_path: Path
) -> None:
    tela = abrir_tela()
    win = tela.win
    sessao = _criar_perfil(tela)
    win._unlocked(sessao)
    sessao.index.folders.append(_pasta_aberta(tmp_path))
    win._refresh()
    win.home.set_notice(f"'{NOME}' está aberta. Tranque de novo quando terminar.")
    assert [t for t in _textos(win, so_visiveis=True) if NOME in t]
    # ☰ > Bloquear agora
    bloquear = next(a for a in _menu_principal(win).actions() if a.text() == "Bloquear agora")
    bloquear.trigger()
    _descarta()
    assert win.pages.currentWidget() is win.unlock_page
    assert not win.unlock_page.master  # volta ao PIN
    assert win.session is None
    assert win.mgr is None
    with pytest.raises(OwlVaultError):
        _ = sessao.index  # chaves descartadas
    assert win.home.findChildren(pages.FolderRow) == []
    assert win.home.banner.isHidden()
    assert not [t for t in _textos(win, so_visiveis=True) if NOME in t]
    pai = str(tmp_path / "pastas")
    assert not [w for w in win.findChildren(QWidget) if pai in w.toolTip()]


@gui
def test_bloquear_agora_nao_deixa_nome_em_rotulo_oculto(
    abrir_tela: Callable[..., Tela], tmp_path: Path
) -> None:
    tela = abrir_tela()
    win = tela.win
    sessao = _criar_perfil(tela)
    win._unlocked(sessao)
    sessao.index.folders.append(_pasta_aberta(tmp_path))
    win._refresh()
    win.home.set_notice(f"'{NOME}' está trancada.")  # como em _lock_done
    win._protect()  # assistente com a pasta escolhida também não pode guardar o nome
    win.protect_page.set_path(winfs.strip_extended(sessao.index.folders[0].path))
    win.lock_now()
    _descarta()
    assert not [t for t in _textos(win) if NOME in t]
    assert not [w for w in win.findChildren(QLineEdit) if NOME in w.text()]


@gui
def test_menu_principal_tem_itens_da_especificacao(abrir_tela: Callable[..., Tela]) -> None:
    tela = abrir_tela()
    win = tela.win
    menu = _menu_principal(win)
    textos = [a.text() for a in menu.actions() if not a.isSeparator()]
    for item in (
        "Recuperar uma pasta protegida…",
        "Cópia criptografada de uma pasta…",
        "Alterar PIN…",
        "Bloquear agora",
        "Limites da proteção",
        "Tema",
    ):
        assert item in textos
    so_destravado = (
        "Recuperar uma pasta protegida…",
        "Cópia criptografada de uma pasta…",
        "Alterar PIN…",
        "Bloquear agora",
    )
    visiveis = {a.text(): a.isVisible() for a in menu.actions()}
    for item in so_destravado:  # travado: só Limites, Tema e Sobre
        assert not visiveis[item], item
    assert visiveis["Limites da proteção"]
    win._unlocked(_criar_perfil(tela))
    visiveis = {a.text(): a.isVisible() for a in menu.actions()}
    for item in so_destravado:
        assert visiveis[item], item


@gui
def test_bloquear_durante_operacao_espera_terminar(abrir_tela: Callable[..., Tela]) -> None:
    tela = abrir_tela()
    win = tela.win
    win._unlocked(_criar_perfil(tela))
    liberar = threading.Event()
    fim: list[object] = []
    assert win._run(lambda _p, _c: liberar.wait(10), fim.append)
    assert win.runner.busy
    win.lock_now()
    assert win._lock_after_job
    assert win.session is not None  # não derruba a sessão no meio do trabalho
    liberar.set()
    _espera(lambda: win.session is None)
    assert fim == [True]
    assert win.pages.currentWidget() is win.unlock_page


@gui
def test_run_recusa_com_trabalho_em_andamento(abrir_tela: Callable[..., Tela]) -> None:
    """Achado: o 2º _run sobrescrevia _job e a 1ª tela de progresso nunca fechava."""
    tela = abrir_tela()
    win = tela.win
    win._unlocked(_criar_perfil(tela))
    liberar = threading.Event()
    primeiro: list[object] = []
    segundo: list[object] = []
    depois: list[bool] = []
    assert win._run(
        lambda _p, _c: liberar.wait(10) and "r1",
        primeiro.append,
        title="Primeira",
        after=lambda: depois.append(True),
    )
    job = win._job
    assert not win._run(lambda _p, _c: "r2", segundo.append, title="Segunda")
    assert win._job is job  # o trabalho em curso não foi tocado
    assert win.home.rodape.ponto.property("estado") == "erro"
    liberar.set()
    _espera(lambda: not win.runner.busy and win._job is None)
    _descarta()
    assert primeiro == ["r1"]
    assert segundo == []
    assert depois == [True]
    assert job is not None and job.dialog is not None
    # a tela de progresso fechou e foi destruída (fluxos-9: o título dela tem o nome da pasta)
    assert not shiboken6.isValid(job.dialog)


@gui
def test_inatividade_bloqueia(abrir_tela: Callable[..., Tela]) -> None:
    tela = abrir_tela()
    win = tela.win
    win._unlocked(_criar_perfil(tela))
    win._idle_check()  # uso recente: continua aberto
    assert win.session is not None
    win._watcher.last = time.monotonic() - IDLE_LOCK_SECONDS - 1
    win._idle_check()
    assert win.session is None
    assert win.pages.currentWidget() is win.unlock_page


@gui
def test_fim_de_operacao_longa_conta_como_uso(abrir_tela: Callable[..., Tela]) -> None:
    """Achado: o resultado de uma verificação de 10 min sumia no travamento logo em seguida."""
    tela = abrir_tela()
    win = tela.win
    win._unlocked(_criar_perfil(tela))
    ainda_aberto: list[bool] = []

    def resultado(_r: object) -> None:  # como um inform() aberto com o resultado
        win._idle_check()
        ainda_aberto.append(win.session is not None)

    win._watcher.last = time.monotonic() - IDLE_LOCK_SECONDS - 1  # ninguém mexeu no mouse
    assert win._run(lambda _p, _c: None, resultado)
    _espera(lambda: bool(ainda_aberto))
    assert ainda_aberto == [True]
    win._idle_check()
    assert win.session is not None


@gui
def test_pratica_vencida_pede_senha_mestra(abrir_tela: Callable[..., Tela]) -> None:
    tela = abrir_tela()
    win = tela.win
    _criar_perfil(tela).close()
    _vencer_pratica(tela.store)
    win._show_unlock()
    page = win.unlock_page
    assert page.master
    assert page.practice
    assert page.title.text() == "Digite sua senha mestra"
    assert "não esquecê-la" in page.text.text()
    assert page.edit.placeholderText() == "Senha mestra"
    assert page.switch.isHidden()
    assert page.forgot.isHidden()
    # "Usar o PIN desta vez"
    page.use_pin_once.emit()
    assert not win.unlock_page.master
    assert not win.unlock_page.practice


@gui
def test_pratica_vencida_nao_atrapalha_pedido_do_atalho(abrir_tela: Callable[..., Tela]) -> None:
    tela = abrir_tela()
    _criar_perfil(tela).close()
    _vencer_pratica(tela.store)
    win = abrir_tela(open_request=ID_OK).win
    assert win.pending_open == ID_OK
    assert win.pages.currentWidget() is win.unlock_page
    assert not win.unlock_page.master
    assert win.unlock_page.title.text() == "Abrir pasta protegida"
    assert win.unlock_page.go.text() == "Abrir"


@gui
def test_pratica_com_senha_mestra_em_thread_adia_a_proxima(abrir_tela: Callable[..., Tela]) -> None:
    tela = abrir_tela()
    win = tela.win
    _criar_perfil(tela).close()
    _vencer_pratica(tela.store)
    win._show_unlock()
    assert win.unlock_page.master
    _envia(tela, "senha errada de proposito")
    assert win.unlock_page.err.text() == "Senha mestra incorreta."
    assert win.pages.currentWidget() is win.unlock_page
    _envia(tela, SENHA_MESTRA)
    assert win.pages.currentWidget() is win.home
    assert not tela.store.practice_due()
    win.lock_now()
    assert not win.unlock_page.master  # a prática foi feita: volta ao PIN


@gui
def test_pin_desativado_pede_senha_mestra_sem_troca(abrir_tela: Callable[..., Tela]) -> None:
    tela = abrir_tela()
    win = tela.win
    _criar_perfil(tela).close()
    obj, _ = tela.store.read_raw()
    obj["pin"] = None
    tela.store.write_both(obj)
    win._show_unlock()
    page = win.unlock_page
    assert page.master
    assert page.text.text() == "O PIN está desativado. Use a senha mestra."
    assert page.switch.isHidden()
    assert page.forgot.isHidden()


@gui
def test_perfil_danificado_tela_propria_e_recuperar_guarda_os_arquivos(
    abrir_tela: Callable[..., Tela],
) -> None:
    """Perfil ilegível: nada de "PIN desativado"; [Recuperar…] guarda os arquivos ao lado."""
    tela = abrir_tela()
    tela.perfil.mkdir()
    lixo = {"perfil.owlp": b"lixo sintetico, nao e json", "perfil.owlp.bak": b"\x00\x01lixo"}
    for nome, dados in lixo.items():
        (tela.perfil / nome).write_bytes(dados)
    win = abrir_tela().win
    page = win.problem_page
    assert win.pages.currentWidget() is page
    assert win.rodapes.currentWidget() is page.rodape
    assert page.title.text() == "O perfil deste computador está danificado"
    assert not [t for t in _textos(win, so_visiveis=True) if "PIN está desativado" in t]
    assert page.rodape.primario.text() == "Recuperar minhas pastas com a senha mestra"
    assert "Nada é apagado" in page.aviso.texto()
    page.rodape.primario.click()
    assert win.pages.currentWidget() is win.setup_page
    assert win.setup_page.wants_recover  # depois do PIN, entra em "Recuperar"
    assert not win.store.exists()
    guardados = sorted(tela.perfil.iterdir())
    assert len(guardados) == 2
    for p in guardados:
        original = p.name.split(".danificado-")[0]
        assert original in lixo, p.name
        assert p.read_bytes() == lixo[original]  # renomeado, nunca apagado


@gui
def test_perfil_inacessivel_oferece_tentar_de_novo(
    abrir_tela: Callable[..., Tela], monkeypatch: pytest.MonkeyPatch
) -> None:
    tela = abrir_tela()
    _criar_perfil(tela).close()
    win = tela.win

    def preso() -> bool:
        raise PermissionError(32, "arquivo em uso por outro processo")

    monkeypatch.setattr(win.store, "pin_available", preso)
    win._show_unlock()
    page = win.problem_page
    assert win.pages.currentWidget() is page
    assert not page.corrupt
    assert page.title.text() == "Não foi possível ler o perfil agora"
    assert page.rodape.primario.text() == "Tentar de novo"
    monkeypatch.undo()  # o outro programa soltou o arquivo
    page.rodape.primario.click()
    assert win.pages.currentWidget() is win.unlock_page
    assert (tela.perfil / "perfil.owlp").is_file()  # nada foi renomeado


@gui
def test_pin_correto_em_thread_abre_a_lista(abrir_tela: Callable[..., Tela]) -> None:
    _criar_perfil(abrir_tela()).close()
    tela = abrir_tela()  # janela nova: começa no PIN
    win = tela.win
    assert win.pages.currentWidget() is win.unlock_page
    _envia(tela, PIN)
    assert win.pages.currentWidget() is win.home
    assert win.session is not None
    assert win.mgr is not None


@gui
def test_cinco_pins_errados_desativam_o_pin(abrir_tela: Callable[..., Tela]) -> None:
    tela = abrir_tela()
    win = tela.win
    _criar_perfil(tela).close()
    win._show_unlock()
    for restam in (4, 3, 2, 1):
        _envia(tela, PIN_ERRADO)
        assert win.unlock_page.err.text() == (
            f"PIN incorreto. Restam {restam} tentativa(s); depois disso, só a senha mestra."
        )
        assert not win.unlock_page.master
    _envia(tela, PIN_ERRADO)
    page = win.unlock_page
    assert page.master  # depois de 5 erros, o campo passa a ser a senha mestra
    assert page.err.text() == "PIN incorreto muitas vezes. O PIN foi desativado."
    assert page.switch.isHidden()
    for copia in ("perfil.owlp", "perfil.owlp.bak"):
        store = ProfileStore(tela.perfil, TESTING_POLICY)
        obj = store._read_one(tela.perfil / copia)
        assert obj["pin"] is None, copia
    _envia(tela, SENHA_MESTRA)
    assert win.pages.currentWidget() is win.home


@gui
def test_senha_mestra_devolve_as_tentativas_do_pin(abrir_tela: Callable[..., Tela]) -> None:
    tela = abrir_tela()
    win = tela.win
    _criar_perfil(tela).close()
    win._show_unlock()
    _envia(tela, PIN_ERRADO)
    _envia(tela, PIN_ERRADO)
    assert "Restam 3 tentativa(s)" in win.unlock_page.err.text()
    win.unlock_page._toggle()  # "Usar a senha mestra"
    assert win.unlock_page.master
    _envia(tela, SENHA_MESTRA)
    assert win.pages.currentWidget() is win.home
    win.lock_now()
    assert not win.unlock_page.master
    _envia(tela, PIN_ERRADO)
    assert "Restam 4 tentativa(s)" in win.unlock_page.err.text()


@gui
def test_assistente_completo_cria_perfil_em_thread(
    abrir_tela: Callable[..., Tela], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(profile_mod, "calibrate", lambda *_a, **_k: TESTING_PARAMS)
    tela = abrir_tela()
    win = tela.win
    page = win.setup_page
    page.sm1.setText(SENHA_MESTRA)
    page.sm2.setText(SENHA_MESTRA)
    page.noted.setChecked(True)
    page._next()
    page.pin1.setText(PIN)
    page.pin2.setText(PIN)
    page._finish()
    assert not page.rodape.primario.isEnabled()  # ocupado enquanto cria
    assert page.rodape.ponto.property("estado") == "trabalhando"
    _espera(lambda: not win.runner.busy)
    assert win.pages.currentWidget() is win.home
    assert (tela.perfil / "perfil.owlp").is_file()
    assert win.session is not None
    assert win.session.index.keks[0].params == TESTING_PARAMS
    _descarta()
    assert tela.dialogos == []  # sem "recuperar" pedido: nenhum diálogo


@gui
def test_falhas_de_desbloqueio_mostradas_na_tela(abrir_tela: Callable[..., Tela]) -> None:
    tela = abrir_tela()
    win = tela.win
    _criar_perfil(tela).close()
    win._show_unlock()
    assert win._unlock_failed(PinError(3))
    assert "Restam 3" in win.unlock_page.err.text()
    assert win._unlock_failed(DpapiUnavailableError("O Windows não consegue mais usar o PIN."))
    assert win.unlock_page.master
    assert win.unlock_page.text.text() == "O Windows não consegue mais usar o PIN."
    assert win.unlock_page.switch.isHidden()
    assert win._needs_new_pin
    assert win._unlock_failed(AuthenticationError("x"))
    assert win.unlock_page.err.text() == "Senha mestra incorreta."
    assert win._unlock_failed(ProfileCorruptError("perfil ausente ou ilegível"))
    assert win.pages.currentWidget() is win.problem_page


@gui
def test_pedido_do_atalho_com_app_travado_guarda_e_pede_pin(
    abrir_tela: Callable[..., Tela],
) -> None:
    tela = abrir_tela()
    win = tela.win
    _criar_perfil(tela).close()
    win._show_unlock()
    fid = secrets.token_hex(16)
    win.request_open(fid)
    assert win.pending_open == fid
    assert win.pages.currentWidget() is win.unlock_page
    assert win.unlock_page.title.text() == "Abrir pasta protegida"
    assert win.unlock_page.go.text() == "Abrir"
    assert not win.unlock_page.master


class _SegredoFalso:
    """SecretDialog que não abre nada: devolve ``respostas`` em ordem (None = Cancelar)."""

    criados: list[dict[str, object]]
    respostas: list[str | None]

    def __init__(self, _parent: object, title: str, text: str, button: str, **kw: Any) -> None:
        type(self).criados.append({"title": title, "text": text, "button": button, **kw})
        self.master = bool(kw.get("master"))
        self._valor = type(self).respostas.pop(0) if type(self).respostas else None

    def exec(self) -> QDialog.DialogCode:
        if self._valor is None:
            return QDialog.DialogCode.Rejected
        return QDialog.DialogCode.Accepted

    def take(self) -> str:
        return self._valor or ""


def _segredo_falso(monkeypatch: pytest.MonkeyPatch, respostas: list[str | None]) -> type:
    cls = type("SegredoFalso", (_SegredoFalso,), {"criados": [], "respostas": list(respostas)})
    monkeypatch.setattr(owl_window, "SecretDialog", cls)
    return cls


@gui
def test_pedido_do_atalho_com_app_destravado_pede_pin_de_novo(
    abrir_tela: Callable[..., Tela], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    falso = _segredo_falso(monkeypatch, [None])
    tela = abrir_tela()
    win = tela.win
    sessao = _criar_perfil(tela)
    win._unlocked(sessao)
    rec = _pasta_aberta(tmp_path)
    sessao.index.folders.append(rec)
    win.request_open(rec.id)
    assert len(falso.criados) == 1
    assert falso.criados[0]["title"] == f"Abrir '{NOME}'"
    assert falso.criados[0]["button"] == "Abrir"
    assert falso.criados[0]["master"] is False
    assert not win.runner.busy  # cancelado: nada foi feito
    assert win.session is sessao
    assert ("explorer", rec.path) not in tela.dialogos


def _perfil_com_pasta(tela: Tela, tmp_path: Path) -> FolderRecord:
    sessao = _criar_perfil(tela)
    rec = _pasta_aberta(tmp_path)
    sessao.index.folders.append(rec)
    sessao.save()
    sessao.close()
    return rec


@gui
@pytest.mark.parametrize("resposta", ["cancel", "open"])
def test_pedido_por_mensagem_so_abre_com_confirmacao_e_nome(
    abrir_tela: Callable[..., Tela], tmp_path: Path, resposta: str
) -> None:
    """Achado: 'abrir <id>' vindo de outro processo reaproveitava o PIN da tela de desbloqueio
    como consentimento e decifrava a pasta sem perguntar."""
    tela = abrir_tela()
    rec = _perfil_com_pasta(tela, tmp_path)
    win = tela.win
    win._show_unlock()
    tela.respostas["Abrir '"] = resposta
    win.handle_message(f"abrir {rec.id}")
    assert win.pending_open == rec.id
    assert win.unlock_page.title.text() == "Abrir pasta protegida"
    _envia(tela, PIN)  # o PIN foi digitado "só para ver a lista"
    _descarta()
    pergunta = tela.pergunta(f"Abrir '{NOME}'?")
    assert pergunta["buttons"] == ["open", "cancel"]
    assert win.pending_open is None
    abriu = ("explorer", rec.path) in tela.dialogos
    assert abriu == (resposta == "open")


@gui
def test_pedido_da_linha_de_comando_abre_depois_do_pin(
    abrir_tela: Callable[..., Tela], tmp_path: Path
) -> None:
    """O atalho iniciou o app (--abrir): o PIN digitado na tela "Abrir pasta protegida" basta."""
    rec = _perfil_com_pasta(abrir_tela(), tmp_path)
    tela = abrir_tela(open_request=rec.id)
    _envia(tela, PIN)
    _descarta()
    assert ("explorer", rec.path) in tela.dialogos
    assert not [p for p in tela.perguntas if p["title"].startswith("Abrir '")]


@gui
def test_atalho_de_pasta_fora_da_lista_explica_sem_pedir_pin(
    abrir_tela: Callable[..., Tela], monkeypatch: pytest.MonkeyPatch
) -> None:
    falso = _segredo_falso(monkeypatch, [])
    tela = abrir_tela()
    win = tela.win
    win._unlocked(_criar_perfil(tela))
    recuperar: list[bool] = []
    monkeypatch.setattr(win, "_recover", lambda *a, **k: recuperar.append(True))
    tela.respostas["Esta pasta não está na lista"] = "recover"
    win.request_open(ID_OK)
    assert falso.criados == []  # nada de PIN para dizer que a pasta não está na lista
    pergunta = tela.pergunta("Esta pasta não está na lista")
    assert "reinstalou" in pergunta["text"]
    assert pergunta["buttons"] == ["recover", "close"]
    assert recuperar == [True]


@gui
def test_recuperacao_em_andamento_adia_o_pedido_do_atalho(
    abrir_tela: Callable[..., Tela], monkeypatch: pytest.MonkeyPatch
) -> None:
    tela = abrir_tela()
    win = tela.win
    depois: list[Callable[[], None]] = []
    monkeypatch.setattr(win, "_recover", lambda then=None: depois.append(then))
    win._wants_recover = True
    win.pending_open = ID_OK  # atalho antigo (id de antes de reinstalar)
    win._unlocked(_criar_perfil(tela))
    _descarta()
    assert len(depois) == 1  # a recuperação começou...
    assert win.pending_open == ID_OK  # ...e o pedido do atalho esperou
    assert tela.perguntas == []
    callback = depois[0]
    assert callback is not None
    callback()  # a recuperação terminou
    _descarta()
    assert win.pending_open is None
    assert not [p for p in tela.perguntas if p["title"] == "Esta pasta não está na lista"]
    assert "recuperadas" in win.home.notice.text()


@gui
def test_after_unlock_encadeia_novo_pin_e_pedido_uma_etapa_por_vez(
    abrir_tela: Callable[..., Tela], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Achado: _after_unlock iniciava o 'abrir' com o 'Salvando o PIN…' ainda rodando."""
    novo_pin = "961473"

    class NovoPinFalso:
        def __init__(self, *_a: object, **_k: object) -> None:
            pass

        def exec(self) -> QDialog.DialogCode:
            return QDialog.DialogCode.Accepted

        def take(self) -> str:
            return novo_pin

    monkeypatch.setattr(owl_window, "NewSecretDialog", NovoPinFalso)
    tela = abrir_tela()
    win = tela.win
    sessao = _criar_perfil(tela)
    liberar = threading.Event()
    real_set_pin = sessao.set_pin

    def set_pin_lento(pin: str, **kw: Any) -> None:
        liberar.wait(10)
        real_set_pin(pin, **kw)

    monkeypatch.setattr(sessao, "set_pin", set_pin_lento)
    win._needs_new_pin = True
    win.pending_open = ID_OK
    win._unlocked(sessao)
    _descarta()
    assert win.runner.busy  # salvando o PIN...
    assert win.pending_open == ID_OK  # ...e o pedido do atalho ainda espera
    assert tela.perguntas == []
    liberar.set()
    _espera(lambda: not win.runner.busy)
    _descarta()
    _descarta()
    assert win.pending_open is None
    assert tela.pergunta("Esta pasta não está na lista")
    assert win.home.notice.text() == "PIN criado."
    win.lock_now()
    _envia(tela, novo_pin)
    assert win.session is not None  # o PIN novo foi gravado


@gui
def test_pin_errado_ao_remover_protecao_sincroniza_a_sessao(
    abrir_tela: Callable[..., Tela], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Achado: depois de 5 PINs errados em 'Remover proteção', os saves seguintes gravavam o
    PIN de volta com o contador zerado."""
    falso = _segredo_falso(monkeypatch, [PIN_ERRADO] * 5 + [None])
    tela = abrir_tela()
    win = tela.win
    sessao = _criar_perfil(tela)
    win._unlocked(sessao)
    win._remove(ID_OK)
    _espera(lambda: len(falso.criados) == 6 and not win.runner.busy)
    _descarta()
    assert falso.criados[-1]["master"] is True  # o PIN foi desativado: só a senha mestra
    assert sessao.obj["pin"] is None
    assert sessao.obj["pin_failures"] >= 5
    sessao.save()
    sessao.save()
    store = ProfileStore(tela.perfil, TESTING_POLICY)
    assert not store.pin_available()
    with pytest.raises(PinUnavailableError):
        store.unlock_with_pin(PIN)


@gui
def test_pin_errado_ao_alterar_pin_sincroniza_a_sessao(
    abrir_tela: Callable[..., Tela], monkeypatch: pytest.MonkeyPatch
) -> None:
    class AlterarFalso:
        def __init__(self, *_a: object) -> None:
            pass

        def exec(self) -> QDialog.DialogCode:
            return QDialog.DialogCode.Accepted

        def take(self) -> tuple[str, str, bool]:
            return PIN_ERRADO, "961473", False

    monkeypatch.setattr(owl_window, "ChangePinDialog", AlterarFalso)
    tela = abrir_tela()
    win = tela.win
    sessao = _criar_perfil(tela)
    win._unlocked(sessao)
    win._change_pin()
    _espera(lambda: not win.runner.busy)
    _descarta()
    assert tela.pergunta("PIN incorreto")["text"] == "Restam 4 tentativa(s)."
    assert sessao.obj["pin_failures"] == 1
    sessao.save()  # um save depois do erro não zera o contador do disco
    obj, bak = tela.store.read_raw()
    assert obj["pin_failures"] == 1
    assert bak is not None and bak["pin_failures"] == 1


@gui
def test_mensagem_da_outra_instancia_so_aceita_id_valido(
    abrir_tela: Callable[..., Tela], monkeypatch: pytest.MonkeyPatch
) -> None:
    win = abrir_tela().win
    pedidos: list[str] = []
    monkeypatch.setattr(win, "request_open", pedidos.append)
    win.handle_message(f"abrir {ID_OK}")
    win.handle_message("mostrar")
    win.handle_message(f"abrir {ID_OK.upper()}")
    win.handle_message(f"abrir {ID_OK} extra")
    win.handle_message("abrir ../../x")
    win.handle_message(f"abrir {ID_OK[:-1]}")
    assert pedidos == [ID_OK]


@pytest.mark.parametrize(
    ("pedido", "esperado"),
    [(ID_OK, ID_OK), (ID_OK.upper(), None), ("zz", None), ("", None), (None, None)],
)
@gui
def test_janela_valida_pedido_inicial(
    abrir_tela: Callable[..., Tela], pedido: str | None, esperado: str | None
) -> None:
    assert abrir_tela(open_request=pedido).win.pending_open == esperado


@gui
def test_acoes_das_linhas_chegam_aos_tratadores(
    abrir_tela: Callable[..., Tela], monkeypatch: pytest.MonkeyPatch
) -> None:
    tela = abrir_tela()
    win = tela.win
    win._unlocked(_criar_perfil(tela))
    chamadas: list[tuple[str, str]] = []
    for metodo in set(TRATADORES.values()):
        monkeypatch.setattr(
            win, metodo, lambda fid, *_a, _m=metodo, **_k: chamadas.append((_m, fid))
        )
    chaves = {k for c in CASOS_MENU for _l, k in c[6]} | {c[3] for c in CASOS_MENU if c[3]}
    assert chaves <= set(TRATADORES)
    for chave in sorted(chaves):
        chamadas.clear()
        win._on_row_action(ID_OK, chave)
        assert chamadas == [(TRATADORES[chave], ID_OK)], chave
    chamadas.clear()
    win._on_row_action(ID_OK, "desconhecida")
    assert chamadas == []


@gui
def test_pasta_aberta_renomeada_oferece_procurar_e_explica_tirar_da_lista(
    abrir_tela: Callable[..., Tela], tmp_path: Path
) -> None:
    tela = abrir_tela()
    win = tela.win
    sessao = _criar_perfil(tela)
    win._unlocked(sessao)
    rec = _pasta_aberta(tmp_path)
    # a cópia criptografada da pasta aberta fica na área temporária ao lado dela
    area = tmp_path / "pastas" / f".owlvault-{rec.id}" / "anterior-0123456789abcdef"
    area.mkdir(parents=True)
    rec.vaults.append(VaultRef("cd" * 16, "anterior", winfs.to_extended(str(area))))
    sessao.index.folders.append(rec)
    pasta = Path(winfs.strip_extended(rec.path))
    pasta.rename(pasta.with_name(NOME + " 2024"))  # renomeada no Explorer
    win._refresh()
    assert win.home.counts["atencao"] == 1
    win._resolve(rec.id)
    pergunta = tela.pergunta(f"'{NOME}' não foi encontrada")
    assert pergunta["buttons"] == ["find", "forget"]
    assert "renomeou" in pergunta["text"]
    win._forget(rec.id)
    texto = tela.pergunta(f"Tirar '{NOME}' da lista?")["text"]
    assert f".owlvault-{rec.id}" in texto  # onde fica a cópia criptografada anterior
    assert "Proteger uma pasta" in texto
    # Recuperar não acharia nada aqui: o texto avisa isso (UI_SPEC T8) e nunca manda usá-lo
    # (antes este teste exigia que "Recuperar" nem aparecesse — estados-3/fluxos-7)
    assert "use ☰ > Recuperar" not in texto
    assert "NÃO" in texto and "Recuperar uma pasta protegida" in texto


# --------------------------------------------------------------------------- integração 0.3
# (a janela usa o que o motor das pastas passou a devolver: relatório do Desfazer, versão
# anterior ilegível, conferência do atalho, aviso de 'Tirar da lista' e alertas destrutivos)


def _destravada_com_pasta(
    tela: Tela, tmp_path: Path, state: str = ABERTA
) -> tuple[OwlWindow, FolderRecord]:
    win = tela.win
    sessao = _criar_perfil(tela)
    win._unlocked(sessao)
    rec = _pasta_aberta(tmp_path, state=state)
    sessao.index.folders.append(rec)
    return win, rec


def _com_vista(
    win: OwlWindow, monkeypatch: pytest.MonkeyPatch, rec: FolderRecord, issue: str
) -> None:
    assert win.mgr is not None
    vista = FolderView(rec, "Precisa de atenção", "resolver", "Atenção sintética", issue=issue)
    monkeypatch.setattr(win.mgr, "view", lambda _r: vista)


def _versao_mantida(rec: FolderRecord, local: Path, *, existe: bool) -> None:
    if existe:
        local.mkdir(parents=True)
    rec.vaults.append(VaultRef("ab" * 16, MANTIDO, winfs.to_extended(str(local))))


@gui
def test_desfazer_mostra_conflitos_falhas_ou_so_o_aviso(
    abrir_tela: Callable[..., Tela], tmp_path: Path
) -> None:
    """Pendência do motor: depois de 'Desfazer', mostrar UnlockOutcome.report (conflito em
    arquivo apagado ⇒ versão MANTIDA) em vez de só "'X' continua aberta."."""
    tela = abrir_tela()
    win, rec = _destravada_com_pasta(tela, tmp_path)
    # 1) conflito num caminho que o Owl Vault apagou: a versão guardada foi mantida
    _versao_mantida(rec, tmp_path / "area" / "novo-0123456789abcdef", existe=True)
    rec.attention = (
        "1 arquivo(s) não voltaram para a pasta porque já havia outro item com o mesmo nome: "
        "a.txt. A versão guardada deles foi mantida."
    )
    conflito = RestoreReport(rec.path, "ok", conflicts=["a.txt"])
    win._undo_done(UnlockOutcome(rec, True, conflito, rec.path), NOME)
    assert "versão guardada deles foi mantida" in tela.pergunta(f"'{NOME}' continua aberta")["text"]
    # 2) falha ao devolver: diz que nem tudo voltou
    rec.attention = "Não foi possível devolver todos os arquivos: b.txt"
    falha = RestoreReport(rec.path, "ok", failed=["b.txt"])
    win._undo_done(UnlockOutcome(rec, False, falha, rec.path), NOME)
    assert "b.txt" in tela.pergunta(f"Nem todos os arquivos voltaram para '{NOME}'")["text"]
    # 3) tudo voltou: só o aviso na lista, sem caixa
    rec.vaults.clear()
    rec.attention = ""
    antes = len(tela.perguntas)
    win._undo_done(UnlockOutcome(rec, True, RestoreReport(rec.path, "ok"), rec.path), NOME)
    assert len(tela.perguntas) == antes
    assert win.home.notice.text() == f"'{NOME}' continua aberta."


@gui
@pytest.mark.parametrize("sumiu", [False, True])
def test_versao_anterior_ilegivel_nunca_oferece_apagar(
    abrir_tela: Callable[..., Tela],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    sumiu: bool,
) -> None:
    tela = abrir_tela()
    win, rec = _destravada_com_pasta(tela, tmp_path)
    _versao_mantida(rec, tmp_path / "area" / "anterior-0123456789abcdef", existe=not sumiu)
    _com_vista(win, monkeypatch, rec, "versao_anterior_ilegivel")
    assert win.mgr is not None
    esquecidas: list[str] = []

    def esquecer(fid: str) -> int:
        esquecidas.append(fid)
        return 1

    monkeypatch.setattr(win.mgr, "forget_missing_kept", esquecer)
    tela.respostas["Versão anterior de"] = "forget_kept" if sumiu else "close"
    win._resolve(rec.id)
    pergunta = tela.pergunta(f"Versão anterior de '{NOME}'")
    assert "delete" not in pergunta["buttons"]
    # JAN-7: todo Resolver tem [Tirar da lista] (T8), também o da versão anterior ilegível
    if sumiu:
        assert pergunta["buttons"] == ["forget_kept", "forget", "close"]
        assert esquecidas == [rec.id]
        assert "Nada foi apagado" in win.home.notice.text()
    else:
        assert pergunta["buttons"] == ["restore", "forget", "close"]
        assert esquecidas == []


@gui
def test_versao_anterior_que_ficou_ilegivel_nao_conta_como_vazia(
    abrir_tela: Callable[..., Tela], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """kept_only_files agora levanta StateError com a versão ilegível: a janela não quebra nem
    oferece 'Apagar' (antes, a lista vazia virava "não tem arquivos que faltem. Apagar?")."""
    tela = abrir_tela()
    win, rec = _destravada_com_pasta(tela, tmp_path)
    _versao_mantida(rec, tmp_path / "area" / "anterior-0123456789abcdef", existe=True)
    _com_vista(win, monkeypatch, rec, "versao_anterior")
    assert win.mgr is not None

    def ilegivel(_fid: str) -> list[str]:
        raise StateError("Não foi possível ler a versão anterior mantida. Nada foi apagado.")

    monkeypatch.setattr(win.mgr, "kept_only_files", ilegivel)
    win._resolve(rec.id)
    pergunta = tela.pergunta(f"Versão anterior de '{NOME}'")
    assert pergunta["buttons"] == ["restore", "forget", "close"]  # JAN-7: com Tirar da lista
    # legível: 'Apagar a versão anterior…' é o botão destrutivo (vermelho)
    monkeypatch.setattr(win.mgr, "kept_only_files", lambda _fid: ["a.txt"])
    win._resolve(rec.id)
    pergunta = tela.pergunta(f"Versão anterior de '{NOME}'")
    assert pergunta["buttons"] == ["restore", "delete", "forget", "close"]
    assert pergunta["perigo"] == "delete"
    assert pergunta["primary"] == "restore"  # o padrão não mudou


@gui
def test_pedido_do_atalho_confere_e_refaz_o_atalho(
    abrir_tela: Callable[..., Tela], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tela = abrir_tela()
    win, rec = _destravada_com_pasta(tela, tmp_path, TRANCADA)
    assert win.mgr is not None
    nota = f"O atalho 'Abrir com Owl Vault' de '{NOME}' estava diferente do esperado e foi refeito."
    conferidas: list[str] = []

    def refaz(fid: str) -> list[str]:
        conferidas.append(fid)
        return [nota]

    monkeypatch.setattr(win.mgr, "repair_placeholders", refaz)
    abertas: list[str] = []
    monkeypatch.setattr(win, "_open_folder", abertas.append)
    win._open_from_shortcut(rec.id)  # app destravado: depois do PIN pedido de novo
    assert conferidas == [rec.id]
    assert tela.pergunta("O atalho desta pasta foi refeito")["text"] == nota
    assert abertas == [rec.id]
    win._open_pending(rec.id, owl_window.ORIGEM_LINHA)  # --abrir: depois da tela de PIN
    assert conferidas == [rec.id, rec.id]
    assert abertas == [rec.id, rec.id]

    def fora_do_lugar(_fid: str) -> list[str]:
        raise StateError("A pasta não está no lugar.")

    monkeypatch.setattr(win.mgr, "repair_placeholders", fora_do_lugar)
    antes = len(tela.perguntas)
    win._open_from_shortcut(rec.id)  # o próprio 'Abrir' explica o problema
    assert len(tela.perguntas) == antes
    assert abertas == [rec.id, rec.id, rec.id]


@gui
def test_tirar_da_lista_pasta_trancada_com_cofre_fora_avisa(
    abrir_tela: Callable[..., Tela], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tela = abrir_tela()
    win, rec = _destravada_com_pasta(tela, tmp_path, TRANCADA)
    assert win.mgr is not None
    aviso = (
        f"'{NOME}' tem arquivos guardados fora da pasta (em X, uma pasta oculta). Depois de tirar "
        "da lista, eles NÃO aparecem em 'Recuperar uma pasta protegida'."
    )
    monkeypatch.setattr(win.mgr, "forget_warning", lambda _fid: aviso)
    win._forget(rec.id)
    texto = tela.pergunta(f"Tirar '{NOME}' da lista?")["text"]
    assert texto.startswith("Nada será apagado.")
    assert aviso in texto
    assert "use ☰ > Recuperar" not in texto
    monkeypatch.setattr(win.mgr, "forget_warning", lambda _fid: "")
    win._forget(rec.id)
    assert "use ☰ > Recuperar" in tela.pergunta(f"Tirar '{NOME}' da lista?")["text"]
    assert win.session is not None and win.session.index.folder(rec.id) is rec  # cancelado


@gui
def test_resolver_trancando_mostra_as_notas_da_conferencia(
    abrir_tela: Callable[..., Tela], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tela = abrir_tela()
    win, rec = _destravada_com_pasta(tela, tmp_path, TRANCANDO)
    assert win.mgr is not None
    nota = f"O trancamento de '{NOME}' foi interrompido antes de apagar arquivos."
    monkeypatch.setattr(win.mgr, "reconcile_on_start", lambda: [nota])
    _com_vista(win, monkeypatch, rec, TRANCANDO)
    win._resolve(rec.id)
    assert win.home.notice.text() == nota


class _Queda(BaseException):
    """Queda simulada do processo: passa por cima do tratamento normal de erros."""


@gui
def test_resolver_trancando_preso_oferece_deixar_a_pasta_aberta(
    abrir_tela: Callable[..., Tela], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """estados-5 (B), pendência entre motor e janela: um trancamento interrompido cuja cópia
    nova não pode ser conferida ficava preso em 'trancando' (só Procurar e Tirar da lista).
    Agora o Resolver oferece 'Deixar a pasta aberta' (``LockerManager.leave_open``): a pasta
    volta a ficar aberta, a cópia em dúvida vira versão anterior e nada é apagado."""
    tela = abrir_tela()
    win = _pronta(tela)
    pasta, rec = _protegida(win, tmp_path / "pastas", NOME)
    mgr = win.mgr
    assert mgr is not None
    assert mgr.unlock(rec.id).complete
    antes = {p.name: p.read_bytes() for p in pasta.iterdir() if p.is_file()}
    real = type(mgr)._vault_id_of

    def queda_no_novo(vault_dir: str) -> str:
        if "novo-" in vault_dir:
            raise _Queda
        return real(vault_dir)

    with monkeypatch.context() as m:
        m.setattr(type(mgr), "_vault_id_of", staticmethod(queda_no_novo))
        with pytest.raises(_Queda):
            mgr.lock(rec.id)
    novo = rec.vault("novo")
    assert novo is not None and rec.state == TRANCANDO
    for n in ("vault.owl", "vault.owl.bak"):  # cabeçalho da cópia nova danificado
        f = Path(winfs.strip_extended(novo.location)) / n
        if f.exists():
            with open(f, "r+b") as fh:
                fh.seek(40)
                fh.write(b"\x00" * 16)
    titulo = f"Trancamento de '{NOME}' interrompido"
    tela.respostas[titulo] = "open"

    win._resolve(rec.id)
    _descarta()

    pergunta = tela.pergunta(titulo)
    assert pergunta["buttons"] == ["open", "find", "forget", "close"]
    assert pergunta["primary"] == "close"  # Enter não muda nada
    assert "Deixar a pasta aberta" in pergunta["text"]
    assert rec.state == ABERTA
    assert MANTIDO in [v.role for v in rec.vaults]  # a cópia em dúvida não foi apagada
    assert os.path.isdir(winfs.strip_extended(novo.location))
    assert {p.name: p.read_bytes() for p in pasta.iterdir() if p.is_file()} == antes
    assert win.home.notice.text() == f"'{NOME}' continua aberta."


@gui
def test_deixar_a_pasta_aberta_que_vira_apagando_ou_falha_tem_saida(
    abrir_tela: Callable[..., Tela], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Se a conferência de 'Deixar a pasta aberta' decidir que a exclusão já tinha começado
    (APAGANDO), aparece o Resolver da etapa 4; se ela falhar, o motivo aparece."""
    tela = abrir_tela()
    win, rec = _destravada_com_pasta(tela, tmp_path, TRANCANDO)
    assert win.mgr is not None
    monkeypatch.setattr(win.mgr, "reconcile_on_start", lambda: [])
    monkeypatch.setattr(
        win.mgr,
        "view",
        lambda r: FolderView(
            r, "Precisa de atenção", "resolver", "Atenção sintética", issue=r.state
        ),
    )

    def para_apagando(_fid: str) -> str:
        rec.state = APAGANDO
        return APAGANDO

    monkeypatch.setattr(win.mgr, "leave_open", para_apagando)
    titulo = f"Trancamento de '{NOME}' interrompido"
    tela.respostas[titulo] = "open"
    win._resolve(rec.id)
    _descarta()
    assert "undo" in tela.pergunta(titulo)["buttons"]  # Resolver da etapa 4 (Desfazer)

    def falha(_fid: str) -> str:
        raise StateError("Não há trancamento interrompido nesta pasta.")

    rec.state = TRANCANDO
    monkeypatch.setattr(win.mgr, "leave_open", falha)
    win._resolve(rec.id)
    _descarta()
    assert (
        tela.pergunta("Não foi possível deixar a pasta aberta")["text"]
        == "Não há trancamento interrompido nesta pasta."
    )


@gui
def test_alterar_pin_com_copia_de_seguranca_travada_avisa(
    abrir_tela: Callable[..., Tela], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Pendência do perfil (perfil-2): quando o PIN novo valeu no arquivo principal mas a cópia
    de segurança do perfil não pôde ser trocada, o aviso diz isso (NOTE_BACKUP_PENDING)."""

    class AlterarFalso:
        def __init__(self, *_a: object) -> None:
            pass

        def exec(self) -> QDialog.DialogCode:
            return QDialog.DialogCode.Accepted

        def take(self) -> tuple[str, str, bool]:
            return PIN, "961473", False

    monkeypatch.setattr(owl_window, "ChangePinDialog", AlterarFalso)
    tela = abrir_tela()
    win = tela.win
    win._unlocked(_criar_perfil(tela))
    store = win.store
    real = store.write_both

    def bak_travado(obj: dict[str, Any]) -> bool:
        real(obj)
        store.backup_pending = True  # o .bak não pôde ser trocado
        return False

    monkeypatch.setattr(store, "write_both", bak_travado)
    win._change_pin()
    _espera(lambda: not win.runner.busy)
    _descarta()
    assert win.home.notice.text() == f"PIN alterado. {profile_mod.NOTE_BACKUP_PENDING}"
    assert OwlWindow._profile_saved("PIN criado.", None) == "PIN criado."


@gui
def test_remover_protecao_usa_o_botao_de_perigo(
    abrir_tela: Callable[..., Tela], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    falso = _segredo_falso(monkeypatch, [None])
    tela = abrir_tela()
    win, rec = _destravada_com_pasta(tela, tmp_path)
    win._remove(rec.id)
    assert len(falso.criados) == 1
    assert falso.criados[0]["button"] == "Remover proteção"
    assert falso.criados[0]["perigo"] is True
    win.request_open(rec.id)  # o PIN do atalho não é destrutivo
    assert falso.criados[1]["perigo"] is False


# --------------------------------------------------------------------------- proteger na janela


@gui
def test_proteger_abre_o_assistente_na_janela(abrir_tela: Callable[..., Tela]) -> None:
    tela = abrir_tela()
    win = tela.win
    win._unlocked(_criar_perfil(tela))
    win.home.rodape.primario.click()  # "+ Proteger uma pasta…"
    page = win.protect_page
    assert win.pages.currentWidget() is page
    assert win.rodapes.currentWidget() is page.rodape
    assert page.step == 0
    assert page.first_time  # nenhuma pasta ainda: "Entendi" obrigatório
    page.rodape.voltar.click()
    assert win.pages.currentWidget() is win.home
    assert tela.dialogos == []  # nenhum diálogo modal (nem o seletor de pastas)


@gui
def test_proteger_pasta_que_nao_existe_mostra_o_motivo(
    abrir_tela: Callable[..., Tela], tmp_path: Path
) -> None:
    tela = abrir_tela()
    win = tela.win
    win._unlocked(_criar_perfil(tela))
    win._protect(str(tmp_path / "nao existe"))
    _espera(lambda: not win.runner.busy)
    _descarta()
    page = win.protect_page
    assert page.step == 1
    assert page.failures
    assert _estados(page)["permitida"] == "falhou"
    assert not page.rodape.primario.isEnabled()
    assert tela.dialogos == []  # a recusa aparece no passo "Conferência", não numa caixa


@gui
def test_proteger_confere_e_tranca_de_verdade(
    abrir_tela: Callable[..., Tela], tmp_path: Path
) -> None:
    """Fluxo inteiro com uma pasta sintética: conferência real, trancar em thread, lista."""
    tela = abrir_tela()
    win = tela.win
    win._unlocked(_criar_perfil(tela))
    pasta = tmp_path / "pastas" / NOME
    pasta.mkdir(parents=True)
    (pasta / "Relatório sigiloso.txt").write_bytes(b"dados sinteticos " * 100)
    win._protect(str(pasta))
    page = win.protect_page
    assert page.checking_now
    _espera(lambda: not win.runner.busy)
    _descarta()
    assert page.check is not None, page.failures
    assert set(_estados(page).values()) == {"ok"}
    assert page.linhas["arquivos"].detalhe.text().startswith("1 arquivo(s)")
    page.entendi.setChecked(True)
    page.rodape.primario.click()  # Trancar agora
    assert page.step == 2
    assert page.locking_now
    _espera(lambda: not win.runner.busy)
    _descarta()
    assert page.done
    assert page.t3.text() == f"'{NOME}' está trancada."
    registro = page.log.toPlainText()
    assert "4/4" in registro
    assert "Relatório" not in registro  # o registro só tem etapas
    assert win.mgr is not None
    assert [r.state for r in win.mgr.folders] == [TRANCADA]
    assert not (pasta / "Relatório sigiloso.txt").exists()
    page.rodape.primario.click()  # Voltar para a lista
    assert win.pages.currentWidget() is win.home
    assert len(win.home.findChildren(pages.FolderRow)) == 1
    assert win.home.notice.text() == f"'{NOME}' está trancada."


# --------------------------------------------------------------------------- sair (T11)


@gui
def test_sair_com_pasta_aberta_pergunta_antes(
    abrir_tela: Callable[..., Tela], tmp_path: Path
) -> None:
    tela = abrir_tela()
    win = tela.win
    sessao = _criar_perfil(tela)
    win._unlocked(sessao)
    sessao.index.folders.append(_pasta_aberta(tmp_path))
    assert not win.close()  # resposta gravada: "cancel"
    pergunta = tela.pergunta("Sair do Owl Vault?")
    assert pergunta["buttons"] == ["lock", "quit", "cancel"]
    assert pergunta["primary"] == "lock"  # "Trancar e sair" é o padrão
    assert win.session is sessao
    sessao.index.folders.clear()
    assert win.close()  # nenhuma aberta: sai e descarta as chaves
    assert win.session is None


@gui
def test_sair_com_app_travado_e_pasta_aberta_ainda_pergunta(
    abrir_tela: Callable[..., Tela], tmp_path: Path
) -> None:
    """Achado: depois do travamento automático (mgr=None), o X fechava sem o T11."""
    tela = abrir_tela()
    win = tela.win
    sessao = _criar_perfil(tela)
    win._unlocked(sessao)
    sessao.index.folders.append(_pasta_aberta(tmp_path))
    win.lock_now()
    assert win._visible_count == 1  # só a contagem, sem nomes
    assert not win.close()
    pergunta = tela.pergunta("Sair do Owl Vault?")
    assert pergunta["text"] == "Há 1 pasta aberta e visível. Digite o PIN para trancar."
    assert pergunta["buttons"] == ["quit", "cancel"]
    assert NOME not in pergunta["text"]
    assert win.pages.currentWidget() is win.unlock_page  # Cancelar: fica no PIN
    tela.respostas["Sair do Owl Vault?"] = "quit"
    assert win.close()


@gui
@pytest.mark.parametrize("estado", [APAGANDO, ABERTURA_INCOMPLETA, ABRINDO, RESTAURANDO, TRANCANDO])
def test_sair_com_pasta_com_copias_legiveis_pergunta(
    abrir_tela: Callable[..., Tela], tmp_path: Path, estado: str
) -> None:
    tela = abrir_tela()
    win = tela.win
    sessao = _criar_perfil(tela)
    win._unlocked(sessao)
    sessao.index.folders.append(_pasta_aberta(tmp_path, state=estado))
    win._refresh()
    assert not win.home.banner.isHidden()  # a faixa também aparece
    assert not win.close()
    pergunta = tela.pergunta("Sair do Owl Vault?")
    assert "lock" not in pergunta["buttons"]  # não dá para trancar automaticamente
    assert pergunta["buttons"] == ["quit", "cancel"]
    assert any("precisa de atenção" in d for d in pergunta["details"])


@gui
def test_fechar_durante_operacao_nao_deixa_conexao_permanente(
    abrir_tela: Callable[..., Tela], tmp_path: Path
) -> None:
    """Achado: 'Parar e fechar' conectava runner.done → sair para sempre."""
    tela = abrir_tela()
    win = tela.win
    sessao = _criar_perfil(tela)
    win._unlocked(sessao)
    sessao.index.folders.append(_pasta_aberta(tmp_path))
    receptores = win.runner.receivers(SIGNAL("done(PyObject)"))
    liberar = threading.Event()
    assert win._run(lambda _p, _c: liberar.wait(10), lambda _r: None)

    def termina_antes_de_responder() -> str:  # o trabalho acaba com a pergunta aberta
        liberar.set()
        _espera(lambda: not win.runner.busy)
        return "stop"

    tela.respostas["Há uma operação em andamento"] = termina_antes_de_responder
    assert not win.close()
    _descarta()
    assert not win._quit_after_job  # já tinha terminado: segue o caminho normal (T11)
    assert tela.pergunta("Sair do Owl Vault?")  # T11 perguntou e a resposta foi "cancel"
    assert win.session is sessao
    fim: list[object] = []
    assert win._run(lambda _p, _c: "depois", fim.append)  # uma operação futura...
    _espera(lambda: bool(fim))
    _descarta()
    assert not win._quitting  # ...não fecha o app
    assert win.session is sessao
    assert win.runner.receivers(SIGNAL("done(PyObject)")) == receptores


@gui
def test_parar_e_fechar_fecha_uma_vez_quando_o_trabalho_para(
    abrir_tela: Callable[..., Tela],
) -> None:
    tela = abrir_tela()
    win = tela.win
    win._unlocked(_criar_perfil(tela))
    liberar = threading.Event()
    assert win._run(lambda _p, c: liberar.wait(10), lambda _r: None)
    tela.respostas["Há uma operação em andamento"] = "stop"
    assert not win.close()
    assert win._quit_after_job
    assert win.runner.cancel_token is not None and win.runner.cancel_token.cancelled
    liberar.set()
    _espera(lambda: win._quitting)
    assert win.session is None
    assert not win._quit_after_job


class _CopiaFalsa(QWidget):
    """Janela da Cópia criptografada (sem abrir a real): ``aceita`` decide se fecha."""

    def __init__(self, aceita: bool) -> None:
        super().__init__()
        self.aceita = aceita
        self.fechada = False

    def isVisible(self) -> bool:
        return not self.fechada

    def close(self) -> bool:
        if self.aceita:
            self.fechada = True
        return self.aceita


@gui
def test_fechar_a_janela_fecha_a_copia_e_nao_reaparece_sem_sessao(
    abrir_tela: Callable[..., Tela], tmp_path: Path
) -> None:
    tela = abrir_tela()
    win = tela.win
    sessao = _criar_perfil(tela)
    win._unlocked(sessao)
    sessao.index.folders.append(_pasta_aberta(tmp_path, "Outra"))
    sessao.index.folders[0].state = TRANCADA
    win._refresh()
    copia = _CopiaFalsa(aceita=True)
    win._copy_window = copia
    assert win.close()
    assert copia.fechada
    assert win._copy_window is None
    assert win.session is None
    assert win.home.findChildren(pages.FolderRow) == []  # nada da lista fica na janela
    win.handle_message("mostrar")  # 2ª execução pede para mostrar
    assert not win._quitting  # o próximo X passa pelo T11 de novo
    assert win.pages.currentWidget() is win.unlock_page


@gui
def test_copia_ocupada_impede_fechar_pela_metade(abrir_tela: Callable[..., Tela]) -> None:
    tela = abrir_tela()
    win = tela.win
    sessao = _criar_perfil(tela)
    win._unlocked(sessao)
    win._copy_window = _CopiaFalsa(aceita=False)  # trabalhando: recusa fechar
    assert not win.close()
    assert win.session is sessao
    assert not win._quitting


@gui
@pytest.mark.parametrize(("resposta", "sai"), [("", False), ("quit", True)])
def test_erro_no_trancar_e_sair_mostra_o_motivo_e_esc_nao_sai(
    abrir_tela: Callable[..., Tela], tmp_path: Path, resposta: str, sai: bool
) -> None:
    tela = abrir_tela()
    win = tela.win
    sessao = _criar_perfil(tela)
    win._unlocked(sessao)
    rec = _pasta_aberta(tmp_path)
    sessao.index.folders.append(rec)
    tela.respostas["Não deu para trancar"] = resposta
    erro = PreflightError(
        "Não é possível proteger esta pasta.", ["IMG_0042.jpg: em uso", "IMG_0043.jpg: em uso"]
    )
    # a fila não para no erro (estados-7): ele vai para o resumo do fim do "Trancar e sair"
    seq = owl_window._Sequencia([], sair=True, conhecidas={rec.id})
    seq.falhas.append(win._lock_failure(rec.id, erro))
    win._quit_sequence = True
    win._quit_sequence_end(seq)
    _descarta()
    pergunta = tela.pergunta(f"Não deu para trancar '{NOME}'")
    assert pergunta["text"].startswith("IMG_0042.jpg: em uso")
    assert "Tentar de novo" in pergunta["text"]
    assert pergunta["details"] == ["IMG_0043.jpg: em uso"]
    assert pergunta["buttons"] == ["retry", "quit"]
    assert pergunta["primary"] == "retry"
    assert not win._quit_sequence
    assert win._quitting == sai
    if not sai:  # Esc/X no aviso: volta ao app, nada de sair com a pasta aberta
        assert win.session is sessao
        assert "continuam abertas" in win.home.notice.text()


# =========================================================================== revisão adversarial
# (janela principal: achados estados-*, fluxos-*, perfil-*, visual-* da revisão da 0.3.0)


class _CancelaDepois(NullProgress):
    """Progresso que pede o cancelamento depois de ``n`` arquivos (como o [Cancelar] da tela)."""

    def __init__(self, token: CancelToken, n: int) -> None:
        self.token = token
        self.n = n
        self.vistos = 0

    def advance(self, nbytes: int = 0, nitems: int = 0) -> None:
        self.vistos += nitems
        if self.vistos >= self.n:
            self.token.cancel()


def _pronta(tela: Tela) -> OwlWindow:
    tela.win._unlocked(_criar_perfil(tela))
    _descarta()
    return tela.win


def _protegida(win: OwlWindow, base: Path, nome: str, n: int = 4) -> tuple[Path, FolderRecord]:
    """Pasta sintética protegida DE VERDADE (trancada) pelo gerente da janela."""
    pasta = base / nome
    pasta.mkdir(parents=True)
    for i in range(n):
        (pasta / f"doc {i}.txt").write_bytes(f"{i:02d}".encode() * 300)
    assert win.mgr is not None
    return pasta, win.mgr.protect(win.mgr.check_protect(str(pasta))).record


def _espera_fila(win: OwlWindow, cond: Callable[[], object], timeout: float = 60.0) -> None:
    """Espera uma fila de trabalhos (um puxa o outro por QTimer) chegar a ``cond``."""
    fim = time.monotonic() + timeout
    while not (cond() and not win.runner.busy):
        if time.monotonic() > fim:
            raise AssertionError("tempo esgotado esperando a fila de trabalhos")
        _descarta()
        time.sleep(0.005)
    _descarta()


@gui
def test_abertura_cancelada_no_meio_pergunta_ao_sair_e_conta_ao_bloquear(
    abrir_tela: Callable[..., Tela], tmp_path: Path
) -> None:
    """estados-1 / fluxos-1: [Cancelar] em 'Abrindo' deixa a pasta em 'restaurando' com parte
    dos arquivos legível. Antes, a faixa sumia e o X fechava o app sem perguntar nada."""
    tela = abrir_tela()
    win = _pronta(tela)
    pasta, rec = _protegida(win, tmp_path / "pastas", NOME, n=6)
    assert win.mgr is not None
    token = CancelToken()
    with pytest.raises(CancelledError):
        win.mgr.unlock(rec.id, _CancelaDepois(token, 2), token)
    assert rec.state == RESTAURANDO
    assert [n for n in os.listdir(pasta) if n.endswith(".txt")]  # há cópias legíveis
    win._refresh()
    assert not win.home.banner.isHidden()
    assert win.home.banner_text.startswith("1 pasta está aberta e visível")
    assert not win.close()
    pergunta = tela.pergunta("Sair do Owl Vault?")
    assert pergunta["buttons"] == ["quit", "cancel"]  # não dá para trancar automaticamente
    assert any(NOME in d and "precisa de atenção" in d for d in pergunta["details"])
    assert win.session is not None
    win.lock_now()  # depois do bloqueio, o X ainda pergunta (só a contagem fica em memória)
    assert win._visible_count == 1
    antes = len(tela.perguntas)
    assert not win.close()
    assert [p["title"] for p in tela.perguntas[antes:]] == ["Sair do Owl Vault?"]


@gui
@pytest.mark.parametrize("estado", [APAGANDO, ABRINDO, RESTAURANDO, ABERTURA_INCOMPLETA])
def test_tirar_da_lista_em_estado_intermediario_diz_a_verdade(
    abrir_tela: Callable[..., Tela],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    estado: str,
) -> None:
    """estados-3 / fluxos-7 (contrato C2): o texto vem de forget_warning em QUALQUER estado.
    Antes, fora de 'trancada', a janela dizia "Os arquivos legíveis continuam na pasta" (falso:
    em 'abrindo' a pasta está vazia; em 'apagando' parte já foi apagada) e não avisava que
    'Recuperar' não acha a cópia da área temporária."""
    tela = abrir_tela()
    win, rec = _destravada_com_pasta(tela, tmp_path, estado)
    assert win.mgr is not None
    aviso = (
        f"'{NOME}' tem arquivos guardados fora da pasta (em X, uma pasta oculta). Depois de tirar "
        "da lista, eles NÃO aparecem em 'Recuperar uma pasta protegida'."
    )
    monkeypatch.setattr(win.mgr, "forget_warning", lambda _fid: aviso)
    win._forget(rec.id)
    texto = tela.pergunta(f"Tirar '{NOME}' da lista?")["text"]
    assert texto.startswith("Nada será apagado.")
    assert aviso in texto
    assert "Os arquivos legíveis continuam na pasta" not in texto
    assert "use ☰ > Recuperar" not in texto
    # sem aviso do gerente: a janela também não afirma o que pode ser falso
    monkeypatch.setattr(win.mgr, "forget_warning", lambda _fid: "")
    win._forget(rec.id)
    texto = tela.pergunta(f"Tirar '{NOME}' da lista?")["text"]
    assert "Os arquivos legíveis continuam na pasta" not in texto
    assert f".owlvault-{rec.id}" in texto
    assert "NÃO encontra" in texto
    assert "use ☰ > Recuperar" not in texto
    assert win.session is not None and win.session.index.folder(rec.id) is rec  # cancelado
    tela.respostas[f"Tirar '{NOME}'"] = "go"
    win._forget(rec.id)
    assert win.session.index.folder(rec.id) is None
    assert win.home.notice.text() == f"'{NOME}' saiu da lista. Nada foi apagado."


#: (estado da pasta, issue mostrada, título do Resolver)
CASOS_RESOLVER = [
    (APAGANDO, APAGANDO, f"Trancamento de '{NOME}' interrompido"),
    (ABRINDO, ABRINDO, f"Abertura de '{NOME}' interrompida"),
    (RESTAURANDO, ABRINDO, f"Abertura de '{NOME}' interrompida"),
    (ABERTURA_INCOMPLETA, ABERTURA_INCOMPLETA, f"'{NOME}' não abriu por completo"),
    (TRANCANDO, TRANCANDO, f"Trancamento de '{NOME}' interrompido"),
    (TRANCADA, "indisponivel", f"'{NOME}' está indisponível"),
    (TRANCADA, "nao_encontrada", f"'{NOME}' não foi encontrada"),
    (TRANCADA, "itens_extras", f"Há itens novos em '{NOME}'"),
    (TRANCADA, "sem_dados", f"Dados de '{NOME}' não encontrados"),
    (TRANCADA, "cofre_diferente", f"'{NOME}' precisa de atenção"),
    ("estado_novo", "estado_novo", f"'{NOME}' precisa de atenção"),
]


@gui
@pytest.mark.parametrize(("estado", "issue", "titulo"), CASOS_RESOLVER)
def test_resolver_de_todo_estado_oferece_tirar_da_lista(
    abrir_tela: Callable[..., Tela],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    estado: str,
    issue: str,
    titulo: str,
) -> None:
    """estados-5 / contratos C2 e C4: todo Resolver tem uma saída ("Tirar da lista"), mostra o
    texto do gerente (``attention``) e um problema desconhecido cai no Resolver genérico."""
    tela = abrir_tela()
    win, rec = _destravada_com_pasta(tela, tmp_path, estado)
    assert win.mgr is not None
    _com_vista(win, monkeypatch, rec, issue)
    monkeypatch.setattr(win.mgr, "reconcile_on_start", lambda: [])  # 'trancando' continua preso
    tela.respostas[titulo] = "forget"
    win._resolve(rec.id)
    pergunta = tela.pergunta(titulo)
    assert "forget" in pergunta["buttons"]
    if issue not in ("nao_encontrada", "abertura_incompleta", "sem_dados"):
        assert "Atenção sintética" in pergunta["text"]  # o texto específico do gerente
    if issue in ("indisponivel", "nao_encontrada", "cofre_diferente", "estado_novo", TRANCANDO):
        assert "find" in pergunta["buttons"]  # "Procurar a pasta…"
    tela.pergunta(f"Tirar '{NOME}' da lista?")  # "Tirar da lista" leva à confirmação


@gui
def test_resolver_generico_oferece_a_acao_base_e_cancelar_e_o_padrao(
    abrir_tela: Callable[..., Tela], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """C4 / estados-9: um problema novo do gerente (ex.: o cofre na pasta não é o registrado)
    mostra o texto dele, a ação base, [Procurar a pasta…] [Tirar da lista] [Cancelar]."""
    tela = abrir_tela()
    win, rec = _destravada_com_pasta(tela, tmp_path, TRANCADA)
    assert win.mgr is not None
    vista = FolderView(
        rec,
        "Precisa de atenção",
        "resolver",
        "Os dados desta pasta não são os registrados.",
        issue="cofre_diferente",
        base_action="abrir",
    )
    monkeypatch.setattr(win.mgr, "view", lambda _r: vista)
    win._resolve(rec.id)
    pergunta = tela.pergunta(f"'{NOME}' precisa de atenção")
    assert pergunta["text"] == "Os dados desta pasta não são os registrados."
    assert pergunta["buttons"] == ["base", "find", "forget", "cancel"]
    assert pergunta["primary"] == "cancel"
    assert pages.row_menu(vista)[-2:] == [PROCURAR, TIRAR]


@gui
def test_unidade_com_outra_letra_pelo_atalho_explica_e_oferece_procurar(
    abrir_tela: Callable[..., Tela], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """estados-6: 'indisponível' tinha só "Tirar da lista" no ⋯, e o atalho da própria pasta
    pedia o PIN e terminava em silêncio (o Resolver não tinha ramo para 'indisponivel')."""
    tela = abrir_tela()
    win, rec = _destravada_com_pasta(tela, tmp_path, TRANCADA)
    assert win.mgr is not None
    vista = FolderView(
        rec,
        "Indisponível — conecte a unidade Q:",
        "",
        f"A unidade de '{NOME}' não está disponível.",
        available=False,
        issue="indisponivel",
    )
    monkeypatch.setattr(win.mgr, "view", lambda _r: vista)

    def fora(_fid: str) -> list[str]:
        raise StateError("A unidade não está disponível.")

    monkeypatch.setattr(win.mgr, "repair_placeholders", fora)
    procurar: list[str] = []
    monkeypatch.setattr(win, "_relocate", procurar.append)
    tela.respostas[f"'{NOME}' está indisponível"] = "find"
    win._open_from_shortcut(rec.id)  # depois do PIN aceito
    pergunta = tela.pergunta(f"'{NOME}' está indisponível")
    assert pergunta["buttons"] == ["find", "forget", "close"]
    assert "outra letra" in pergunta["text"]
    assert procurar == [rec.id]
    assert pages.row_menu(vista) == [PROCURAR, TIRAR]
    row = pages.FolderRow(vista, lambda _f, _a: None, pages.row_menu(vista))
    assert any("Procurar a pasta" in d.accessibleName() for d in _por_nome(row, "linhaDetalhe"))
    row.deleteLater()
    _descarta()


@gui
def test_trancar_agora_segue_depois_de_uma_falha_e_resume(
    abrir_tela: Callable[..., Tela], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """fluxos-12 / estados-7: a 1ª pasta com erro não para a fila; no fim, um resumo diz qual
    ficou aberta e por quê (com o nome dela, não "Não é possível proteger esta pasta.")."""
    tela = abrir_tela()
    win = _pronta(tela)
    _pa, ra = _protegida(win, tmp_path / "pastas", "Pasta A", 2)
    _pb, rb = _protegida(win, tmp_path / "pastas", "Pasta B", 2)
    _pc, rc = _protegida(win, tmp_path / "pastas", "Pasta C", 2)
    mgr = win.mgr
    assert mgr is not None
    for r in (ra, rb, rc):
        mgr.unlock(r.id)
    (tmp_path / "pastas" / "Pasta C").rename(tmp_path / "pastas" / "Pasta C renomeada")
    real_lock = mgr.lock

    def lock(folder_id: str, *a: Any, **k: Any) -> LockOutcome:
        if folder_id == ra.id:
            raise PreflightError(
                "Não é possível proteger esta pasta.", ["doc 0.txt: em uso", "doc 1.txt: em uso"]
            )
        return real_lock(folder_id, *a, **k)

    monkeypatch.setattr(mgr, "lock", lock)
    win._refresh()
    assert not win.home.lock_all.isHidden()
    win._lock_all()
    _espera_fila(win, lambda: rb.state == TRANCADA and tela.perguntas)
    assert [ra.state, rb.state, rc.state] == [ABERTA, TRANCADA, ABERTA]
    pergunta = tela.perguntas[-1]
    assert pergunta["title"] == "2 pastas não foram trancadas"
    assert pergunta["text"].startswith("1 pasta(s) foram trancadas.")
    assert any(d.startswith("Pasta A: doc 0.txt: em uso") for d in pergunta["details"])
    assert any(d.startswith("Pasta C: ") for d in pergunta["details"])
    assert not [p for p in tela.perguntas if p["title"] == "Não é possível proteger esta pasta."]


@gui
def test_trancar_agora_poe_no_resumo_a_pasta_restaurando(
    abrir_tela: Callable[..., Tela], tmp_path: Path
) -> None:
    """'Trancar agora' tranca as abertas e põe no resumo também a pasta visível que não dá
    para trancar fora de 'aberta' (aqui, uma abertura cancelada no meio: 'restaurando').
    Antes, só as pastas em 'aberta' entravam no resumo e esta ficava de fora, calada."""
    tela = abrir_tela()
    win = _pronta(tela)
    _pa, ra = _protegida(win, tmp_path / "pastas", "Pasta A", 2)
    _pb, rb = _protegida(win, tmp_path / "pastas", "Pasta B", 6)
    mgr = win.mgr
    assert mgr is not None
    mgr.unlock(ra.id)
    token = CancelToken()
    with pytest.raises(CancelledError):
        mgr.unlock(rb.id, _CancelaDepois(token, 2), token)
    assert rb.state == RESTAURANDO
    win._refresh()
    assert not win.home.lock_all.isHidden()
    win._lock_all()
    _espera_fila(win, lambda: ra.state == TRANCADA and tela.perguntas)
    assert [ra.state, rb.state] == [TRANCADA, RESTAURANDO]
    pergunta = tela.perguntas[-1]
    assert pergunta["title"] == "Não deu para trancar 'Pasta B'"
    assert pergunta["text"].startswith("1 pasta(s) foram trancadas.")


@gui
def test_bloquear_no_meio_do_trancar_agora_nao_mostra_resumo_na_tela_travada(
    abrir_tela: Callable[..., Tela], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """O travamento automático (ou Win+L) chega com a pergunta do T7 na tela, no meio de
    'Trancar agora': a fila acaba ali, sem mostrar o resumo (com nomes) na tela travada."""
    tela = abrir_tela()
    win = _pronta(tela)
    _pa, ra = _protegida(win, tmp_path / "pastas", "Pasta A", 2)
    _pc, rc = _protegida(win, tmp_path / "pastas", "Pasta C", 2)
    mgr = win.mgr
    assert mgr is not None
    for r in (ra, rc):
        mgr.unlock(r.id)
    (tmp_path / "pastas" / "Pasta C").rename(tmp_path / "pastas" / "Pasta C 2")  # vai p/ resumo
    monkeypatch.setattr(mgr, "missing_since_open", lambda _f: ["doc 9.txt"])

    def t7() -> str:
        win.lock_now()  # bloqueia com a pergunta na tela (ela é rejeitada)
        return ""

    tela.respostas["Trancar 'Pasta A'?"] = t7
    win._lock_all()
    _descarta()
    assert win.session is None and win.mgr is None
    assert [p["title"] for p in tela.perguntas] == ["Trancar 'Pasta A'?"]
    assert ra.state == ABERTA


@gui
@pytest.mark.parametrize("resposta", ["", "quit"])
def test_trancar_e_sair_tranca_as_outras_e_so_sai_se_pedirem(
    abrir_tela: Callable[..., Tela],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    resposta: str,
) -> None:
    """estados-7: "Trancar e sair" parava na 1ª pasta com problema e "Sair sem trancar" deixava
    abertas TODAS as outras; agora a fila segue e o resumo só sai se o usuário pedir."""
    tela = abrir_tela()
    win = _pronta(tela)
    _pa, ra = _protegida(win, tmp_path / "pastas", "Antiga", 2)
    _pb, rb = _protegida(win, tmp_path / "pastas", "Fotos", 2)
    _pc, rc = _protegida(win, tmp_path / "pastas", "Renomeada", 2)
    mgr = win.mgr
    assert mgr is not None
    for r in (ra, rb, rc):
        mgr.unlock(r.id)
    (tmp_path / "pastas" / "Renomeada").rename(tmp_path / "pastas" / "Renomeada 2")
    real_lock = mgr.lock

    def lock(folder_id: str, *a: Any, **k: Any) -> LockOutcome:
        if folder_id == ra.id:
            raise PreflightError("Não é possível proteger esta pasta.", ["doc 0.txt: em uso"])
        return real_lock(folder_id, *a, **k)

    monkeypatch.setattr(mgr, "lock", lock)
    tela.respostas["Sair do Owl Vault?"] = "lock"
    tela.respostas["2 pastas não foram trancadas"] = resposta
    assert not win.close()
    t11 = tela.pergunta("Sair do Owl Vault?")
    assert t11["buttons"] == ["lock", "quit", "cancel"]
    # a que sumiu aparece como "precisa de atenção", não como aberta
    assert any(d.startswith("Renomeada — precisa de atenção") for d in t11["details"])
    _espera_fila(
        win, lambda: bool([p for p in tela.perguntas if "não foram trancadas" in p["title"]])
    )
    assert rb.state == TRANCADA  # a falha de 'Antiga' não impediu as outras
    # JAN-1: a que precisa de atenção ('Renomeada', com cópias legíveis) também entra no
    # resumo — antes, só 'Antiga' aparecia e a outra ficava aberta sem ninguém escolher
    resumo = tela.pergunta("2 pastas não foram trancadas")
    assert resumo["buttons"] == ["retry", "quit"]  # 'Antiga' dá para tentar de novo
    assert any(d.startswith("Antiga: doc 0.txt: em uso") for d in resumo["details"])
    assert any(d.startswith("Renomeada: ") for d in resumo["details"])
    _descarta()
    assert win._quitting == (resposta == "quit")
    assert len([p for p in tela.perguntas if p["title"] == "Sair do Owl Vault?"]) == 1
    if not resposta:
        assert win.session is not None
        assert ra.state == ABERTA


@gui
def test_trancar_e_sair_parado_na_etapa_4_nao_promete_o_que_nao_existe(
    abrir_tela: Callable[..., Tela], tmp_path: Path
) -> None:
    """fluxos-4: [Parar depois do arquivo atual] deixa a pasta em 'apagando'. O aviso dizia "A
    pasta continua aberta" e oferecia "Tentar de novo", que não trancava nada."""
    tela = abrir_tela()
    win, rec = _destravada_com_pasta(tela, tmp_path, APAGANDO)
    falha = win._lock_failure(rec.id, CancelledError("parou"))
    assert "parte das cópias legíveis ainda está na pasta" in falha.motivo
    assert "continua aberta" not in falha.motivo
    assert "Resolver" in falha.motivo
    seq = owl_window._Sequencia([], sair=True, conhecidas={rec.id}, parou=True)
    seq.falhas.append(falha)
    win._quit_sequence = True
    win._quit_sequence_end(seq)
    pergunta = tela.pergunta(f"Não deu para trancar '{NOME}'")
    assert pergunta["buttons"] == ["cancel", "quit"]  # [Voltar ao Owl Vault] [Sair sem trancar]
    assert pergunta["primary"] == "cancel"
    assert not win._quitting
    assert "Resolver" in win.home.notice.text()
    # cancelado nas etapas 1 a 3: a pasta continua aberta, como antes
    rec.state = ABERTA
    assert "continua aberta" in win._lock_failure(rec.id, CancelledError("parou")).motivo


@gui
def test_t11_decide_com_a_lista_de_agora(abrir_tela: Callable[..., Tela], tmp_path: Path) -> None:
    """fluxos-2: uma pasta aberta pelo atalho com a pergunta de saída na tela ficava aberta e
    o app saía. Agora a lista é refeita no momento da decisão e a pergunta volta com ela."""
    tela = abrir_tela()
    win, rec_a = _destravada_com_pasta(tela, tmp_path)
    rec_b = _pasta_aberta(tmp_path, "Pasta B", state=TRANCADA)
    assert win.session is not None
    win.session.index.folders.append(rec_b)
    respostas = iter(["quit", "cancel"])

    def responde() -> str:
        rec_b.state = ABERTA  # o atalho abriu 'Pasta B' com a pergunta na tela
        return next(respostas)

    tela.respostas["Sair do Owl Vault?"] = responde
    assert not win.close()
    t11 = [p for p in tela.perguntas if p["title"] == "Sair do Owl Vault?"]
    assert len(t11) == 2
    assert not any("Pasta B" in d for d in t11[0]["details"])
    assert any(d == "Pasta B" for d in t11[1]["details"])
    assert not win._quitting  # a 2ª resposta foi "Cancelar"
    assert win.session is not None
    assert rec_a.state == ABERTA


@gui
def test_t11_trancar_e_sair_tranca_a_pasta_aberta_durante_a_pergunta(
    abrir_tela: Callable[..., Tela], tmp_path: Path
) -> None:
    tela = abrir_tela()
    win = _pronta(tela)
    _pa, ra = _protegida(win, tmp_path / "pastas", "Pasta A", 2)
    _pb, rb = _protegida(win, tmp_path / "pastas", "Pasta B", 2)
    mgr = win.mgr
    assert mgr is not None
    mgr.unlock(ra.id)
    chamadas: list[int] = []

    def responde() -> str:
        if not chamadas:
            mgr.unlock(rb.id)  # aberta pelo atalho com a pergunta na tela
        chamadas.append(1)
        return "lock"

    tela.respostas["Sair do Owl Vault?"] = responde
    assert not win.close()
    _espera_fila(win, lambda: win._quitting)
    assert [ra.state, rb.state] == [TRANCADA, TRANCADA]
    assert len(chamadas) == 2  # a pergunta voltou, agora com 'Pasta B'


@gui
def test_t11_pasta_oferecida_que_sumiu_durante_a_pergunta_vai_para_o_resumo(
    abrir_tela: Callable[..., Tela], tmp_path: Path
) -> None:
    """fluxos-2 / estados-7: 'Trancar e sair' prometeu trancar 'Pasta B'; se ela deixou de poder
    ser trancada com a pergunta na tela (renomeada), o app não sai calado: o resumo diz qual
    ficou aberta e por quê, e só sai sem trancar se o usuário escolher."""
    tela = abrir_tela()
    win = _pronta(tela)
    _pa, ra = _protegida(win, tmp_path / "pastas", "Pasta A", 2)
    _pb, rb = _protegida(win, tmp_path / "pastas", "Pasta B", 2)
    mgr = win.mgr
    assert mgr is not None
    mgr.unlock(ra.id)
    mgr.unlock(rb.id)

    def responde() -> str:
        (tmp_path / "pastas" / "Pasta B").rename(tmp_path / "pastas" / "Pasta B 2")
        return "lock"

    tela.respostas["Sair do Owl Vault?"] = responde
    tela.respostas["Não deu para trancar"] = ""  # Esc: volta ao app
    assert not win.close()
    t11 = tela.pergunta("Sair do Owl Vault?")
    assert t11["details"] == ["Pasta A", "Pasta B"]  # as duas podiam ser trancadas
    _espera_fila(win, lambda: bool(tela.perguntas[-1]["title"].startswith("Não deu")))
    resumo = tela.pergunta("Não deu para trancar 'Pasta B'")
    assert resumo["buttons"] == ["cancel", "quit"]  # [Voltar ao Owl Vault] [Sair sem trancar]
    assert resumo["text"].startswith("1 pasta(s) foram trancadas.")
    _descarta()
    assert [ra.state, rb.state] == [TRANCADA, ABERTA]
    assert not win._quitting and win.session is not None
    assert len([p for p in tela.perguntas if p["title"] == "Sair do Owl Vault?"]) == 1


@gui
def test_atalho_durante_trancar_e_sair_pede_para_esperar(
    abrir_tela: Callable[..., Tela], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    falso = _segredo_falso(monkeypatch, [PIN])
    tela = abrir_tela()
    win, rec = _destravada_com_pasta(tela, tmp_path, TRANCADA)
    win._quit_sequence = True
    win.request_open(rec.id)
    assert falso.criados == []  # nada de PIN: a pasta não é aberta no meio da saída
    assert "trancando as pastas para fechar" in tela.pergunta("Aguarde")["text"]
    # e se, mesmo assim, aparecer outra pasta aberta, o app pergunta de novo em vez de sair
    rec.state = ABERTA
    win._quit_now(conhecidas=set())
    assert not win._quitting
    _descarta()
    assert tela.pergunta("Sair do Owl Vault?")


@gui
def test_t7_enter_nao_escolhe_trancar_e_apagar(
    abrir_tela: Callable[..., Tela], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """fluxos-5: no T7, Enter acionava "Trancar mesmo assim", que apaga para sempre a cópia
    protegida dos arquivos que sumiram. O padrão agora é Cancelar e o "go" é o de perigo."""
    tela = abrir_tela()
    win, rec = _destravada_com_pasta(tela, tmp_path)
    assert win.mgr is not None
    monkeypatch.setattr(win.mgr, "missing_since_open", lambda _f: ["Relatorio secreto 1.txt"])
    assert not win._lock_folder(rec.id)  # resposta gravada: "cancel"
    assert not win.runner.busy
    pergunta = tela.pergunta(f"Trancar '{NOME}'?")
    assert pergunta["buttons"] == ["go", "cancel"]
    assert pergunta["primary"] == "cancel"
    assert pergunta["perigo"] == "go"
    assert "para sempre" in pergunta["text"]
    # a caixa de verdade: Enter (botão padrão) é Cancelar
    caixa = folder_dialogs.ChoiceDialog(
        win,
        pergunta["title"],
        pergunta["text"],
        [("Trancar mesmo assim", "go"), ("Cancelar", "cancel")],
        primary="cancel",
        perigo="go",
    )
    assert caixa.buttons["cancel"].isDefault()
    assert not caixa.buttons["go"].isDefault()
    assert caixa.buttons["go"].objectName() == "perigo"
    caixa.deleteLater()
    _descarta()


@gui
def test_resolver_apagando_usa_o_texto_do_gerente_e_avisa_item_novo(
    abrir_tela: Callable[..., Tela], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """fluxos-6: o Resolver dizia "Seus arquivos já estão guardados… Feche-os" também para um
    item NOVO colocado durante o trancamento (que NÃO está guardado)."""
    tela = abrir_tela()
    win, rec = _destravada_com_pasta(tela, tmp_path, APAGANDO)
    assert win.mgr is not None
    rec.pending = ["Planilha nova.xlsx: item novo colocado na pasta durante o trancamento"]
    vista = FolderView(rec, "Precisa de atenção", "resolver", "Texto do gerente.", issue=APAGANDO)
    monkeypatch.setattr(win.mgr, "view", lambda _r: vista)
    tela.respostas[f"Trancamento de '{NOME}'"] = "show"
    win._resolve(rec.id)
    pergunta = tela.pergunta(f"Trancamento de '{NOME}' interrompido")
    assert pergunta["text"].startswith("Texto do gerente.")
    assert "NÃO estão guardados" in pergunta["text"]
    assert "Seus arquivos já estão guardados" not in pergunta["text"]
    assert pergunta["details"] == rec.pending
    assert pergunta["details_open"]
    assert pergunta["buttons"] == ["cont", "undo", "show", "forget", "close"]
    assert ("explorer", rec.path) in tela.dialogos
    # quando o texto do gerente já fala dos itens novos, o aviso não se repete
    tela.perguntas.clear()
    vista.attention = (
        "O trancamento não terminou. 1 item(ns) foram colocados na pasta durante o trancamento "
        "e NÃO estão guardados: Planilha nova.xlsx."
    )
    win._resolve(rec.id)
    texto = tela.pergunta(f"Trancamento de '{NOME}' interrompido")["text"]
    assert texto == vista.attention


class _CopiaOcupada(QWidget):
    """Cópia criptografada (falsa) com um trabalho rodando e o ``bloquear`` do contrato C1."""

    def __init__(self) -> None:
        super().__init__()
        self.runner = SimpleNamespace(busy=True)
        self.bloqueios = 0

    def bloquear(self) -> None:
        self.bloqueios += 1
        self.hide()


@gui
def test_bloquear_fecha_a_copia_criptografada_e_apaga_a_senha(
    abrir_tela: Callable[..., Tela],
) -> None:
    """fluxos-8 / perfil-1 (contrato C1): a janela da Cópia continuava aberta e utilizável depois
    do bloqueio, com o caminho e a senha digitada (que "Mostrar" revelava)."""
    tela = abrir_tela()
    win = _pronta(tela)
    win._open_copy_tool()
    copia = win._copy_window
    assert copia is not None and copia.isVisible()
    copia.r_senha.setText("SenhaDaCopia-Teste-91")  # type: ignore[attr-defined]
    win._watcher.last = time.monotonic() - IDLE_LOCK_SECONDS - 1
    win._idle_check()  # 5 min sem uso
    assert win.session is None
    assert copia.r_senha.text() == ""  # type: ignore[attr-defined]
    assert not copia.isVisible()
    assert win._copy_window is None  # parada: fechada e descartada
    _descarta()
    assert not shiboken6.isValid(copia)


@gui
def test_bloquear_com_a_copia_trabalhando_bloqueia_ja_e_espera_ela_parar(
    abrir_tela: Callable[..., Tela],
) -> None:
    tela = abrir_tela()
    win = _pronta(tela)
    copia = _CopiaOcupada()
    copia.show()
    win._copy_window = copia
    win._watcher.last = time.monotonic() - IDLE_LOCK_SECONDS - 1
    win._idle_check()  # a Cópia trabalhando conta como uso: não interrompe o trabalho dela
    assert win.session is not None and copia.bloqueios == 0
    liberar = threading.Event()
    assert win._run(lambda _p, _c: liberar.wait(10), lambda _r: None)
    win.lock_now()  # Win+L com um trabalho desta janela rodando
    assert copia.bloqueios == 1  # a Cópia é bloqueada JÁ (a senha dela não espera)
    assert win.session is not None  # a principal espera o próprio trabalho
    assert win._copy_window is copia  # a referência fica até ela parar e fechar
    liberar.set()
    _espera(lambda: win.session is None)
    assert not win._close_copy_window()  # ainda parando: não é destruída no meio
    copia.runner.busy = False
    assert win._close_copy_window()
    assert win._copy_window is None


@gui
def test_bloquear_destroi_os_dialogos_com_nomes(abrir_tela: Callable[..., Tela]) -> None:
    """fluxos-9: diálogos ocultos (progresso, perguntas) guardavam nomes de pastas e arquivos
    depois do bloqueio e se acumulavam a cada operação."""
    tela = abrir_tela()
    win = _pronta(tela)
    for _ in range(3):
        assert win._run(lambda _p, _c: None, lambda _r: None, title=f"Abrindo '{NOME}'")
        _espera(lambda: not win.runner.busy)
        _descarta()
    assert win.findChildren(QDialog) == []  # não se acumulam
    caixa = folder_dialogs.ChoiceDialog(
        win, f"Trancar '{NOME}'?", f"Desde que você abriu '{NOME}'…", [("OK", "ok")]
    )
    assert not caixa.isVisible()  # como depois de um exec()
    win.lock_now()
    _descarta()
    assert not shiboken6.isValid(caixa)
    assert win.findChildren(QDialog) == []
    assert not [t for t in _textos(win) if NOME in t]


@gui
def test_nova_senha_mestra_com_pin_desativado_pede_a_senha_mestra(
    abrir_tela: Callable[..., Tela],
) -> None:
    """perfil-3 / fluxos-10: com o PIN desativado no meio de "Criar nova senha mestra", a tela
    continuava pedindo o PIN (que não funcionava mais) e escondia "Usar a senha mestra"."""
    tela = abrir_tela()
    win = tela.win
    _criar_perfil(tela).close()
    win._show_unlock()
    win._request_new_master()
    page = win.unlock_page
    assert not page.master
    assert "nova senha mestra" in page.text.text()
    for _ in range(5):
        _envia(tela, PIN_ERRADO)
    assert not tela.store.pin_available()
    assert page.master  # agora pede a senha mestra
    assert not win._wants_new_master
    assert "PIN foi desativado" in page.text.text()
    assert "PIN incorreto muitas vezes" in page.err.text()
    _envia(tela, SENHA_MESTRA)
    assert win.session is not None


@gui
@pytest.mark.parametrize("falhou", [False, True])
def test_recuperar_versao_anterior_mostra_falhas_e_nao_abre_explorer_bloqueado(
    abrir_tela: Callable[..., Tela],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    falhou: bool,
) -> None:
    """estados-12: "Versão anterior recuperada" mesmo com arquivos que falharam. fluxos-11: o
    Explorer abria na pasta recuperada (legível) depois de o app bloquear com o aviso na tela."""
    tela = abrir_tela()
    win, rec = _destravada_com_pasta(tela, tmp_path)
    assert win.mgr is not None
    destino = tmp_path / "destino"
    destino.mkdir()
    monkeypatch.setattr(owl_window, "choose_folder", lambda *_a, **_k: str(destino))
    alvo = winfs.to_extended(str(destino / f"{NOME} (versão anterior)"))
    relatorio = RestoreReport(alvo, "ok", restored=1)
    if falhou:
        relatorio.failed.append("b.txt: dado criptografado ausente ou truncado")
    monkeypatch.setattr(win.mgr, "restore_kept", lambda *_a, **_k: [relatorio])
    avisos: list[tuple[str, str, list[str]]] = []

    def inform(_p: object, title: str, text: str = "", details: Any = (), **_k: object) -> None:
        avisos.append((title, text, list(details)))
        if falhou:
            win.lock_now()  # 5 min sem uso (ou Win+L) com o aviso na tela

    monkeypatch.setattr(owl_window, "inform", inform)
    win._restore_kept(rec.id)
    _espera(lambda: not win.runner.busy and bool(avisos))
    _descarta()
    titulo, texto, detalhes = avisos[0]
    explorer = [d for d in tela.dialogos if d[0] == "explorer"]
    if falhou:
        assert titulo == "Nem todos os arquivos foram recuperados"
        assert detalhes == ["b.txt: dado criptografado ausente ou truncado"]
        assert "1 arquivo(s) não puderam ser recuperados" in texto
        assert explorer == []  # bloqueou: nada de abrir a pasta legível
    else:
        assert titulo == "Versão anterior recuperada"
        assert detalhes == [f"{winfs.strip_extended(alvo)}: 1 arquivo(s)"]  # sem \\?\
        assert explorer == [("explorer", alvo)]


@gui
@pytest.mark.parametrize("esconde_falha", [False, True])
def test_trancar_e_esconder_esconde_mesmo_depois_de_continuar(
    abrir_tela: Callable[..., Tela],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    esconde_falha: bool,
) -> None:
    """estados-15: com o trancamento parado na etapa 4, "Continuar trancando" terminava sem
    esconder; e uma falha ao esconder era engolida ("'X' está trancada.")."""
    tela = abrir_tela()
    win, rec = _destravada_com_pasta(tela, tmp_path)
    mgr = win.mgr
    assert mgr is not None

    def lock(folder_id: str, *_a: Any, **_k: Any) -> LockOutcome:
        rec.state = APAGANDO
        rec.pending = ["nota.txt: em uso"]
        return LockOutcome(rec, complete=False, pending=list(rec.pending))

    def continua(folder_id: str, *_a: Any, **_k: Any) -> LockOutcome:
        rec.state = TRANCADA
        rec.pending = []
        return LockOutcome(rec, complete=True)

    escondidas: list[str] = []

    def hide(folder_id: str) -> None:
        if esconde_falha:
            raise OSError("acesso negado (simulado)")
        escondidas.append(folder_id)

    monkeypatch.setattr(mgr, "lock", lock)
    monkeypatch.setattr(mgr, "continue_lock", continua)
    monkeypatch.setattr(mgr, "hide", hide)
    _com_vista(win, monkeypatch, rec, APAGANDO)
    tela.respostas[f"Trancamento de '{NOME}'"] = "cont"
    win._on_row_action(rec.id, "lock_hide")
    _espera_fila(win, lambda: rec.state == TRANCADA)
    _descarta()
    assert tela.pergunta(f"Trancamento de '{NOME}' interrompido")
    if esconde_falha:
        assert "não foi possível escondê-la" in win.home.notice.text()
        assert "acesso negado" in win.home.notice.text()
    else:
        assert escondidas == [rec.id]
        assert win.home.notice.text() == f"'{NOME}' está trancada."
    assert rec.id not in win._hide_after


# --------------------------------------------------------------------- rodada verifica2-janela


def _enter(tela: Tela) -> Callable[[], str]:
    """Responde como a tecla Enter: o botão padrão da última pergunta (``primary`` ou o 1º)."""

    def responde() -> str:
        p = tela.perguntas[-1]
        return str(p.get("primary") or p["buttons"][0])

    return responde


def _legiveis(pasta: Path) -> list[str]:
    return sorted(n for n in os.listdir(pasta) if n.endswith(".txt")) if pasta.exists() else []


@gui
@pytest.mark.parametrize("resposta", ["enter", "quit"])
@pytest.mark.parametrize("variante", ["restaurando", "renomeada"])
def test_trancar_e_sair_com_pasta_que_precisa_de_atencao_so_sai_se_pedirem(
    abrir_tela: Callable[..., Tela], tmp_path: Path, variante: str, resposta: str
) -> None:
    """JAN-1: T11 com uma pasta que dá para trancar (B) e outra que precisa de atenção (A, com
    cópias legíveis). 'Trancar e sair' (o padrão, Enter) trancava B e SAÍA, deixando A legível
    sem a pessoa escolher 'Sair sem trancar'. Agora A entra no resumo do fim."""
    tela = abrir_tela()
    win = _pronta(tela)
    pa, ra = _protegida(win, tmp_path / "pastas", "Pasta A", 6)
    _pb, rb = _protegida(win, tmp_path / "pastas", "Pasta B", 2)
    mgr = win.mgr
    assert mgr is not None
    mgr.unlock(rb.id)
    if variante == "restaurando":  # abertura de A cancelada no meio
        token = CancelToken()
        with pytest.raises(CancelledError):
            mgr.unlock(ra.id, _CancelaDepois(token, 2), token)
        assert ra.state == RESTAURANDO
        local_a = pa
    else:  # A aberta e renomeada no Explorer
        mgr.unlock(ra.id)
        local_a = pa.with_name("Pasta A renomeada")
        pa.rename(local_a)
    legiveis = _legiveis(local_a)
    assert legiveis
    win._refresh()
    tela.respostas["Sair do Owl Vault?"] = _enter(tela)
    tela.respostas["Não deu para trancar"] = _enter(tela) if resposta == "enter" else "quit"
    assert not win.close()
    t11 = tela.pergunta("Sair do Owl Vault?")
    assert t11["buttons"] == ["lock", "quit", "cancel"]
    assert t11["primary"] == "lock"
    _espera_fila(win, lambda: any(p["title"].startswith("Não deu") for p in tela.perguntas))
    _descarta()
    assert rb.state == TRANCADA  # a que dava para trancar foi trancada
    resumo = tela.pergunta("Não deu para trancar 'Pasta A'")
    assert resumo["buttons"] == ["cancel", "quit"]  # [Voltar ao Owl Vault] [Sair sem trancar]
    assert resumo["primary"] == "cancel"  # Enter NÃO sai deixando A legível
    assert resumo["text"].startswith("1 pasta(s) foram trancadas.")
    assert "'Resolver…'" in resumo["text"]  # as saídas que o texto cita ficam na lista
    assert win._quitting == (resposta == "quit")
    assert _legiveis(local_a) == legiveis  # nada foi apagado de A
    if resposta == "enter":
        assert win.session is not None
        assert win.pages.currentWidget() is win.home
        assert len([p for p in tela.perguntas if p["title"] == "Sair do Owl Vault?"]) == 1


def _modal_e_ausencia(win: OwlWindow, sessao: list[object]) -> None:
    """Uma pergunta modal de verdade na tela e 10 min sem uso: roda o timer de inatividade."""
    caixa = QDialog(win)
    caixa.open()
    assert QApplication.activeModalWidget() is caixa
    win._watcher.last = time.monotonic() - IDLE_LOCK_SECONDS - 300
    win._idle_check()
    sessao.append(win.session)
    caixa.deleteLater()


@gui
@pytest.mark.parametrize("onde", ["resumo", "t7"])
def test_inatividade_trava_com_pergunta_do_trancar_e_sair_na_tela(
    abrir_tela: Callable[..., Tela], tmp_path: Path, monkeypatch: pytest.MonkeyPatch, onde: str
) -> None:
    """JAN-2: com o resumo "Não deu para trancar…" (ou o T7) do 'Trancar e sair' na tela, o
    travamento automático ficava desligado: a pessoa saía de perto e o app ficava destravado,
    com o nome da pasta na tela, sem prazo."""
    tela = abrir_tela()
    win = _pronta(tela)
    _pa, ra = _protegida(win, tmp_path / "pastas", "Pasta Quati", 2)
    mgr = win.mgr
    assert mgr is not None
    mgr.unlock(ra.id)
    win._refresh()
    # entre um trancamento e o próximo da fila (sem pergunta na tela) não trava no meio
    win._quit_sequence = True
    win._watcher.last = time.monotonic() - IDLE_LOCK_SECONDS - 300
    win._idle_check()
    assert win.session is not None
    win._quit_sequence = False
    win._watcher.last = time.monotonic()
    if onde == "resumo":

        def em_uso(_fid: str, *_a: Any, **_k: Any) -> LockOutcome:
            raise PreflightError("Não é possível proteger esta pasta.", ["doc 0.txt: em uso"])

        monkeypatch.setattr(mgr, "lock", em_uso)
        titulo = "Não deu para trancar 'Pasta Quati'"
    else:
        monkeypatch.setattr(mgr, "missing_since_open", lambda _f: ["doc 1.txt"])
        titulo = "Trancar 'Pasta Quati'?"
    sessao: list[object] = []

    def pergunta() -> str:
        _modal_e_ausencia(win, sessao)
        return ""  # a caixa de verdade foi rejeitada pelo bloqueio

    tela.respostas["Sair do Owl Vault?"] = "lock"
    tela.respostas[titulo] = pergunta
    assert not win.close()
    _espera_fila(win, lambda: bool(sessao))
    _descarta()
    assert sessao == [None]  # travou com a pergunta na tela
    assert win.session is None and win.mgr is None
    assert win.pages.currentWidget() is win.unlock_page
    assert not win._quit_sequence and not win._quitting
    assert "Pasta Quati" not in win.home.notice.text()
    assert ra.state == ABERTA  # nada foi trancado nem apagado pela metade


@gui
def test_bloqueio_durante_parar_e_fechar_trava_antes_da_pergunta_de_sair(
    abrir_tela: Callable[..., Tela], tmp_path: Path
) -> None:
    """JAN-3: X → 'Parar e fechar' e, com o trabalho ainda parando, Win+L/suspensão. O pedido de
    bloqueio se perdia: o T11 aparecia com os nomes e, com Cancelar, o app voltava destravado."""
    tela = abrir_tela()
    win, _rec = _destravada_com_pasta(tela, tmp_path)  # 'aberta': há o que perguntar ao sair
    liberar = threading.Event()
    fim: list[object] = []
    assert win._run(lambda _p, _c: liberar.wait(10), fim.append, title=f"Abrindo '{NOME}'")
    tela.respostas["Há uma operação em andamento"] = "stop"
    assert not win.close()
    assert win._quit_after_job
    win.lock_now()  # Win+L / suspensão com o trabalho ainda indo até o ponto seguro
    assert win._lock_after_job and win.session is not None
    antes = len(tela.perguntas)
    liberar.set()
    _espera(lambda: not win.runner.busy)
    _descarta()
    assert fim == [True]
    assert win.session is None and win.mgr is None
    assert win.pages.currentWidget() is win.unlock_page
    assert not win._lock_after_job and not win._quit_after_job
    sair = [p for p in tela.perguntas[antes:] if p["title"] == "Sair do Owl Vault?"]
    assert len(sair) == 1
    assert sair[0]["buttons"] == ["quit", "cancel"]  # travado: só a contagem, pede o PIN
    assert "Há 1 pasta aberta" in sair[0]["text"]
    assert NOME not in sair[0]["text"] and not sair[0].get("details")
    assert not win._quitting  # respondeu Cancelar: continua aberto, mas BLOQUEADO


@gui
def test_bloqueio_pedido_durante_recuperar_versao_anterior_vem_antes_do_aviso(
    abrir_tela: Callable[..., Tela], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """JAN-4: Win+L durante 'Recuperando a versão anterior': o aviso com os caminhos aparecia
    com o app destravado e, no OK, o Explorer abria a pasta decifrada; só então bloqueava."""
    tela = abrir_tela()
    win, rec = _destravada_com_pasta(tela, tmp_path)
    assert win.mgr is not None
    destino = tmp_path / "destino"
    destino.mkdir()
    monkeypatch.setattr(owl_window, "choose_folder", lambda *_a, **_k: str(destino))
    alvo = winfs.to_extended(str(destino / f"{NOME} (versão anterior)"))
    liberar = threading.Event()

    def lento(*_a: Any, **_k: Any) -> list[RestoreReport]:
        liberar.wait(10)
        return [RestoreReport(alvo, "ok", restored=1)]

    monkeypatch.setattr(win.mgr, "restore_kept", lento)
    win._restore_kept(rec.id)
    assert win.runner.busy
    win.lock_now()  # Win+L / suspensão durante o trabalho: fica para o fim dele
    assert win._lock_after_job
    antes = len(tela.perguntas)
    liberar.set()
    _espera(lambda: not win.runner.busy)
    _descarta()
    assert win.session is None and win.pages.currentWidget() is win.unlock_page
    assert tela.perguntas[antes:] == []  # nem o aviso com os caminhos
    assert [d for d in tela.dialogos if d[0] == "explorer"] == []  # nem o Explorer


@gui
def test_bloqueio_pedido_durante_a_abertura_nao_abre_o_explorer(
    abrir_tela: Callable[..., Tela], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """JAN-4 (outros fins de trabalho): a pasta aberta não aparece no Explorer depois do Win+L,
    e o aviso "'<Nome>' está aberta" não fica na lista escondida."""
    tela = abrir_tela()
    win, rec = _destravada_com_pasta(tela, tmp_path, TRANCADA)
    mgr = win.mgr
    assert mgr is not None
    vista = FolderView(rec, "Trancada", "abrir", base_action="abrir")
    monkeypatch.setattr(mgr, "view", lambda _r: vista)
    liberar = threading.Event()

    def lento(folder_id: str, *_a: Any, **_k: Any) -> UnlockOutcome:
        liberar.wait(10)
        rec.state = ABERTA
        return UnlockOutcome(rec, True, None, rec.path)

    monkeypatch.setattr(mgr, "unlock", lento)
    win._open_folder(rec.id)
    assert win.runner.busy
    win.lock_now()
    liberar.set()
    _espera(lambda: not win.runner.busy)
    _descarta()
    assert win.session is None
    assert [d for d in tela.dialogos if d[0] == "explorer"] == []
    assert NOME not in win.home.notice.text()


@gui
def test_bloqueio_pedido_durante_o_desbloqueio_descarta_a_sessao_nova(
    abrir_tela: Callable[..., Tela], monkeypatch: pytest.MonkeyPatch
) -> None:
    """JAN-4: com o bloqueio pedido enquanto o PIN é conferido, a sessão nova não é adotada (o
    bloqueio vale mais) e é fechada."""
    tela = abrir_tela()
    win = tela.win
    _criar_perfil(tela).close()
    win._show_unlock()
    real = win.store.unlock_with_pin
    liberar = threading.Event()
    sessoes: list[profile_mod.ProfileSession] = []

    def lento(pin: str) -> profile_mod.ProfileSession:
        liberar.wait(10)
        s = real(pin)
        sessoes.append(s)
        return s

    monkeypatch.setattr(win.store, "unlock_with_pin", lento)
    win.unlock_page.edit.setText(PIN)
    win.unlock_page._submit()
    assert win.runner.busy
    win.lock_now()
    liberar.set()
    _espera(lambda: not win.runner.busy)
    _descarta()
    assert len(sessoes) == 1
    assert win.session is None and win.mgr is None
    assert win.pages.currentWidget() is win.unlock_page
    with pytest.raises(OwlVaultError):
        _ = sessoes[0].index  # fechada: as chaves foram descartadas


PIN_NOVO = "961473"


class _AlterarPinFalso:
    """ChangePinDialog que não abre nada: confirma com ``atual`` e ``novo``."""

    atual = PIN
    novo = PIN_NOVO

    def __init__(self, _parent: object) -> None:
        pass

    def exec(self) -> QDialog.DialogCode:
        return QDialog.DialogCode.Accepted

    def take(self) -> tuple[str, str, bool]:
        return type(self).atual, type(self).novo, False


@gui
def test_bloqueio_pedido_ao_alterar_o_pin_avisa_que_o_pin_mudou(
    abrir_tela: Callable[..., Tela], monkeypatch: pytest.MonkeyPatch
) -> None:
    """JAN-4: o PIN muda no disco mesmo com o bloqueio pedido no meio; a tela travada diz isso
    (sem nomes), para a pessoa não gastar tentativas com o PIN antigo."""
    tela = abrir_tela()
    win = tela.win
    win._unlocked(_criar_perfil(tela))
    monkeypatch.setattr(owl_window, "ChangePinDialog", _AlterarPinFalso)
    real = win.store.unlock_with_pin
    liberar = threading.Event()

    def lento(pin: str) -> profile_mod.ProfileSession:
        liberar.wait(10)
        return real(pin)

    monkeypatch.setattr(win.store, "unlock_with_pin", lento)
    win._change_pin()
    assert win.runner.busy
    win.lock_now()
    liberar.set()
    _espera(lambda: not win.runner.busy)
    _descarta()
    assert win.session is None and win.pages.currentWidget() is win.unlock_page
    aviso = tela.pergunta("PIN alterado")
    assert aviso["text"] == "Para entrar, use o PIN novo."
    monkeypatch.setattr(win.store, "unlock_with_pin", real)
    win.store.unlock_with_pin(PIN_NOVO).close()  # o PIN novo vale


@gui
def test_seletor_aberto_no_bloqueio_nao_comeca_a_recuperar_a_versao_anterior(
    abrir_tela: Callable[..., Tela], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """JAN-5: o seletor de pastas nativo não fecha com o bloqueio. Uma pasta escolhida depois
    dele iniciava o trabalho com o app travado (e um erro aparecia sobre a tela do PIN)."""
    tela = abrir_tela()
    win, rec = _destravada_com_pasta(tela, tmp_path)
    assert win.mgr is not None
    destino = tmp_path / "destino"
    destino.mkdir()
    chamadas: list[object] = []
    monkeypatch.setattr(win.mgr, "restore_kept", lambda *a, **_k: chamadas.append(a) or [])

    def seletor(*_a: Any, **_k: Any) -> str:
        win.lock_now()  # Win+L / 5 min sem uso com o seletor aberto
        return str(destino)  # alguém escolhe uma pasta depois do bloqueio

    monkeypatch.setattr(owl_window, "choose_folder", seletor)
    win._restore_kept(rec.id)
    _descarta()
    assert not win.runner.busy
    assert chamadas == []
    assert win.session is None and win.pages.currentWidget() is win.unlock_page
    assert tela.perguntas == []  # nada de "Não foi possível concluir" na tela travada
    assert list(destino.iterdir()) == []


@gui
def test_proteger_seletor_que_volta_depois_do_bloqueio_nao_guarda_o_caminho(
    abrir_tela: Callable[..., Tela], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """JAN-6: '+ Proteger uma pasta…' > Escolher com o app bloqueando no meio: o caminho (com o
    nome da pasta) ficava no campo oculto e na dica da tela Proteger da janela travada."""
    tela = abrir_tela()
    win = _pronta(tela)
    pasta = tmp_path / "pastas" / NOME
    pasta.mkdir(parents=True)
    win._protect()
    assert win.pages.currentWidget() is win.protect_page

    def seletor(*_a: Any, **_k: Any) -> str:
        win.lock_now()
        return str(pasta)

    monkeypatch.setattr(componentes, "choose_folder", seletor)
    win.protect_page.campo.botao.click()
    _descarta()
    assert win.session is None and win.pages.currentWidget() is win.unlock_page
    assert win.protect_page._path == ""
    assert win.protect_page.campo.texto() == ""
    assert not [w for w in win.findChildren(QLineEdit) if NOME in w.text()]
    assert not [w for w in win.findChildren(QWidget) if NOME in w.toolTip()]
    assert not [t for t in _textos(win) if NOME in t]
    assert not win.runner.busy  # nenhuma conferência começou


@gui
def test_proteger_depois_de_bloquear_recusa_caminho_ate_comecar_de_novo(
    proteger: protect_flow.ProtectPage,
) -> None:
    page = proteger
    caminho = "C:\\Sintetico\\Pastas\\" + NOME
    page.clear()  # o app bloqueou
    page.set_path(caminho)
    assert page._path == ""
    assert page.campo.texto() == ""
    assert not page.rodape.primario.isEnabled()
    page.start(first_time=False)  # desbloqueou e abriu "Proteger uma pasta" de novo
    page.set_path(caminho)
    assert page.campo.texto() == caminho
    assert page.rodape.primario.isEnabled()


@gui
@pytest.mark.parametrize(
    ("issue", "titulo"),
    [
        ("versao_anterior", f"Versão anterior de '{NOME}'"),
        ("versao_anterior_ilegivel", f"Versão anterior de '{NOME}'"),
        ("senha_antiga", f"Atualizar '{NOME}'"),
    ],
)
def test_resolver_da_versao_anterior_e_da_senha_antiga_tem_tirar_da_lista(
    abrir_tela: Callable[..., Tela],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    issue: str,
    titulo: str,
) -> None:
    """JAN-7 (T8: "Todo Resolver tem [Tirar da lista]"): faltava nestes três."""
    tela = abrir_tela()
    win, rec = _destravada_com_pasta(tela, tmp_path, TRANCADA)
    assert win.mgr is not None
    _versao_mantida(rec, tmp_path / "area" / "anterior-0123456789abcdef", existe=True)
    _com_vista(win, monkeypatch, rec, issue)
    monkeypatch.setattr(win.mgr, "kept_only_files", lambda _fid: ["a.txt"])
    tela.respostas[titulo] = "forget"
    win._resolve(rec.id)
    pergunta = tela.pergunta(titulo)
    assert pergunta["buttons"][-2:] == ["forget", "close"]
    # a escolha leva à confirmação de 'Tirar da lista' (padrão Cancelar), com o aviso do gerente
    confirmacao = tela.pergunta(f"Tirar '{NOME}' da lista?")
    assert confirmacao["primary"] == "cancel"
    assert win.session is not None and win.session.index.folder(rec.id) is rec  # cancelou


SM_UNICA = "frase mestra so deste teste 5521"


def _closures_com_segredo(segredos: tuple[str, ...], dono: str) -> list[str]:
    """Funções vivas (de ``dono``) cuja closure guarda um dos segredos, direto ou numa caixa
    ``_Segredo`` que ainda não foi esvaziada."""
    gc.collect()
    achados: list[str] = []
    for o in gc.get_objects():
        if not isinstance(o, types.FunctionType) or dono not in o.__qualname__:
            continue
        for cell in o.__closure__ or ():
            try:
                v = cell.cell_contents
            except ValueError:
                continue
            if isinstance(v, str) and any(s in v for s in segredos):
                achados.append(o.__qualname__)
            elif isinstance(v, owl_window._Segredo) and v._valor:
                achados.append(f"{o.__qualname__} (caixa cheia)")
    return achados


PIN_NOVO_2 = "583920"


@gui
def test_senha_mestra_e_pin_nao_ficam_no_trabalho_depois_de_bloquear(
    abrir_tela: Callable[..., Tela], monkeypatch: pytest.MonkeyPatch
) -> None:
    """JAN-8 (parte da janela): o JobRunner mantém vivo o trabalho de cada operação; a função
    do desbloqueio guardava a senha mestra ou o PIN digitado, alcançáveis depois de bloquear.
    Também o PIN novo de 'Alterar PIN' quando o PIN atual está errado (o trabalho falha antes
    de usá-lo)."""
    tela = abrir_tela()
    win = tela.win
    tela.store.create(SM_UNICA, PIN_NOVO, params=TESTING_PARAMS).close()
    win._show_unlock()
    win.unlock_page.configure(master=True)
    _envia(tela, SM_UNICA)
    assert win.session is not None
    win.lock_now()
    _envia(tela, PIN_NOVO)
    assert win.session is not None
    falso = type("AlterarPinErrado", (_AlterarPinFalso,), {"atual": PIN, "novo": PIN_NOVO_2})
    monkeypatch.setattr(owl_window, "ChangePinDialog", falso)
    win._change_pin()  # PIN atual errado: falha antes de gravar o novo
    _espera(lambda: not win.runner.busy)
    assert tela.pergunta("PIN incorreto")
    win.lock_now()
    _descarta()
    assert win.session is None
    assert _closures_com_segredo((SM_UNICA, PIN_NOVO, PIN_NOVO_2), "OwlWindow.") == []


@gui
def test_verificar_recusa_cofre_que_nao_e_o_registrado(
    abrir_tela: Callable[..., Tela], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """estados-9 (parte da janela): 'Verificar arquivos' dizia "Tudo certo" sobre um cofre
    trocado (backup antigo copiado por cima), que não é o registrado."""
    tela = abrir_tela()
    win, rec = _destravada_com_pasta(tela, tmp_path, TRANCADA)
    _com_vista(win, monkeypatch, rec, COFRE_DIFERENTE)  # o gerente vê o cofre trocado
    win._verify(rec.id)
    assert not win.runner.busy  # nada é conferido
    pergunta = tela.pergunta("Os dados não são os registrados")
    assert pergunta["text"].startswith("Atenção sintética")  # o texto do gerente
    assert "Nada foi verificado" in pergunta["text"]
    # e a linha tem saída: o ⋯ oferece Procurar e Tirar da lista (issue desconhecida, C4)
    menu = pages.row_menu(win.mgr.view(rec))  # type: ignore[union-attr]
    assert PROCURAR in menu and TIRAR in menu


@gui
def test_lista_com_nome_longo_nunca_esconde_botoes_e_menu(qapp: QApplication) -> None:
    """visual-2: nome longo (ou "Aberta — visível…" numa janela estreita) empurrava o botão e o
    ⋯ de TODAS as linhas para fora da lista, sem rolagem horizontal."""
    home = pages.HomePage()
    longo = "Relatórios trimestrais da diretoria financeira " * 3
    views = [
        FolderView(_registro(ABERTA, name=longo), "Aberta — visível neste computador", "trancar",
                   base_action="trancar"),
        FolderView(_registro(TRANCADA, name="Contratos"), "Trancada", "abrir",
                   base_action="abrir"),
        FolderView(_registro(TRANCADA, name="Fotos"), "Precisa de atenção", "resolver",
                   "A pasta 'Fotos' não está mais em C:\\Users\\Ana\\Documentos\\Particular\\"
                   "Uma pasta com um nome bem comprido\\Fotos (foi movida, renomeada ou "
                   "substituída).", issue="nao_encontrada"),
    ]  # fmt: skip
    home.set_rows(views, lambda _f, _a: None)
    home.resize(760, 640)
    home.show()
    _descarta()
    vp = home.list_area.viewport()
    linhas = home.findChildren(pages.FolderRow)
    assert len(linhas) == 3
    for row in linhas:
        for b in (row.button, row.more):
            assert b is not None
            direita = b.mapTo(vp, QPoint(b.width(), 0)).x()
            assert direita <= vp.width(), (b.text(), direita, vp.width())
    nome = next(lbl for lbl in _por_nome(linhas[0], "linhaNome"))
    assert nome.text().endswith("…")  # cortado no fim, inteiro na dica
    assert nome.toolTip() == longo
    assert nome.accessibleName() == longo
    home.hide()
    home.deleteLater()
    _descarta()


@gui
def test_desbloqueio_pratica_botoes_um_embaixo_do_outro(qapp: QApplication) -> None:
    """visual-6: 'Criar nova senha mestra' e 'Usar o PIN desta vez' lado a lado não cabiam no
    cartão de 460 px e o primeiro saía cortado dos dois lados."""
    page = pages.UnlockPage()
    page.configure(master=True, practice=True)
    for _ in range(3):
        page.fail("Senha mestra incorreta.")
    page.resize(980, 700)
    page.show()
    _descarta()
    assert not page.extra.isHidden()
    for b in (page.new_master, page.once):
        assert b.width() >= b.sizeHint().width(), b.text()
    assert page.once.y() > page.new_master.y()  # um embaixo do outro
    page.hide()
    page.deleteLater()
    _descarta()


@gui
def test_trocar_tema_repinta_sombras_e_marca_o_tema_no_menu(
    abrir_tela: Callable[..., Tela], monkeypatch: pytest.MonkeyPatch
) -> None:
    """visual-10 (C6, janela principal) e visual-11: a sombra dos cartões (inclusive de diálogos
    já montados) segue o tema novo; ☰ > Tema mostra qual está em uso."""
    gravados: list[str] = []
    monkeypatch.setattr(owl_window, "save_theme", gravados.append)  # nada vai para o registro
    tela = abrir_tela()
    win = _pronta(tela)
    assert win._run(lambda _p, c: c.cancelled or time.sleep(0.2), lambda _r: None, title="X")
    menu = win.theme_menu
    acoes = [a for a in menu.actions() if not a.isSeparator()]
    assert [a.text() for a in acoes] == ["Escuro", "Claro"]
    assert all(a.isCheckable() for a in acoes)
    grupo = acoes[0].actionGroup()
    assert grupo is not None and grupo.isExclusive() and acoes[1].actionGroup() is grupo
    assert "QMenu::indicator" in menu.styleSheet()  # a marca aparece (o app esconde)
    try:
        win._set_theme("light")
        _descarta()
        assert gravados == ["light"]
        assert [a.isChecked() for a in acoes] == [False, True]
        cor = QColor(current_tokens()["sombra"])
        efeitos = [
            w.graphicsEffect()
            for w in win.findChildren(QWidget)
            if isinstance(w.graphicsEffect(), QGraphicsDropShadowEffect)
        ]
        assert efeitos  # cartões da janela e da tela de progresso
        assert all(e.color() == cor for e in efeitos)  # type: ignore[union-attr]
    finally:
        win._set_theme("dark")
        _descarta()
    assert [a.isChecked() for a in acoes] == [True, False]
    _espera(lambda: not win.runner.busy)


_TELA_PEQUENA = r"""
import json, os, sys, tempfile
from pathlib import Path
from PySide6.QtCore import QCoreApplication, QEvent
from PySide6.QtWidgets import QAbstractButton, QApplication, QLabel, QScrollArea
from owl_vault.application.protection import ProtectedPaths
from owl_vault.crypto.kdf import TESTING_PARAMS, TESTING_POLICY
from owl_vault.ui import owl_window
from owl_vault.ui.theme import apply_theme

owl_window.saved_theme = lambda: "dark"
owl_window.save_theme = lambda _k: None
real = owl_window.LockerManager
def gerente(session, **kw):
    kw["protected"] = ProtectedPaths.none()
    kw["known_folders"] = {}
    return real(session, **kw)
owl_window.LockerManager = gerente
app = QApplication([])
apply_theme(app, "dark")
def pump():
    for _ in range(8):
        QCoreApplication.processEvents()
        QCoreApplication.sendPostedEvents(None, int(QEvent.Type.DeferredDelete.value))
win = owl_window.OwlWindow(("C:\\Windows\\notepad.exe", ""), policy=TESTING_POLICY,
                           profile_dir=Path(sys.argv[1]))
area = app.primaryScreen().availableGeometry()
out = {"area": [area.width(), area.height()], "min": list(win.minimumSize().toTuple()),
       "hint": list(win.minimumSizeHint().toTuple()), "size": list(win.size().toTuple()),
       "pos": list(win.pos().toTuple()), "cabe": win.fits_screen(), "cortes": []}
def em_rolagem(w):
    p = w.parentWidget()
    while p is not None:
        if isinstance(p, QScrollArea):
            return True
        p = p.parentWidget()
    return False
def cortes(rot):
    pump()
    for w in win.findChildren(QLabel) + win.findChildren(QAbstractButton):
        if not w.isVisible() or em_rolagem(w) or not w.text() or w.objectName() == "mais":
            continue
        quer = (w.heightForWidth(w.width()) if isinstance(w, QLabel) and w.wordWrap()
                else w.minimumSizeHint().height())
        if w.height() < quer or (isinstance(w, QAbstractButton)
                                 and w.width() < w.sizeHint().width()):
            out["cortes"].append([rot, w.text()[:40], w.size().toTuple()])
    rod = win.rodapes.currentWidget()
    if rod.mapTo(win, rod.rect().bottomLeft()).y() > win.height():
        out["cortes"].append([rot, "rodapé fora da janela"])
win.resize(win.minimumSize())
win.show()
cortes("assistente-1")
win.setup_page._ir(1)
cortes("assistente-2")
win.store.create("cavalo correto bateria grampo", "947361", params=TESTING_PARAMS).close()
win._show_unlock()
cortes("pin")
win.unlock_page.configure(master=True, practice=True)
for _ in range(3):
    win.unlock_page.fail("Senha mestra incorreta.")
cortes("pratica")
win._unlocked(win.store.unlock_with_pin("947361"))
win.home.set_notice("Uma frase de aviso na lista, comprida o bastante para quebrar a linha.")
cortes("lista")
win._protect()
cortes("proteger")
print(json.dumps(out))
"""


@gui
def test_janela_cabe_na_tela_de_notebook_e_nada_fica_espremido(tmp_path: Path) -> None:
    """visual-3 / visual-5: em 1366x768 a 125% (1093x614 lógicos) a janela abria maior que a
    área útil (rodapé com o botão principal atrás da barra de tarefas), e o mínimo fixo
    (760x580) era menor que o layout: lateral e textos espremidos, link do rodapé cortado."""
    cfg = tmp_path / "tela.json"
    tela = {"name": "N", "x": 0, "y": 0, "width": 1093, "height": 614, "logicalDpi": 96,
            "logicalBaseDpi": 96, "dpr": 1.0}  # fmt: skip
    cfg.write_text(json.dumps({"screens": [tela]}), encoding="utf-8")
    env = dict(os.environ)
    env["QT_QPA_PLATFORM"] = "offscreen:configfile=tela.json"  # relativo: o ":" do C: quebra
    env.setdefault("QT_QPA_FONTDIR", r"C:\Windows\Fonts")
    env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src")
    env["PYTHONIOENCODING"] = "utf-8"
    proc = subprocess.run(  # noqa: S603
        [sys.executable, "-c", _TELA_PEQUENA, str(tmp_path / "perfil")],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=240,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr[-2000:]
    out = json.loads(proc.stdout.strip().splitlines()[-1])
    area_w, area_h = out["area"]
    barra_de_tarefas = 40  # o offscreen não tem; no Windows a área útil é menor
    min_w, min_h = out["min"]
    assert out["hint"] == out["min"]  # o mínimo é o que o layout precisa (nem menos)
    assert min_w + owl_window.MOLDURA_LARGURA <= area_w
    assert min_h + owl_window.MOLDURA_ALTURA + barra_de_tarefas <= area_h
    w, h = out["size"]
    assert w + owl_window.MOLDURA_LARGURA <= area_w
    assert h + owl_window.MOLDURA_ALTURA <= area_h
    assert out["cabe"]
    assert out["cortes"] == []
