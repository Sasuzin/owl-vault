"""Integração com o Windows (shell, DPAPI, instalação) e interface v2 (pastas protegidas).

Regras destes testes: SOMENTE pastas temporárias (tmp_path) com dados sintéticos; o perfil
fica sempre em tmp_path com TESTING_POLICY/TESTING_PARAMS; nenhum diálogo modal é aberto
(``ask``/``inform``/``SecretDialog`` e o seletor de pastas são trocados por gravadores).
"""

from __future__ import annotations

import builtins
import ctypes
import datetime as dt
import os
import re
import secrets
import shutil
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Iterator
from ctypes import wintypes
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest
from PySide6.QtCore import QCoreApplication, QEvent
from PySide6.QtWidgets import (
    QApplication,
    QDialog,
    QLabel,
    QLineEdit,
    QMenu,
    QPushButton,
    QToolButton,
    QWidget,
)

from owl_vault.application import install
from owl_vault.application import profile as profile_mod
from owl_vault.application.lockers import (
    ABERTA,
    ABERTURA_INCOMPLETA,
    ABRINDO,
    APAGANDO,
    ICON_NAME,
    INFOTIP,
    TRANCADA,
    TRANCANDO,
    FolderView,
)
from owl_vault.application.profile import (
    DpapiUnavailableError,
    FolderRecord,
    PinError,
    ProfileStore,
)
from owl_vault.application.protection import ProtectedPaths
from owl_vault.crypto.kdf import TESTING_PARAMS, TESTING_POLICY
from owl_vault.domain.errors import AuthenticationError, OwlVaultError
from owl_vault.storage import dpapi, shell, winfs
from owl_vault.ui import app as ui_app
from owl_vault.ui import common, owl_window, pages, single_instance
from owl_vault.ui.owl_window import IDLE_LOCK_SECONDS, OwlWindow
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
    # sem .tmp; ao lado fica a versão instalada (impede trocar por uma versão mais antiga)
    assert sorted(p.name for p in instalacao.alvo.parent.iterdir()) == [
        "OwlVault.exe",
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
    # mesma versão (ou mais antiga): NÃO substitui o instalado (revisão de segurança)
    install.ensure_installed()
    assert instalacao.alvo.read_bytes() == antigo
    assert instalacao.escritas == []
    major, minor, patch, build = install.current_version()
    monkeypatch.setattr(
        install, "current_version", lambda: (major, minor, patch - 1 if patch else 0, 0)
    )
    install.ensure_installed()
    assert instalacao.alvo.read_bytes() == antigo
    # versão mais nova: atualiza e grava a versão nova ao lado
    monkeypatch.setattr(install, "current_version", lambda: (major, minor, patch, build + 1))
    install.ensure_installed()
    assert instalacao.alvo.read_bytes() == novo
    assert len(instalacao.escritas) == 1
    assert install.installed_version(instalacao.alvo.parent) == (major, minor, patch, build + 1)


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
        (1, "1 bytes"),
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


@pytest.mark.xfail(
    strict=True,
    reason="BUG: fmt_size arredonda só na exibição: 1 MiB - 1 byte vira '1024,0 KB' (deveria "
    "subir para '1,0 MB'); o mesmo em todas as fronteiras de unidade",
)
@pytest.mark.parametrize("n", [1024**2 - 1, 1024**3 - 1])
def test_fmt_size_fronteira_nao_mostra_1024(n: int) -> None:
    assert not common.fmt_size(n).startswith("1024,0")


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
MENU_NAO_ENCONTRADA = [("Procurar a pasta…", "relocate"), ("Tirar da lista", "forget")]

#: (id, estado, escondida, ação, issue, ação base, menu esperado)
CASOS_MENU: list[tuple[str, str, bool, str, str, str, list[tuple[str, str]]]] = [
    ("trancada", TRANCADA, False, "abrir", "", "abrir", MENU_TRANCADA),
    ("escondida", TRANCADA, True, "abrir", "", "abrir", MENU_ESCONDIDA),
    ("aberta", ABERTA, False, "trancar", "", "trancar", MENU_ABERTA),
    ("itens_extras", TRANCADA, False, "resolver", "itens_extras", "abrir", [("Abrir", "abrir"), *MENU_TRANCADA]),
    ("sem_dados", TRANCADA, False, "resolver", "sem_dados", "abrir", [("Abrir", "abrir"), *MENU_TRANCADA]),
    ("senha_antiga", TRANCADA, True, "resolver", "senha_antiga", "abrir", [("Abrir", "abrir"), *MENU_ESCONDIDA]),
    ("versao_anterior_aberta", ABERTA, False, "resolver", "versao_anterior", "trancar", [("Trancar", "trancar"), *MENU_ABERTA]),
    ("versao_anterior_trancada", TRANCADA, False, "resolver", "versao_anterior", "abrir", [("Abrir", "abrir"), *MENU_TRANCADA]),
    ("nao_encontrada_trancada", TRANCADA, False, "resolver", "nao_encontrada", "", MENU_NAO_ENCONTRADA),
    ("nao_encontrada_aberta", ABERTA, False, "resolver", "nao_encontrada", "", MENU_NAO_ENCONTRADA),
    ("indisponivel", TRANCADA, True, "", "indisponivel", "", [("Tirar da lista", "forget")]),
    ("apagando", APAGANDO, False, "resolver", APAGANDO, "", []),
    ("trancando", TRANCANDO, False, "resolver", TRANCANDO, "", []),
    ("abrindo", ABRINDO, False, "resolver", ABRINDO, "", []),
    ("abertura_incompleta", ABERTURA_INCOMPLETA, False, "resolver", ABERTURA_INCOMPLETA, "", []),
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
    textos = _textos(row)
    assert NOME in textos
    assert "C:\\Sintetico\\Pastas" in textos  # local (pai), sem o prefixo \\?\
    assert view.label in textos
    if view.action == "resolver":
        assert "Atenção sintética" in textos
    botoes = row.findChildren(QPushButton)
    if view.action:
        assert [b.text() for b in botoes] == [ROTULOS_ACAO[view.action]]
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


@gui
def test_home_page_lista_vazia_faixa_e_limpeza(qapp: QApplication) -> None:
    home = pages.HomePage(QMenu())
    assert any("Nenhuma pasta protegida ainda" in t for t in _textos(home))
    assert home.banner.isHidden()
    abertas = [_view(CASOS_MENU[2]), _view(CASOS_MENU[2])]
    trancada = _view(CASOS_MENU[0])
    home.set_rows([abertas[0], trancada], lambda _f, _a: None)
    assert not home.banner.isHidden()
    assert home.banner_text.text() == "1 pasta está aberta e visível neste computador."
    assert len(home.findChildren(pages.FolderRow)) == 2
    home.set_rows([*abertas, trancada], lambda _f, _a: None)
    _descarta()
    assert home.banner_text.text() == "2 pastas estão abertas e visíveis neste computador."
    assert len(home.findChildren(pages.FolderRow)) == 3
    sinal: list[bool] = []
    home.lock_all_clicked.connect(lambda: sinal.append(True))
    trancar_agora = [
        b for b in home.banner.findChildren(QPushButton) if b.text() == "Trancar agora"
    ]
    assert len(trancar_agora) == 1
    trancar_agora[0].click()
    assert sinal == [True]
    home.set_notice(f"'{NOME}' está trancada.")
    assert not home.notice.isHidden()
    home.clear()
    _descarta()
    assert home.banner.isHidden()
    assert home.notice.isHidden()
    assert home.findChildren(pages.FolderRow) == []
    assert not [t for t in _textos(home, so_visiveis=True) if NOME in t]
    home.deleteLater()
    _descarta()


# =========================================================================== pages: assistente (T1/T2)


@gui
def test_assistente_valida_senha_mestra_e_pin(qapp: QApplication) -> None:
    page = pages.SetupPage()
    recebidos: list[tuple[str, str, bool]] = []
    page.finished.connect(lambda sm, pin, rec: recebidos.append((sm, pin, rec)))
    page.sm1.setText("curta")
    page.sm2.setText("curta")
    page._next()
    assert page.stack.currentIndex() == 0
    assert "pelo menos" in page.err1.text()
    page.sm1.setText(SENHA_MESTRA)
    page.sm2.setText(SENHA_MESTRA + "x")
    page._next()
    assert page.err1.text() == "As duas senhas não são iguais."
    page.sm2.setText(SENHA_MESTRA)
    page._next()
    assert "Anotei" in page.err1.text()  # caixa obrigatória
    page.noted.setChecked(True)
    page._next()
    assert page.stack.currentIndex() == 1
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
    page.pin2.setText(PIN)
    page._finish()
    assert recebidos == [(SENHA_MESTRA, PIN, False)]
    for campo in (page.sm1, page.sm2, page.pin1, page.pin2):
        assert campo.text() == ""  # apagados depois de emitir
    page.deleteLater()
    _descarta()


@gui
def test_assistente_recuperar_marca_pedido(qapp: QApplication) -> None:
    page = pages.SetupPage()
    page._recover_hint()
    assert page.wants_recover
    assert "MESMA senha mestra" in page.err1.text()
    page.deleteLater()
    _descarta()


# =========================================================================== pages: desbloqueio (T3)


@gui
def test_unlock_page_pin_envio_e_troca(qapp: QApplication) -> None:
    page = pages.UnlockPage()
    enviados: list[tuple[str, bool]] = []
    page.submitted.connect(lambda s, m: enviados.append((s, m)))
    page.configure(master=False)
    assert page.edit.placeholderText() == "PIN"
    assert page.edit.maxLength() == 12
    assert page.edit.echoMode() == QLineEdit.EchoMode.Password
    page._submit()
    assert page.err.text() == "Digite o PIN."
    assert enviados == []
    page.edit.setText(PIN)
    page._submit()
    assert enviados == [(PIN, False)]
    assert page.edit.text() == ""
    assert not page.go.isEnabled()
    assert page.go.text() == "Abrindo…"
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


# =========================================================================== OwlWindow


@dataclass
class Tela:
    win: OwlWindow
    dialogos: list[tuple[str, str]]
    perfil: Path

    @property
    def store(self) -> ProfileStore:
        return self.win.store


@pytest.fixture
def abrir_tela(
    qapp: QApplication, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Iterator[Callable[..., Tela]]:
    """Fábrica de janelas com perfil em tmp_path e diálogos substituídos por gravadores."""
    dialogos: list[tuple[str, str]] = []

    def ask(_p: object, title: str, *_a: object, **_k: object) -> str:
        dialogos.append(("ask", title))
        return "cancel"

    def inform(_p: object, title: str, *_a: object, **_k: object) -> None:
        dialogos.append(("inform", title))

    def choose_folder(_p: object, title: str, *_a: object, **_k: object) -> None:
        dialogos.append(("choose_folder", title))

    def limits(_p: object) -> None:
        dialogos.append(("limits", ""))

    monkeypatch.setattr(owl_window, "ask", ask)
    monkeypatch.setattr(owl_window, "inform", inform)
    monkeypatch.setattr(owl_window, "choose_folder", choose_folder)
    monkeypatch.setattr(owl_window, "limits_dialog", limits)
    monkeypatch.setattr(owl_window, "saved_theme", lambda: "dark")  # não lê o registro real
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
        janelas.append(win)
        return Tela(win, dialogos, perfil)

    yield abrir
    for win in janelas:
        _espera(lambda w=win: not w.runner.busy)
        win._quitting = True
        win.close()
        win.deleteLater()
    _descarta()
    assert [d for d in dialogos if d[0] == "choose_folder"] == []  # nunca abre QFileDialog


def _criar_perfil(tela: Tela) -> profile_mod.ProfileSession:
    return tela.store.create(SENHA_MESTRA, PIN, params=TESTING_PARAMS)


def _pasta_aberta(base: Path, nome: str = NOME) -> FolderRecord:
    """Pasta real (sintética) em tmp_path registrada como 'aberta'."""
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
        state=ABERTA,
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


@gui
def test_janela_sem_perfil_abre_no_assistente(abrir_tela: Callable[..., Tela]) -> None:
    tela = abrir_tela()
    win = tela.win
    assert win.store.dir == tela.perfil
    assert win.pages.currentWidget() is win.setup_page
    assert win.setup_page.stack.currentIndex() == 0
    assert not tela.perfil.exists()  # abrir a janela não grava nada
    assert win.session is None
    assert win.mgr is None


@gui
def test_apos_criar_perfil_desbloqueio_pede_pin(abrir_tela: Callable[..., Tela]) -> None:
    tela = abrir_tela()
    win = tela.win
    _criar_perfil(tela).close()
    assert (tela.perfil / "perfil.owlp").is_file()
    win._show_unlock()
    page = win.unlock_page
    assert win.pages.currentWidget() is page
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
    assert win.session is sessao
    assert win.mgr is not None
    assert win.mgr.folders == []
    assert win.home.findChildren(pages.FolderRow) == []
    assert any("Nenhuma pasta protegida ainda" in t for t in _textos(win.home))
    assert win.home.banner.isHidden()
    assert win.home.notice.isHidden()
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
    assert win.home.banner_text.text() == "1 pasta está aberta e visível neste computador."
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
    menus = [
        m for m in win.findChildren(QMenu) if any(a.text() == "Bloquear agora" for a in m.actions())
    ]
    assert len(menus) == 1
    bloquear = next(a for a in menus[0].actions() if a.text() == "Bloquear agora")
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
@pytest.mark.xfail(
    strict=True,
    reason="BUG: HomePage.clear() (Bloquear agora) só esconde o aviso; o texto com o nome da "
    "pasta continua num QLabel oculto da janela travada",
)
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
    win.lock_now()
    _descarta()
    assert not [t for t in _textos(win) if NOME in t]


@gui
def test_menu_principal_tem_itens_da_especificacao(abrir_tela: Callable[..., Tela]) -> None:
    win = abrir_tela().win
    menus = [
        m for m in win.findChildren(QMenu) if any(a.text() == "Bloquear agora" for a in m.actions())
    ]
    textos = [a.text() for a in menus[0].actions() if not a.isSeparator()]
    for item in (
        "Recuperar uma pasta protegida…",
        "Cópia criptografada de uma pasta…",
        "Alterar PIN…",
        "Bloquear agora",
        "Limites da proteção",
        "Tema",
    ):
        assert item in textos


@gui
def test_bloquear_durante_operacao_espera_terminar(abrir_tela: Callable[..., Tela]) -> None:
    tela = abrir_tela()
    win = tela.win
    win._unlocked(_criar_perfil(tela))
    liberar = threading.Event()
    fim: list[object] = []
    win._run(lambda _p, _c: liberar.wait(10), fim.append)
    assert win.runner.busy
    win.lock_now()
    assert win._lock_after_job
    assert win.session is not None  # não derruba a sessão no meio do trabalho
    liberar.set()
    _espera(lambda: win.session is None)
    assert fim == [True]
    assert win.pages.currentWidget() is win.unlock_page


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
def test_perfil_danificado_nunca_reabre_o_assistente(abrir_tela: Callable[..., Tela]) -> None:
    tela = abrir_tela()
    tela.perfil.mkdir()
    (tela.perfil / "perfil.owlp").write_bytes(b"lixo sintetico, nao e json")
    win = abrir_tela().win
    assert win.pages.currentWidget() is win.unlock_page
    assert win.unlock_page.master
    assert "danificado" in win.unlock_page.err.text()


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
@pytest.mark.xfail(
    strict=True,
    reason="BUG: ProfileStore.unlock_with_master zera pin_failures só no perfil principal "
    "(session.save -> write); o .bak guarda a contagem antiga e unlock_with_pin usa o máximo "
    "das duas cópias, então entrar com a senha mestra não devolve as 5 tentativas do PIN",
)
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
    assert not win.unlock_page.master


@gui
def test_pedido_do_atalho_com_app_destravado_pede_pin_de_novo(
    abrir_tela: Callable[..., Tela], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    criados: list[dict[str, object]] = []

    class DialogoFalso:
        def __init__(
            self, _parent: object, title: str, text: str, button: str, **kw: object
        ) -> None:
            criados.append({"title": title, "text": text, "button": button, **kw})

        def exec(self) -> QDialog.DialogCode:  # não abre nada: "Cancelar"
            return QDialog.DialogCode.Rejected

    monkeypatch.setattr(owl_window, "SecretDialog", DialogoFalso)
    tela = abrir_tela()
    win = tela.win
    sessao = _criar_perfil(tela)
    win._unlocked(sessao)
    rec = _pasta_aberta(tmp_path)
    sessao.index.folders.append(rec)
    win.request_open(rec.id)
    assert len(criados) == 1
    assert criados[0]["title"] == f"Abrir '{NOME}'"
    assert criados[0]["button"] == "Abrir"
    assert criados[0]["master"] is False
    assert not win.runner.busy  # cancelado: nada foi feito
    assert win.session is sessao


@gui
def test_mensagem_da_outra_instancia_so_aceita_id_valido(
    abrir_tela: Callable[..., Tela], monkeypatch: pytest.MonkeyPatch
) -> None:
    win = abrir_tela().win
    pedidos: list[str] = []
    for nome in ("showNormal", "raise_", "activateWindow"):
        monkeypatch.setattr(win, nome, lambda: None)
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
def test_sair_com_pasta_aberta_pergunta_antes(
    abrir_tela: Callable[..., Tela], tmp_path: Path
) -> None:
    tela = abrir_tela()
    win = tela.win
    sessao = _criar_perfil(tela)
    win._unlocked(sessao)
    sessao.index.folders.append(_pasta_aberta(tmp_path))
    assert not win.close()  # resposta gravada: "cancel"
    assert ("ask", "Sair do Owl Vault?") in tela.dialogos
    assert win.session is sessao
    sessao.index.folders.clear()
    assert win.close()  # nenhuma aberta: sai e descarta as chaves
    assert win.session is None
