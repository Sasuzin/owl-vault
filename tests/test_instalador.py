"""Instalador (Inno Setup, ``packaging/owl_vault.iss``) e as marcas que ele leva.

Só pastas temporárias e dados sintéticos: LOCALAPPDATA/APPDATA e a Área de Trabalho apontam
para ``tmp_path``; o "exe" é o lançador do Python com bytes aleatórios no fim (o Windows só
grava atalho para um PE válido). Nenhum instalador de verdade é executado aqui.
"""

from __future__ import annotations

import hashlib
import os
import re
import sys
from pathlib import Path

import pytest

from owl_vault.application import install, profile

ISS = Path(__file__).resolve().parent.parent / "packaging" / "owl_vault.iss"
V = (0, 5, 0, 16)
DATA = "2026-11-23"


@pytest.fixture
def iss() -> str:
    return ISS.read_text(encoding="utf-8-sig")


@pytest.fixture
def versao(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(install, "current_version", lambda: V)
    monkeypatch.setattr(install, "current_build_date", lambda: DATA)


def test_marcas_do_instalador_descrevem_exatamente_o_exe(tmp_path: Path, versao: None) -> None:
    exe = tmp_path / "OwlVault.exe"
    exe.write_bytes(b"MZ" + os.urandom(5000))
    arquivos = install.installer_files(exe)
    assert sorted(arquivos) == ["area-de-trabalho.txt", "versao.sha256", "versao.txt"]
    assert arquivos["versao.txt"] == b"0.5.0.16\n"
    marca = install.parse_stamp(arquivos["versao.sha256"].decode("ascii"))
    conteudo = exe.read_bytes()
    assert marca == install.InstallStamp(
        V, len(conteudo), hashlib.sha256(conteudo).hexdigest(), DATA
    )
    assert arquivos["area-de-trabalho.txt"].decode("utf-8").startswith("O Owl Vault já criou")


def test_exe_instalado_pelo_instalador_nao_e_regravado_nem_ganha_atalho(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, versao: None
) -> None:
    """Depois do instalador (sem a opção do atalho da Área de Trabalho), rodar o mesmo
    OwlVault.exe baixado não regrava nada e não cria o atalho que a pessoa desmarcou."""
    local = tmp_path / "LocalAppData"
    pasta = local / "Programs" / "Owl Vault"
    pasta.mkdir(parents=True)
    area = tmp_path / "Área de Trabalho"
    area.mkdir()
    pe = Path(sys.executable).read_bytes() + os.urandom(4096)
    alvo = pasta / install.EXE_NAME
    alvo.write_bytes(pe)
    for nome, dados in install.installer_files(alvo).items():  # o que o instalador grava
        (pasta / nome).write_bytes(dados)
    baixado = tmp_path / "Downloads" / install.EXE_NAME
    baixado.parent.mkdir()
    baixado.write_bytes(pe)
    monkeypatch.setenv("LOCALAPPDATA", str(local))
    monkeypatch.setenv("APPDATA", str(tmp_path / "Roaming sem Menu Iniciar"))
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", str(baixado))
    monkeypatch.setattr(install, "desktop_dir", lambda: area)
    antes = {p.name: (p.stat().st_mtime_ns, p.read_bytes()) for p in pasta.iterdir()}
    exe, _args = install.ensure_installed()
    assert os.path.normcase(exe) == os.path.normcase(str(alvo))
    assert {p.name: (p.stat().st_mtime_ns, p.read_bytes()) for p in pasta.iterdir()} == antes
    assert list(area.iterdir()) == []
    # um exe MAIS ANTIGO baixado depois também não substitui o instalado
    monkeypatch.setattr(install, "current_version", lambda: (0, 4, 9, 99))
    baixado.write_bytes(Path(sys.executable).read_bytes() + os.urandom(4096))
    install.ensure_installed()
    assert alvo.read_bytes() == pe


# --- o script do instalador concorda com o programa --------------------------------------


def _setup(iss: str, chave: str) -> str:
    m = re.search(rf"^{chave}=(.*)$", iss, re.MULTILINE)
    assert m, chave
    return m.group(1).strip()


def test_instala_onde_o_programa_se_instala_sozinho_sem_administrador(iss: str) -> None:
    assert _setup(iss, "DefaultDirName") == r"{localappdata}\Programs\Owl Vault"
    assert install.install_dir() is not None
    assert install.install_dir().parts[-2:] == ("Programs", "Owl Vault")  # type: ignore[union-attr]
    assert _setup(iss, "DisableDirPage") == "yes"  # os atalhos das pastas apontam para lá
    assert _setup(iss, "PrivilegesRequired") == "lowest"
    assert _setup(iss, "AppId") == "{{1EBD1724-39BD-4ADE-B5E3-AD125245BF3F}"  # nunca mudar


def test_leva_o_exe_e_todas_as_marcas(iss: str, tmp_path: Path, versao: None) -> None:
    exe = tmp_path / install.EXE_NAME
    exe.write_bytes(b"MZ")
    fontes = set(re.findall(r'^Source: "\.\.\\dist\\(?:instalador\\)?([^"]+)"', iss, re.MULTILINE))
    assert fontes == {install.EXE_NAME, *install.installer_files(exe)}


def test_atalhos_iguais_aos_do_programa(iss: str) -> None:
    icones = re.findall(r'^Name: "\{(auto\w+)\}\\([^"]+)"; Filename: "\{app\}\\([^"]+)"', iss, re.M)
    assert icones == [
        ("autoprograms", install.START_MENU_NAME.removesuffix(".lnk"), install.EXE_NAME),
        ("autodesktop", install.DESKTOP_NAME.removesuffix(".lnk"), install.EXE_NAME),
    ]
    assert iss.count(f'Comment: "{install.SHORTCUT_DESCRIPTION}"') == 2
    assert re.search(r"Tasks: desktopicon$", iss, re.M)  # o da Área de Trabalho é opcional


def test_owl_vault_aberto_o_instalador_pede_para_fechar_nunca_fecha_a_forca(iss: str) -> None:
    """0.6.0: o fechamento automático (Restart Manager) fechou a janela, mas o lançador do
    PyInstaller ficou preso segurando o exe e o instalador parou num erro."""
    from owl_vault.ui import app

    m = re.search(r'^#define AppMutex "([^"]+)"$', iss, re.M)
    assert m and m.group(1) == app.APP_MUTEX
    assert _setup(iss, "AppMutex") == "{#AppMutex}"  # ao abrir o instalador e o desinstalador
    assert _setup(iss, "CloseApplications") == "no"
    assert "function PrepareToInstall" in iss
    # logo antes de copiar: o mutex (0.6.1+) ou o exe em uso (versões sem o mutex e o lançador
    # do PyInstaller, que segura o exe sem ter janela)
    assert "while CheckForMutexes('{#AppMutex}') or ExeInUse() do" in iss
    assert "DLLGetLastError() = 32" in iss  # só "em uso" (violação de compartilhamento)


def test_programa_mantem_o_mutex_enquanto_aberto() -> None:
    import ctypes
    import secrets
    from ctypes import wintypes

    from owl_vault.ui import app

    nome = f"OwlVaultTeste-{secrets.token_hex(8)}"  # nunca o nome real
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.OpenMutexW.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.LPCWSTR]
    k32.OpenMutexW.restype = wintypes.HANDLE
    k32.CloseHandle.argtypes = [wintypes.HANDLE]
    assert not k32.OpenMutexW(0x00100000, False, nome)  # SYNCHRONIZE: ainda não existe
    handle = app.hold_app_mutex(nome)
    assert handle
    try:
        outro = k32.OpenMutexW(0x00100000, False, nome)  # como o CheckForMutexes do Inno
        assert outro
        k32.CloseHandle(outro)
    finally:
        app._HELD_MUTEXES.remove(handle)
        k32.CloseHandle(handle)
    assert not k32.OpenMutexW(0x00100000, False, nome)  # fechado o programa, some


def test_autoria_igual_no_programa_no_exe_e_no_instalador(iss: str) -> None:
    import importlib.util

    import owl_vault

    m = re.search(r'^#define AppAuthor "([^"]+)"$', iss, re.M)
    assert m and m.group(1) == owl_vault.AUTHOR == "Luís Felipe Galvão"
    for chave in ("AppPublisher", "VersionInfoCompany"):
        assert _setup(iss, chave) == "{#AppAuthor}"
    copyright_iss = owl_vault.COPYRIGHT.replace(owl_vault.AUTHOR, "{#AppAuthor}")
    assert _setup(iss, "AppCopyright") == _setup(iss, "VersionInfoCopyright") == copyright_iss
    # propriedades do OwlVault.exe (packaging/stamp_version.py -> version_info.txt)
    spec = importlib.util.spec_from_file_location("stamp_version", ISS.parent / "stamp_version.py")
    assert spec and spec.loader
    stamp = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(stamp)
    assert stamp.read_author() == owl_vault.AUTHOR
    texto = stamp.version_info_text("0.6.0", 17, "0.6.0 (build 17 · abc1234)")
    assert f"StringStruct(u'CompanyName', u'{owl_vault.AUTHOR}')" in texto
    assert f"StringStruct(u'LegalCopyright', u'{owl_vault.COPYRIGHT}')" in texto


def test_desinstalacao_avisa_do_perfil_e_nao_apaga_dados(
    iss: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "LocalAppData sintético"))
    m = re.search(r"ProfileFile = '\{localappdata\}\\(.+)';", iss)
    assert m
    caminho = Path(os.environ["LOCALAPPDATA"]) / m.group(1)
    assert caminho == profile.default_profile_dir() / "perfil.owlp"
    # nada fora da pasta do programa é apagado na desinstalação
    apagados = re.findall(r'^Type: \w+; Name: "([^"]+)"', iss, re.M)
    assert apagados and all(n.startswith("{app}") for n in apagados)
    assert "DelTree" not in iss and "DeleteFile" not in iss
    assert '"Remover proteção…"' in iss  # o nome do botão na interface
    assert "clique em Não" in iss  # os botões do aviso são Sim/Não (era "cancele")
