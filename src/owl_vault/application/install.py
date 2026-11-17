"""Instalação por usuário, sem administrador (UI_SPEC_V2 T0).

Na execução do ``OwlVault.exe`` empacotado, o programa se copia para
``%LOCALAPPDATA%\\Programs\\Owl Vault\\OwlVault.exe`` e cria o atalho do Menu Iniciar. Os atalhos
"Abrir com Owl Vault" das pastas trancadas apontam para esse caminho fixo — assim continuam
funcionando mesmo que o arquivo baixado seja movido ou apagado.

Versão: ao lado do exe instalado fica ``versao.txt`` ("0.3.0.15"). Um ``OwlVault.exe`` MAIS
ANTIGO (ou igual) não substitui o instalado — só um mais novo atualiza (revisão de segurança:
rodar uma cópia velha esquecida em Downloads não pode trocar o alvo de todos os atalhos).

Nada aqui exige privilégios; falhas são silenciosas (o programa roda de onde está).
"""

from __future__ import annotations

import hashlib
import importlib
import os
import re
import secrets
import sys
from pathlib import Path

from owl_vault import __version__
from owl_vault.domain.errors import OwlVaultError
from owl_vault.storage import shell

EXE_NAME = "OwlVault.exe"
START_MENU_NAME = "Owl Vault.lnk"
VERSION_FILE = "versao.txt"

Version = tuple[int, int, int, int]


def install_dir() -> Path | None:
    base = os.environ.get("LOCALAPPDATA")
    return Path(base) / "Programs" / "Owl Vault" if base else None


def start_menu_dir() -> Path | None:
    base = os.environ.get("APPDATA")
    return Path(base) / "Microsoft" / "Windows" / "Start Menu" / "Programs" if base else None


def current_version() -> Version:
    """(maior, menor, correção, build) desta execução; build 0 fora do executável."""
    major, minor, patch = (int(x) for x in __version__.split("."))
    try:
        build = int(importlib.import_module("owl_vault._build").BUILD)
    except (ImportError, AttributeError, ValueError):
        build = 0
    return major, minor, patch, build


def parse_version(text: str) -> Version | None:
    m = re.fullmatch(r"\s*(\d+)\.(\d+)\.(\d+)(?:\.(\d+))?\s*", text)
    if not m:
        return None
    a, b, c, d = m.groups()
    return int(a), int(b), int(c), int(d or 0)


def installed_version(target_dir: Path) -> Version | None:
    try:
        return parse_version((target_dir / VERSION_FILE).read_text(encoding="ascii"))
    except (OSError, UnicodeDecodeError):
        return None


def _digest(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _same_file(a: Path, b: Path) -> bool:
    try:
        if a.stat().st_size != b.stat().st_size:
            return False
        return _digest(a) == _digest(b)
    except OSError:
        return False


def _should_replace(current: Path, target: Path, target_dir: Path) -> bool:
    if not target.exists():
        return True
    if _same_file(current, target):
        return False
    installed = installed_version(target_dir)
    if installed is None:
        return True  # instalação de antes do controle de versão: o atual assume
    return current_version() > installed


def _copy(current: Path, target: Path, target_dir: Path) -> None:
    target_dir.mkdir(parents=True, exist_ok=True)
    tmp = target_dir / f".{EXE_NAME}.{secrets.token_hex(8)}.tmp"
    try:
        with open(current, "rb") as src, open(tmp, "xb") as dst:
            for chunk in iter(lambda: src.read(1 << 20), b""):
                dst.write(chunk)
            dst.flush()
            os.fsync(dst.fileno())
        os.replace(tmp, target)  # falha se a cópia instalada estiver aberta
    finally:
        if tmp.exists():
            tmp.unlink()
    major, minor, patch, build = current_version()
    (target_dir / VERSION_FILE).write_text(f"{major}.{minor}.{patch}.{build}\n", encoding="ascii")


def ensure_installed() -> tuple[str, str]:
    """Garante a cópia instalada; devolve ``(programa, argumentos-base)`` para os atalhos."""
    if not getattr(sys, "frozen", False):
        return shell.current_executable()  # desenvolvimento: pythonw -m owl_vault
    current = Path(sys.executable)
    target_dir = install_dir()
    if target_dir is None:
        return str(current), ""
    target = target_dir / EXE_NAME
    try:
        elsewhere = os.path.normcase(str(current.resolve())) != os.path.normcase(
            str(target.resolve())
        )
        if elsewhere and _should_replace(current, target, target_dir):
            _copy(current, target, target_dir)
    except OSError:
        pass
    exe = target if target.exists() else current
    _ensure_start_menu(exe)
    return str(exe), ""


def _ensure_start_menu(exe: Path) -> None:
    """Cria o atalho do Menu Iniciar ou corrige um que aponte para outro executável."""
    folder = start_menu_dir()
    if folder is None or not folder.is_dir():
        return
    lnk = folder / START_MENU_NAME
    if lnk.exists() and shell.shortcut_matches(str(lnk), str(exe), ""):
        return
    try:
        if lnk.exists():
            lnk.unlink()
        shell.create_shortcut(
            str(lnk), str(exe), "", str(exe), "Owl Vault — pastas protegidas", str(exe.parent)
        )
    except (OSError, OwlVaultError):
        pass
