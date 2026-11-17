"""Instalação por usuário, sem administrador (UI_SPEC_V2 T0).

Na execução do ``OwlVault.exe`` empacotado, o programa se copia para
``%LOCALAPPDATA%\\Programs\\Owl Vault\\OwlVault.exe`` e cria o atalho do Menu Iniciar. Os atalhos
"Abrir com Owl Vault" das pastas trancadas apontam para esse caminho fixo — assim continuam
funcionando mesmo que o arquivo baixado seja movido ou apagado.

Nada aqui exige privilégios; falhas são silenciosas (o programa roda de onde está).
"""

from __future__ import annotations

import hashlib
import os
import secrets
import sys
from pathlib import Path

from owl_vault.domain.errors import OwlVaultError
from owl_vault.storage import shell

EXE_NAME = "OwlVault.exe"
START_MENU_NAME = "Owl Vault.lnk"


def install_dir() -> Path | None:
    base = os.environ.get("LOCALAPPDATA")
    return Path(base) / "Programs" / "Owl Vault" if base else None


def start_menu_dir() -> Path | None:
    base = os.environ.get("APPDATA")
    return Path(base) / "Microsoft" / "Windows" / "Start Menu" / "Programs" if base else None


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
        if elsewhere and (not target.exists() or not _same_file(current, target)):
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
    except OSError:
        pass
    exe = target if target.exists() else current
    _ensure_start_menu(exe)
    return str(exe), ""


def _ensure_start_menu(exe: Path) -> None:
    folder = start_menu_dir()
    if folder is None or not folder.is_dir():
        return
    lnk = folder / START_MENU_NAME
    if lnk.exists():
        return
    try:
        shell.create_shortcut(
            str(lnk), str(exe), "", str(exe), "Owl Vault — pastas protegidas", str(exe.parent)
        )
    except (OSError, OwlVaultError):
        pass
