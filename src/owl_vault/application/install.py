"""Instalação por usuário, sem administrador (UI_SPEC_V2 T0).

Na execução do ``OwlVault.exe`` empacotado, o programa se copia para
``%LOCALAPPDATA%\\Programs\\Owl Vault\\OwlVault.exe`` e cria o atalho do Menu Iniciar. Os atalhos
"Abrir com Owl Vault" das pastas trancadas apontam para esse caminho fixo — assim continuam
funcionando mesmo que o arquivo baixado seja movido ou apagado.

Atalho na Área de Trabalho: criado UMA vez por instalação (a marca ``area-de-trabalho.txt``
fica ao lado do exe instalado). Se a pessoa apagar o atalho, ele não volta; se ele existir e
apontar para outro ``OwlVault.exe`` (cópia baixada, instalação antiga), é corrigido. Um atalho
com o mesmo nome para outro programa fica como está.

Versão: ao lado do exe instalado ficam

* ``versao.txt`` ("0.3.0.15"): só a versão, no formato que as versões anteriores também leem;
* ``versao.sha256`` ("0.3.0.15 <tamanho> <SHA-256> <data do build>"): liga a versão ao
  CONTEÚDO do exe que este programa instalou.

Regras (revisão de segurança: rodar uma cópia velha esquecida em Downloads não pode trocar o alvo
de todos os atalhos, e um exe trocado por fora não pode ficar para sempre no lugar):

* versão mais nova substitui; versão mais antiga nunca substitui (nada de downgrade);
* mesma versão com conteúdo diferente substitui — é um rebuild com o mesmo número, ou um exe
  trocado por fora (por exemplo, por um Owl Vault 0.2.0, que não conhece estes arquivos e deixa
  ``versao.txt`` dizendo a versão de antes). Única exceção: o instalado confere com
  ``versao.sha256`` e é um build de data mais nova;
* exe instalado que não confere com ``versao.sha256`` tem versão desconhecida: só a versão
  registrada ou uma mais nova o substitui.

As marcas são gravadas ANTES de trocar o exe (e voltam ao que eram se a troca falhar): uma queda
no meio deixa a marca à frente do exe — que então não confere e é corrigido pela versão
registrada —, nunca uma marca velha que deixaria uma versão antiga substituir a nova.

Nada aqui exige privilégios; falhas são silenciosas (o programa roda de onde está).
"""

from __future__ import annotations

import contextlib
import hashlib
import importlib
import os
import re
import secrets
import sys
from dataclasses import dataclass
from pathlib import Path

from owl_vault import __version__
from owl_vault.domain.errors import OwlVaultError
from owl_vault.storage import shell

EXE_NAME = "OwlVault.exe"
START_MENU_NAME = "Owl Vault.lnk"
DESKTOP_NAME = "Owl Vault.lnk"
SHORTCUT_DESCRIPTION = "Owl Vault — pastas protegidas"
VERSION_FILE = "versao.txt"
STAMP_FILE = "versao.sha256"
#: ao lado do exe instalado: o atalho da Área de Trabalho já foi criado uma vez
DESKTOP_MARK = "area-de-trabalho.txt"
_DESKTOP_MARK_TEXT = (
    "O Owl Vault já criou o atalho da Área de Trabalho nesta instalação. "
    "Se ele foi apagado, não é recriado.\n"
).encode()

Version = tuple[int, int, int, int]

_COPY, _STAMP, _NOTHING = "copiar", "marcar", "nada"
_STAMP_RE = re.compile(
    r"\s*(\d+)\.(\d+)\.(\d+)\.(\d+) (\d+) ([0-9a-f]{64}) (\d{4}-\d{2}-\d{2}|-)\s*"
)


@dataclass(frozen=True)
class InstallStamp:
    """O que ``versao.sha256`` diz do exe instalado."""

    version: Version
    size: int
    sha256: str
    date: str  # data do build (AAAA-MM-DD) ou "" se desconhecida

    def text(self) -> str:
        return f"{_version_text(self.version)} {self.size} {self.sha256} {self.date or '-'}\n"


def install_dir() -> Path | None:
    base = os.environ.get("LOCALAPPDATA")
    return Path(base) / "Programs" / "Owl Vault" if base else None


def start_menu_dir() -> Path | None:
    base = os.environ.get("APPDATA")
    return Path(base) / "Microsoft" / "Windows" / "Start Menu" / "Programs" if base else None


def desktop_dir() -> Path | None:
    """Área de Trabalho do usuário (segue o redirecionamento, por exemplo o do OneDrive)."""
    path = shell.known_folder(shell.KNOWN_FOLDERS["Área de Trabalho"])
    return Path(path) if path else None


def current_version() -> Version:
    """(maior, menor, correção, build) desta execução; build 0 fora do executável."""
    major, minor, patch = (int(x) for x in __version__.split("."))
    try:
        build = int(importlib.import_module("owl_vault._build").BUILD)
    except (ImportError, AttributeError, ValueError):
        build = 0
    return major, minor, patch, build


def current_build_date() -> str:
    """Data do build desta execução (AAAA-MM-DD) ou "" se desconhecida."""
    try:
        date = str(importlib.import_module("owl_vault._build").DATE)
    except (ImportError, AttributeError):
        return ""
    return date if re.fullmatch(r"\d{4}-\d{2}-\d{2}", date) else ""


def _version_text(v: Version) -> str:
    return ".".join(str(x) for x in v)


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


def parse_stamp(text: str) -> InstallStamp | None:
    m = _STAMP_RE.fullmatch(text)
    if not m:
        return None
    a, b, c, d, size, digest, date = m.groups()
    return InstallStamp(
        (int(a), int(b), int(c), int(d)), int(size), digest, "" if date == "-" else date
    )


def installed_stamp(target_dir: Path) -> InstallStamp | None:
    try:
        return parse_stamp((target_dir / STAMP_FILE).read_text(encoding="ascii"))
    except (OSError, UnicodeDecodeError):
        return None


def _digest(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _decide(current: Path, target: Path, target_dir: Path) -> tuple[str, InstallStamp | None]:
    """(``_COPY``, None): instalar o atual; (``_STAMP``, marca): o instalado já é o atual, mas
    as marcas não o descrevem — gravar ``marca``; (``_NOTHING``, None): deixar como está."""
    if not target.exists():
        return _COPY, None
    digests: dict[Path, str] = {}

    def digest(p: Path) -> str:
        if p not in digests:
            digests[p] = _digest(p)
        return digests[p]

    size = target.stat().st_size
    mine = current_version()
    if current.stat().st_size == size and digest(current) == digest(target):
        expected = InstallStamp(mine, size, digest(target), current_build_date())
        if installed_version(target_dir) == mine and installed_stamp(target_dir) == expected:
            return _NOTHING, None
        return _STAMP, expected
    installed = installed_version(target_dir)
    if installed is None:
        return _COPY, None  # instalação de antes do controle de versão: o atual assume
    if mine != installed:
        return (_COPY if mine > installed else _NOTHING), None  # nunca downgrade
    # mesma versão, conteúdo diferente: rebuild com o mesmo número ou exe trocado por fora
    stamp = installed_stamp(target_dir)
    if (
        stamp is not None
        and stamp.version == installed
        and stamp.size == size
        and stamp.sha256 == digest(target)
    ):
        mine_date = current_build_date()
        if stamp.date and mine_date and mine_date < stamp.date:
            return _NOTHING, None  # o instalado é um build mais novo com o mesmo número
    return _COPY, None


def _should_replace(current: Path, target: Path, target_dir: Path) -> bool:
    return _decide(current, target, target_dir)[0] == _COPY


def _write_atomic(path: Path, data: bytes) -> None:
    tmp = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o644)
    try:
        try:
            os.write(fd, data)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, path)
    finally:
        if tmp.exists():
            with contextlib.suppress(OSError):
                tmp.unlink()


def _read_marks(target_dir: Path) -> dict[str, bytes | None]:
    out: dict[str, bytes | None] = {}
    for name in (VERSION_FILE, STAMP_FILE):
        try:
            out[name] = (target_dir / name).read_bytes()
        except FileNotFoundError:
            out[name] = None
    return out


def _restore_marks(target_dir: Path, before: dict[str, bytes | None]) -> None:
    """Melhor esforço: as marcas voltam ao que eram (a troca do exe não aconteceu)."""
    for name, data in before.items():
        with contextlib.suppress(OSError):
            if data is None:
                (target_dir / name).unlink(missing_ok=True)
            else:
                _write_atomic(target_dir / name, data)


def _marks(stamp: InstallStamp) -> dict[str, bytes]:
    return {
        STAMP_FILE: stamp.text().encode("ascii"),
        VERSION_FILE: f"{_version_text(stamp.version)}\n".encode("ascii"),
    }


def _write_marks(target_dir: Path, stamp: InstallStamp) -> None:
    for name, data in _marks(stamp).items():  # versao.sha256 antes de versao.txt
        _write_atomic(target_dir / name, data)


def installer_files(exe: Path) -> dict[str, bytes]:
    """Arquivos que o instalador (``packaging/owl_vault.iss``) grava ao lado de ``exe``: as
    marcas que o descrevem exatamente — iguais às que este programa gravaria ao se instalar —
    e a marca da Área de Trabalho (o atalho de lá é uma opção do instalador; o programa não o
    cria sozinho depois)."""
    data = exe.read_bytes()
    stamp = InstallStamp(
        current_version(), len(data), hashlib.sha256(data).hexdigest(), current_build_date()
    )
    return {**_marks(stamp), DESKTOP_MARK: _DESKTOP_MARK_TEXT}


def _copy(current: Path, target: Path, target_dir: Path) -> None:
    target_dir.mkdir(parents=True, exist_ok=True)
    tmp = target_dir / f".{EXE_NAME}.{secrets.token_hex(8)}.tmp"
    try:
        h = hashlib.sha256()
        size = 0
        with open(current, "rb") as src, open(tmp, "xb") as dst:
            for chunk in iter(lambda: src.read(1 << 20), b""):
                dst.write(chunk)
                h.update(chunk)
                size += len(chunk)
            dst.flush()
            os.fsync(dst.fileno())
        before = _read_marks(target_dir)
        # as marcas descrevem exatamente os bytes que vão para o lugar, e vêm ANTES deles
        _write_marks(
            target_dir, InstallStamp(current_version(), size, h.hexdigest(), current_build_date())
        )
        try:
            os.replace(tmp, target)  # falha se a cópia instalada estiver aberta
        except BaseException:
            _restore_marks(target_dir, before)
            raise
    finally:
        if tmp.exists():
            tmp.unlink()


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
        if elsewhere:
            what, stamp = _decide(current, target, target_dir)
            if what == _COPY:
                _copy(current, target, target_dir)
            elif what == _STAMP and stamp is not None:
                _write_marks(target_dir, stamp)
    except OSError:
        pass
    exe = target if target.exists() else current
    _ensure_start_menu(exe)
    _ensure_desktop(exe, target_dir)
    return str(exe), ""


def _make_shortcut(lnk: Path, exe: Path) -> None:
    if lnk.exists():
        lnk.unlink()
    shell.create_shortcut(str(lnk), str(exe), "", str(exe), SHORTCUT_DESCRIPTION, str(exe.parent))


def _ensure_start_menu(exe: Path) -> None:
    """Cria o atalho do Menu Iniciar ou corrige um que aponte para outro executável."""
    folder = start_menu_dir()
    if folder is None or not folder.is_dir():
        return
    lnk = folder / START_MENU_NAME
    if lnk.exists() and shell.shortcut_matches(str(lnk), str(exe), ""):
        return
    with contextlib.suppress(OSError, OwlVaultError):
        _make_shortcut(lnk, exe)


def _points_to_owl_vault(lnk: Path) -> bool:
    """O atalho abre um ``OwlVault.exe`` (qualquer cópia)? Ilegível conta como "não"."""
    try:
        target, _args = shell.read_shortcut(str(lnk))
    except (OSError, OwlVaultError):
        return False
    return os.path.normcase(os.path.basename(target)) == os.path.normcase(EXE_NAME)


def _ensure_desktop(exe: Path, target_dir: Path) -> None:
    """Atalho na Área de Trabalho: criado uma vez (marca ao lado do exe instalado), corrigido
    se apontar para outro ``OwlVault.exe``, nunca recriado depois de apagado."""
    folder = desktop_dir()
    if folder is None or not folder.is_dir():
        return
    lnk = folder / DESKTOP_NAME
    mark = target_dir / DESKTOP_MARK
    try:
        if lnk.exists():
            if _points_to_owl_vault(lnk) and not shell.shortcut_matches(str(lnk), str(exe), ""):
                _make_shortcut(lnk, exe)
        elif mark.exists():
            return  # já foi criado uma vez e a pessoa apagou
        else:
            _make_shortcut(lnk, exe)
        if target_dir.is_dir() and not mark.exists():
            _write_atomic(mark, _DESKTOP_MARK_TEXT)
    except (OSError, OwlVaultError):
        pass
