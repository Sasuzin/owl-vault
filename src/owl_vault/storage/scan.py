"""Varredura segura da origem (ARCHITECTURE §4.1 passo 1).

Classifica cada entrada pelos atributos vindos da listagem do diretório
(``DirEntry.stat(follow_symlinks=False)`` não abre o arquivo no Windows) ANTES de qualquer
abertura: nunca segue links nem dispara download de arquivos de nuvem. Qualquer erro de
listagem é BLOQUEIO (nunca uma subárvore pulada em silêncio).
"""

from __future__ import annotations

import os
import stat as stat_mod
from collections.abc import Callable
from dataclasses import dataclass, field

from owl_vault.domain.limits import MAX_DEPTH, MAX_ENTRIES, MAX_FILE_SIZE
from owl_vault.domain.names import component_problem, display_path, fold
from owl_vault.storage import winfs

IO_REPARSE_TAG_APPEXECLINK = 0x8000001B
IO_REPARSE_TAG_WOF = 0x80000017
IO_REPARSE_TAG_DEDUP = 0x80000013
_MAX_DETAILED = 200


def describe_reparse(tag: int) -> str:
    if tag == winfs.IO_REPARSE_TAG_SYMLINK:
        return "link simbólico"
    if tag == winfs.IO_REPARSE_TAG_MOUNT_POINT:
        return "junction ou ponto de montagem"
    if (tag & 0xFFFF0FFF) == 0x9000001A:
        return (
            "item do OneDrive/Arquivos sob Demanda (não suportado na v1, mesmo com "
            "'Sempre manter neste dispositivo'; copie a pasta para fora do OneDrive)"
        )
    if tag == IO_REPARSE_TAG_APPEXECLINK:
        return "atalho de aplicativo do sistema"
    if tag in (IO_REPARSE_TAG_WOF, IO_REPARSE_TAG_DEDUP):
        return "arquivo compactado/deduplicado pelo sistema"
    return f"ponto de reparse (tipo 0x{tag:08X})"


@dataclass(frozen=True, slots=True)
class ScannedFile:
    path: tuple[str, ...]
    ext_path: str
    size: int
    mtime_ns: int
    attributes: int


@dataclass(frozen=True, slots=True)
class ScannedDir:
    path: tuple[str, ...]
    ext_path: str


@dataclass
class ScanResult:
    files: list[ScannedFile] = field(default_factory=list)
    dirs: list[ScannedDir] = field(default_factory=list)
    blockers: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    blocker_count: int = 0
    hidden_or_system: int = 0

    def block(self, message: str) -> None:
        self.blocker_count += 1
        if len(self.blockers) < _MAX_DETAILED:
            self.blockers.append(message)
        elif len(self.blockers) == _MAX_DETAILED:
            self.blockers.append("... (outros bloqueios omitidos)")

    @property
    def total_bytes(self) -> int:
        return sum(f.size for f in self.files)


def scan_tree(root_ext: str, check_cancel: Callable[[], None]) -> ScanResult:
    """Percorre ``root_ext`` (caminho estendido de uma pasta comum) sem seguir links."""
    result = ScanResult()
    stack: list[tuple[str, tuple[str, ...]]] = [(root_ext, ())]
    count = 0
    while stack:
        check_cancel()
        folder, rel = stack.pop()
        try:
            with os.scandir(folder) as it:
                entries = list(it)
        except OSError as exc:
            where = display_path(rel) if rel else "(pasta de origem)"
            result.block(f"{where}: não foi possível listar a pasta ({exc.strerror or exc})")
            continue
        seen: dict[str, str] = {}
        for entry in entries:
            name = entry.name
            child_rel = (*rel, name)
            shown = display_path(child_rel)
            problem = component_problem(name)
            if problem is not None:
                result.block(f"{shown}: {problem}")
                continue
            key = fold(name)
            if key in seen:
                result.block(
                    f"{shown}: conflita com '{seen[key]}' (diferença só de maiúsculas/minúsculas)"
                )
                continue
            seen[key] = name
            try:
                st = entry.stat(follow_symlinks=False)
            except OSError as exc:
                result.block(f"{shown}: não foi possível ler atributos ({exc.strerror or exc})")
                continue
            attrs = getattr(st, "st_file_attributes", 0)
            if attrs & winfs.FILE_ATTRIBUTE_REPARSE_POINT:
                result.block(f"{shown}: {describe_reparse(getattr(st, 'st_reparse_tag', 0))}")
                continue
            if attrs & winfs.RECALL_ATTRIBUTES:
                result.block(f"{shown}: arquivo somente na nuvem/offline")
                continue
            if attrs & (winfs.FILE_ATTRIBUTE_HIDDEN | winfs.FILE_ATTRIBUTE_SYSTEM):
                result.hidden_or_system += 1
            count += 1
            if count > MAX_ENTRIES:
                result.block(f"a pasta tem mais de {MAX_ENTRIES} itens (limite da v1)")
                return result
            if len(child_rel) > MAX_DEPTH:
                result.block(f"{shown}: mais de {MAX_DEPTH} níveis de pastas")
                continue
            if stat_mod.S_ISDIR(st.st_mode):
                result.dirs.append(ScannedDir(child_rel, entry.path))
                stack.append((entry.path, child_rel))
            elif stat_mod.S_ISREG(st.st_mode):
                if st.st_size > MAX_FILE_SIZE:
                    result.block(f"{shown}: arquivo maior que 1 TiB (limite da v1)")
                    continue
                result.files.append(
                    ScannedFile(child_rel, entry.path, int(st.st_size), int(st.st_mtime_ns), attrs)
                )
            else:
                result.block(f"{shown}: tipo de arquivo especial não suportado")
    if result.hidden_or_system:
        result.warnings.append(
            f"{result.hidden_or_system} item(ns) oculto(s)/de sistema serão incluídos."
        )
    return result
