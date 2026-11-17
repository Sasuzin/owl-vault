"""Manifesto: esquema, validação completa (FORMAT §5.1/§5.2) e estimativa de tamanho."""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Any

from owl_vault.crypto.stream import validate_chunk_size
from owl_vault.domain.errors import FormatError, LimitError, UnsafePathError
from owl_vault.domain.limits import (
    FORMAT_VERSION,
    MAX_DEPTH,
    MAX_ENTRIES,
    MAX_FILE_SIZE,
    MAX_MANIFEST_PLAINTEXT,
    MAX_MTIME_NS,
    MIN_MTIME_NS,
)
from owl_vault.domain.models import (
    DirEntryRecord,
    Entry,
    FileEntryRecord,
    FileIdentity,
    Fingerprint,
)
from owl_vault.domain.names import component_problem, display_path, fold_path
from owl_vault.storage.container import (
    canonical_json,
    get_hex,
    get_int,
    get_list,
    require_object,
)


@dataclass(frozen=True, slots=True)
class Manifest:
    vault_id: bytes
    chunk_size: int
    entries: tuple[Entry, ...]

    @property
    def files(self) -> list[FileEntryRecord]:
        return [e for e in self.entries if isinstance(e, FileEntryRecord)]

    @property
    def dirs(self) -> list[DirEntryRecord]:
        return [e for e in self.entries if isinstance(e, DirEntryRecord)]

    def total_bytes(self) -> int:
        return sum(e.size for e in self.files)


# --- (de)serialização de entradas -------------------------------------------------------


def entry_to_obj(e: Entry) -> dict[str, Any]:
    if isinstance(e, FileEntryRecord):
        return {
            "type": "file",
            "path": list(e.path),
            "size": e.size,
            "mtime_ns": e.mtime_ns,
            "file_id": e.file_id.hex(),
            "sha256": e.sha256.hex(),
        }
    return {"type": "dir", "path": list(e.path)}


def fingerprint_to_obj(fp: Fingerprint) -> dict[str, Any]:
    return {
        "vol": fp.identity.volume_serial,
        "fid": fp.identity.file_id.hex(),
        "size": fp.size,
        "mtime_ns": fp.mtime_ns,
        "ctime_ns": fp.ctime_ns,
    }


def fingerprint_from_obj(obj: Any) -> Fingerprint:
    o = require_object(obj, {"vol", "fid", "size", "mtime_ns", "ctime_ns"})
    return Fingerprint(
        identity=FileIdentity(get_int(o, "vol", 0, 2**64 - 1), get_hex(o, "fid", 16)),
        size=get_int(o, "size", 0, MAX_FILE_SIZE),
        mtime_ns=get_int(o, "mtime_ns", MIN_MTIME_NS, MAX_MTIME_NS),
        ctime_ns=get_int(o, "ctime_ns", MIN_MTIME_NS, MAX_MTIME_NS),
    )


def _path_from_obj(o: dict[str, Any]) -> tuple[str, ...]:
    raw = o["path"]
    if not isinstance(raw, list) or not raw:
        raise FormatError("caminho de entrada deve ser lista não vazia")
    if len(raw) > MAX_DEPTH:
        raise LimitError("caminho profundo demais")
    for comp in raw:
        problem = component_problem(comp)
        if problem is not None:
            raise UnsafePathError(f"caminho inválido no manifesto: {problem}")
    return tuple(raw)


def entry_from_obj(obj: Any, *, with_fp: bool = False) -> tuple[Entry, Fingerprint | None]:
    if not isinstance(obj, dict):
        raise FormatError("entrada do manifesto deve ser objeto")
    t = obj.get("type")
    if t == "dir":
        o = require_object(obj, {"type", "path"})
        return DirEntryRecord(_path_from_obj(o)), None
    if t == "file":
        req = {"type", "path", "size", "mtime_ns", "file_id", "sha256"}
        if with_fp:
            req = req | {"fp"}
        o = require_object(obj, req)
        entry = FileEntryRecord(
            path=_path_from_obj(o),
            size=get_int(o, "size", 0, MAX_FILE_SIZE),
            mtime_ns=get_int(o, "mtime_ns", MIN_MTIME_NS, MAX_MTIME_NS),
            file_id=get_hex(o, "file_id", 16),
            sha256=get_hex(o, "sha256", 32),
        )
        fp = fingerprint_from_obj(o["fp"]) if with_fp else None
        return entry, fp
    raise FormatError("tipo de entrada desconhecido")


# --- validação de conjunto --------------------------------------------------------------


def validate_entries(entries: Sequence[Entry]) -> None:
    """Regras de conjunto da FORMAT §5.2 (componentes já validados individualmente)."""
    if len(entries) > MAX_ENTRIES:
        raise LimitError(f"manifesto com mais de {MAX_ENTRIES} entradas")
    dirs: set[tuple[str, ...]] = set()
    seen: set[tuple[str, ...]] = set()
    file_ids: set[bytes] = set()
    for e in entries:
        for comp in e.path:
            problem = component_problem(comp)
            if problem is not None:
                raise UnsafePathError(f"caminho inválido: {problem}")
        if not e.path or len(e.path) > MAX_DEPTH:
            raise LimitError("caminho vazio ou profundo demais")
        key = fold_path(e.path)
        if key in seen:
            raise UnsafePathError(
                f"caminho duplicado (diferença só de maiúsculas/minúsculas?): {display_path(e.path)}"
            )
        seen.add(key)
        if isinstance(e, DirEntryRecord):
            dirs.add(key)
        else:
            if e.file_id in file_ids:
                raise FormatError("file_id duplicado no manifesto")
            file_ids.add(e.file_id)
            if not 0 <= e.size <= MAX_FILE_SIZE:
                raise LimitError("tamanho de arquivo fora dos limites")
            if not MIN_MTIME_NS <= e.mtime_ns <= MAX_MTIME_NS:
                raise LimitError("data de modificação fora dos limites")
    for e in entries:
        key = fold_path(e.path)
        parent = key[:-1]
        if parent and parent not in dirs:
            raise UnsafePathError(
                f"entrada sem pasta-pai registrada (ou pai é arquivo): {display_path(e.path)}"
            )


def manifest_to_obj(m: Manifest) -> dict[str, Any]:
    return {
        "kind": "manifest",
        "format_version": FORMAT_VERSION,
        "vault_id": m.vault_id.hex(),
        "chunk_size": m.chunk_size,
        "entries": [entry_to_obj(e) for e in m.entries],
    }


def manifest_from_obj(obj: Any, expected_vault_id: bytes) -> Manifest:
    o = require_object(obj, {"kind", "format_version", "vault_id", "chunk_size", "entries"})
    if o["kind"] != "manifest":
        raise FormatError("conteúdo não é um manifesto")
    if get_int(o, "format_version", 0, 2**16) != FORMAT_VERSION:
        raise FormatError("versão de manifesto não suportada")
    if get_hex(o, "vault_id", 16) != expected_vault_id:
        raise FormatError("manifesto pertence a outro cofre")
    chunk_size = get_int(o, "chunk_size", 0, 2**32)
    validate_chunk_size(chunk_size)
    raw_entries = get_list(o, "entries", MAX_ENTRIES)
    entries = tuple(entry_from_obj(x)[0] for x in raw_entries)
    validate_entries(entries)
    return Manifest(expected_vault_id, chunk_size, entries)


def build_manifest(vault_id: bytes, chunk_size: int, entries: Iterable[Entry]) -> Manifest:
    ordered = tuple(sorted(entries, key=lambda e: (fold_path(e.path), e.path)))
    validate_entries(ordered)
    m = Manifest(vault_id, chunk_size, ordered)
    size = len(canonical_json(manifest_to_obj(m)))
    if size > MAX_MANIFEST_PLAINTEXT:
        raise LimitError("manifesto excede 256 MiB (pasta com arquivos/nomes demais)")
    return m


def estimate_manifest_size(paths: Iterable[tuple[tuple[str, ...], bool]]) -> int:
    """Tamanho EXATO do manifesto serializado para os caminhos dados.

    Usa o mesmo serializador canônico com valores de largura máxima nos campos numéricos,
    então é um limite superior justo (os campos não-caminho têm largura fixa ou limitada).
    """
    base = {
        "kind": "manifest",
        "format_version": FORMAT_VERSION,
        "vault_id": "0" * 32,
        "chunk_size": 16 * 1024 * 1024,
        "entries": [],
    }
    total = len(canonical_json(base))
    widest_file = {
        "type": "file",
        "size": MAX_FILE_SIZE,
        "mtime_ns": MIN_MTIME_NS,
        "file_id": "0" * 32,
        "sha256": "0" * 64,
    }
    first = True
    for path, is_file in paths:
        obj: dict[str, Any] = dict(widest_file) if is_file else {"type": "dir"}
        obj["path"] = list(path)
        total += len(canonical_json(obj)) + (0 if first else 1)
        first = False
    return total
