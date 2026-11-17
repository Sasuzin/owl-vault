"""Diário em segmentos delta write-once (FORMAT §5.3)."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any

from owl_vault.domain.errors import AuthenticationError, FormatError, OwlVaultError
from owl_vault.domain.limits import MAX_ENTRIES, MAX_JOURNAL_SEGMENT_PLAINTEXT
from owl_vault.domain.models import DirEntryRecord, Entry, FileEntryRecord, Fingerprint, Phase
from owl_vault.domain.names import fold_path
from owl_vault.storage import winfs
from owl_vault.storage.container import (
    ContainerKind,
    canonical_json,
    get_hex,
    get_int,
    get_list,
    get_str,
    read_container,
    require_object,
    write_container,
)
from owl_vault.storage.layout import SEGMENT_RE, VaultLayout
from owl_vault.storage.manifest import entry_from_obj, entry_to_obj, fingerprint_to_obj

JOURNAL_PHASES = (
    Phase.ENCRYPTING,
    Phase.MANIFEST_WRITTEN,
    Phase.VERIFIED,
    Phase.RESTORE_TESTED,
)
_MAX_ENTRIES_PER_SEGMENT = 20_000


@dataclass(frozen=True, slots=True)
class JournalInit:
    source_root: str  # caminho estendido
    source_volume: int
    source_root_fid: bytes
    test_dir: str  # caminho estendido da pasta de teste de restauração
    chunk_size: int
    created_utc: str

    def to_obj(self) -> dict[str, Any]:
        return {
            "source_root": self.source_root,
            "source_volume": self.source_volume,
            "source_root_fid": self.source_root_fid.hex(),
            "test_dir": self.test_dir,
            "chunk_size": self.chunk_size,
            "created_utc": self.created_utc,
        }

    @staticmethod
    def from_obj(obj: Any) -> JournalInit:
        o = require_object(
            obj,
            {
                "source_root",
                "source_volume",
                "source_root_fid",
                "test_dir",
                "chunk_size",
                "created_utc",
            },
        )
        return JournalInit(
            source_root=get_str(o, "source_root", 40_000),
            source_volume=get_int(o, "source_volume", 0, 2**64 - 1),
            source_root_fid=get_hex(o, "source_root_fid", 16),
            test_dir=get_str(o, "test_dir", 40_000),
            chunk_size=get_int(o, "chunk_size", 0, 2**32),
            created_utc=get_str(o, "created_utc", 64),
        )


@dataclass
class JournalState:
    init: JournalInit | None = None
    phase: Phase | None = None
    dirs: dict[tuple[str, ...], DirEntryRecord] = field(default_factory=dict)
    files: dict[tuple[str, ...], tuple[FileEntryRecord, Fingerprint]] = field(default_factory=dict)
    next_seq: int = 0
    stale_segments: list[str] = field(default_factory=list)  # após a primeira quebra
    broken_at: int | None = None

    def entries(self) -> list[Entry]:
        out: list[Entry] = list(self.dirs.values())
        out.extend(f for f, _ in self.files.values())
        return out

    def apply(self, seg: dict[str, Any]) -> None:
        if seg["init"] is not None:
            if self.init is not None:
                raise FormatError("diário com mais de uma inicialização")
            self.init = JournalInit.from_obj(seg["init"])
        self.phase = Phase(seg["phase"])
        removed = {get_hex({"x": r}, "x", 16) for r in seg["removed"]}
        if removed:
            for key in [k for k, (f, _) in self.files.items() if f.file_id in removed]:
                del self.files[key]
        for raw in seg["added"]:
            entry, fp = entry_from_obj(raw, with_fp=raw.get("type") == "file")
            key = fold_path(entry.path)
            if isinstance(entry, DirEntryRecord):
                self.dirs[key] = entry
            else:
                assert fp is not None
                self.files[key] = (entry, fp)
        if len(self.dirs) + len(self.files) > MAX_ENTRIES:
            raise FormatError("diário com entradas demais")


def _segment_obj(
    vault_id: bytes,
    seq: int,
    phase: Phase,
    init: JournalInit | None,
    added: list[tuple[Entry, Fingerprint | None]],
    removed: list[bytes],
) -> dict[str, Any]:
    added_objs: list[dict[str, Any]] = []
    for entry, fp in added:
        o = entry_to_obj(entry)
        if isinstance(entry, FileEntryRecord):
            assert fp is not None
            o["fp"] = fingerprint_to_obj(fp)
        added_objs.append(o)
    return {
        "kind": "journal",
        "vault_id": vault_id.hex(),
        "seq": seq,
        "phase": phase.value,
        "init": init.to_obj() if init is not None else None,
        "added": added_objs,
        "removed": [r.hex() for r in removed],
    }


def _validate_segment(obj: Any, vault_id: bytes, seq: int) -> dict[str, Any]:
    o = require_object(obj, {"kind", "vault_id", "seq", "phase", "init", "added", "removed"})
    if get_hex(o, "vault_id", 16) != vault_id:
        raise FormatError("segmento de diário de outro cofre")
    if get_int(o, "seq", 0, 2**63) != seq:
        raise FormatError("segmento de diário fora de ordem")
    if o["phase"] not in {p.value for p in JOURNAL_PHASES}:
        raise FormatError("fase de diário desconhecida")
    if seq == 0 and o["init"] is None:
        raise FormatError("segmento 0 sem inicialização")
    if seq != 0 and o["init"] is not None:
        raise FormatError("inicialização fora do segmento 0")
    get_list(o, "added", _MAX_ENTRIES_PER_SEGMENT * 2)
    get_list(o, "removed", MAX_ENTRIES)
    return o


class JournalWriter:
    """Acrescenta segmentos novos (CREATE_NEW + flush); nunca modifica um existente."""

    def __init__(
        self, layout: VaultLayout, master_key: bytes, vault_id: bytes, next_seq: int
    ) -> None:
        self._layout = layout
        self._mk = master_key
        self._vid = vault_id
        self.next_seq = next_seq

    def write(
        self,
        phase: Phase,
        *,
        init: JournalInit | None = None,
        added: list[tuple[Entry, Fingerprint | None]] | None = None,
        removed: list[bytes] | None = None,
    ) -> None:
        added = list(added or [])
        removed = list(removed or [])
        winfs.ensure_own_dir(self._layout.journal_dir)
        first = True
        while first or added:
            batch = added[:_MAX_ENTRIES_PER_SEGMENT]
            added = added[_MAX_ENTRIES_PER_SEGMENT:]
            obj = _segment_obj(
                self._vid,
                self.next_seq,
                phase,
                init if first else None,
                batch,
                removed if first else [],
            )
            if len(canonical_json(obj)) > MAX_JOURNAL_SEGMENT_PLAINTEXT:
                raise OwlVaultError("segmento de diário grande demais (nomes muito longos?)")
            write_container(
                self._layout.segment(self.next_seq),
                ContainerKind.JOURNAL,
                self._mk,
                self._vid,
                obj,
                op="journal",
            )
            self.next_seq += 1
            first = False


def list_segment_files(layout: VaultLayout) -> list[tuple[int, str]]:
    out: list[tuple[int, str]] = []
    try:
        if not winfs.is_plain_dir(os.lstat(layout.journal_dir)):
            return out  # pasta journal trocada por link: ignorada (nunca seguida)
        names = os.listdir(layout.journal_dir)
    except FileNotFoundError:
        return out
    for name in names:
        if SEGMENT_RE.fullmatch(name) and winfs.is_plain_file_at(
            winfs.join(layout.journal_dir, name)
        ):
            out.append((int(name[:16], 16), winfs.join(layout.journal_dir, name)))
    out.sort()
    return out


def read_journal(layout: VaultLayout, master_key: bytes, vault_id: bytes) -> JournalState:
    """Aplica segmentos a partir de 0 e para no primeiro ausente/não autêntico."""
    state = JournalState()
    files = list_segment_files(layout)
    by_seq = dict(files)
    seq = 0
    while seq in by_seq:
        try:
            read = read_container(by_seq[seq], ContainerKind.JOURNAL, master_key, vault_id)
            seg = _validate_segment(read.obj, vault_id, seq)
            state.apply(seg)
        except (AuthenticationError, FormatError):
            state.broken_at = seq
            break
        seq += 1
    state.next_seq = seq
    state.stale_segments = [p for s, p in files if s >= seq]
    return state
