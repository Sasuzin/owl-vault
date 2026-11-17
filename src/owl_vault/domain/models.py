"""Modelos de dados imutáveis do domínio."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from owl_vault.domain.names import fold_path


@dataclass(frozen=True, slots=True)
class KdfParams:
    """Parâmetros do Argon2id gravados (e autenticados) no cabeçalho."""

    memory_kib: int
    iterations: int
    parallelism: int


@dataclass(frozen=True, slots=True)
class FileIdentity:
    """Identidade estável de um arquivo no NTFS: série do volume + FileId de 128 bits."""

    volume_serial: int
    file_id: bytes  # 16 bytes


@dataclass(frozen=True, slots=True)
class Fingerprint:
    """Impressão digital de um arquivo de origem lida do handle (não do DirEntry)."""

    identity: FileIdentity
    size: int
    mtime_ns: int
    ctime_ns: int  # ChangeTime do NTFS (muda em qualquer alteração de metadados/dados)


@dataclass(frozen=True, slots=True)
class DirEntryRecord:
    """Entrada de diretório do manifesto."""

    path: tuple[str, ...]

    @property
    def folded(self) -> tuple[str, ...]:
        return fold_path(self.path)


@dataclass(frozen=True, slots=True)
class FileEntryRecord:
    """Entrada de arquivo do manifesto."""

    path: tuple[str, ...]
    size: int
    mtime_ns: int
    file_id: bytes  # 16 bytes; também é o nome do blob
    sha256: bytes  # 32 bytes, SHA-256 do texto claro

    @property
    def folded(self) -> tuple[str, ...]:
        return fold_path(self.path)


Entry = DirEntryRecord | FileEntryRecord


class Phase(str, Enum):
    """Máquina de estados da criação (ARCHITECTURE §4.0)."""

    ENCRYPTING = "encrypting"
    MANIFEST_WRITTEN = "manifest_written"
    VERIFIED = "verified"
    RESTORE_TESTED = "restore_tested"
    COMPLETE = "complete"
    INTERRUPTED = "interrupted"  # apenas em state.json (dica de UI)
